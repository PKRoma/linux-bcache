/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Code for managing the extent btree and dynamically updating the writeback
 * dirty sector count.
 */

#include "bcache.h"
#include "bkey_methods.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "checksum.h"
#include "debug.h"
#include "dirent.h"
#include "error.h"
#include "extents.h"
#include "inode.h"
#include "journal.h"
#include "super.h"
#include "writeback.h"
#include "xattr.h"

#include <trace/events/bcache.h>

static enum merge_result bch_extent_merge(struct cache_set *, struct btree *,
					  struct bkey_i *, struct bkey_i *);

static void sort_key_next(struct btree_node_iter *iter,
			  struct btree *b,
			  struct btree_node_iter_set *i)
{
	i->k += __btree_node_offset_to_key(b, i->k)->u64s;

	if (i->k == i->end)
		*i = iter->data[--iter->used];
}

/*
 * Returns true if l > r - unless l == r, in which case returns true if l is
 * older than r.
 *
 * Necessary for btree_sort_fixup() - if there are multiple keys that compare
 * equal in different sets, we have to process them newest to oldest.
 */
#define key_sort_cmp(l, r)						\
({									\
	int _c = bkey_cmp_packed(b,					\
				 __btree_node_offset_to_key(b, (l).k),	\
				 __btree_node_offset_to_key(b, (r).k));	\
									\
	_c ? _c > 0 : (l).k > (r).k;					\
})

static inline bool should_drop_next_key(struct btree_node_iter *iter,
					struct btree *b)
{
	struct btree_node_iter_set *l = iter->data, *r = iter->data + 1;
	struct bkey_packed *k = __btree_node_offset_to_key(b, l->k);

	if (bkey_whiteout(k))
		return true;

	if (iter->used < 2)
		return false;

	if (iter->used > 2 &&
	    key_sort_cmp(r[0], r[1]))
		r++;

	/*
	 * key_sort_cmp() ensures that when keys compare equal the older key
	 * comes first; so if l->k compares equal to r->k then l->k is older and
	 * should be dropped.
	 */
	return !bkey_cmp_packed(b,
				__btree_node_offset_to_key(b, l->k),
				__btree_node_offset_to_key(b, r->k));
}

struct btree_nr_keys bch_key_sort_fix_overlapping(struct bset *dst,
						  struct btree *b,
						  struct btree_node_iter *iter)
{
	struct bkey_packed *out = dst->start;
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	heap_resort(iter, key_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		if (!should_drop_next_key(iter, b)) {
			struct bkey_packed *k =
				__btree_node_offset_to_key(b, iter->data->k);

			bkey_copy(out, k);
			btree_keys_account_key_add(&nr, 0, out);
			out = bkey_next(out);
		}

		sort_key_next(iter, b, iter->data);
		heap_sift(iter, 0, key_sort_cmp);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

/* Common among btree and extent ptrs */

const struct bch_extent_ptr *
bch_extent_has_device(struct bkey_s_c_extent e, unsigned dev)
{
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr)
		if (ptr->dev == dev)
			return ptr;

	return NULL;
}

unsigned bch_extent_nr_ptrs(struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;
	unsigned nr_ptrs = 0;

	extent_for_each_ptr(e, ptr)
		nr_ptrs++;

	return nr_ptrs;
}

unsigned bch_extent_nr_dirty_ptrs(struct bkey_s_c k)
{
	struct bkey_s_c_extent e;
	const struct bch_extent_ptr *ptr;
	unsigned nr_ptrs = 0;

	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		e = bkey_s_c_to_extent(k);

		extent_for_each_ptr(e, ptr)
			nr_ptrs += !ptr->cached;
		break;

	case BCH_RESERVATION:
		nr_ptrs = bkey_s_c_to_reservation(k).v->nr_replicas;
		break;
	}

	return nr_ptrs;
}

/* returns true if equal */
static bool crc_cmp(union bch_extent_crc *l, union bch_extent_crc *r)
{
	return extent_crc_type(l) == extent_crc_type(r) &&
		!memcmp(l, r, extent_entry_bytes(to_entry(l)));
}

/* Increment pointers after @crc by crc's offset until the next crc entry: */
void bch_extent_crc_narrow_pointers(struct bkey_s_extent e, union bch_extent_crc *crc)
{
	union bch_extent_entry *entry;

	extent_for_each_entry_from(e, entry, extent_entry_next(to_entry(crc))) {
		if (!extent_entry_is_ptr(entry))
			return;

		entry->ptr.offset += crc_offset(crc);
	}
}

/*
 * We're writing another replica for this extent, so while we've got the data in
 * memory we'll be computing a new checksum for the currently live data.
 *
 * If there are other replicas we aren't moving, and they are checksummed but
 * not compressed, we can modify them to point to only the data that is
 * currently live (so that readers won't have to bounce) while we've got the
 * checksum we need:
 *
 * XXX: to guard against data being corrupted while in memory, instead of
 * recomputing the checksum here, it would be better in the read path to instead
 * of computing the checksum of the entire extent:
 *
 * | extent                              |
 *
 * compute the checksums of the live and dead data separately
 * | dead data || live data || dead data |
 *
 * and then verify that crc_dead1 + crc_live + crc_dead2 == orig_crc, and then
 * use crc_live here (that we verified was correct earlier)
 *
 * note: doesn't work with encryption
 */
void bch_extent_narrow_crcs(struct bkey_s_extent e)
{
	union bch_extent_crc *crc;
	bool have_wide = false, have_narrow = false;
	struct bch_csum csum = { 0 };
	unsigned csum_type = 0;

	extent_for_each_crc(e, crc) {
		if (crc_compression_type(crc) ||
		    bch_csum_type_is_encryption(crc_csum_type(crc)))
			continue;

		if (crc_uncompressed_size(e.k, crc) != e.k->size) {
			have_wide = true;
		} else {
			have_narrow = true;
			csum = crc_csum(crc);
			csum_type = crc_csum_type(crc);
		}
	}

	if (!have_wide || !have_narrow)
		return;

	extent_for_each_crc(e, crc) {
		if (crc_compression_type(crc))
			continue;

		if (crc_uncompressed_size(e.k, crc) != e.k->size) {
			switch (extent_crc_type(crc)) {
			case BCH_EXTENT_CRC_NONE:
				BUG();
			case BCH_EXTENT_CRC32:
				if (bch_crc_bytes[csum_type] > 4)
					continue;

				bch_extent_crc_narrow_pointers(e, crc);
				crc->crc32._compressed_size	= e.k->size - 1;
				crc->crc32._uncompressed_size	= e.k->size - 1;
				crc->crc32.offset		= 0;
				crc->crc32.csum_type		= csum_type;
				crc->crc32.csum			= csum.lo;
				break;
			case BCH_EXTENT_CRC64:
				if (bch_crc_bytes[csum_type] > 10)
					continue;

				bch_extent_crc_narrow_pointers(e, crc);
				crc->crc64._compressed_size	= e.k->size - 1;
				crc->crc64._uncompressed_size	= e.k->size - 1;
				crc->crc64.offset		= 0;
				crc->crc64.csum_type		= csum_type;
				crc->crc64.csum_lo		= csum.lo;
				crc->crc64.csum_hi		= csum.hi;
				break;
			case BCH_EXTENT_CRC128:
				if (bch_crc_bytes[csum_type] > 16)
					continue;

				bch_extent_crc_narrow_pointers(e, crc);
				crc->crc128._compressed_size	= e.k->size - 1;
				crc->crc128._uncompressed_size	= e.k->size - 1;
				crc->crc128.offset		= 0;
				crc->crc128.csum_type		= csum_type;
				crc->crc128.csum		= csum;
				break;
			}
		}
	}
}

void bch_extent_drop_redundant_crcs(struct bkey_s_extent e)
{
	union bch_extent_entry *entry = e.v->start;
	union bch_extent_crc *crc, *prev = NULL;

	while (entry != extent_entry_last(e)) {
		union bch_extent_entry *next = extent_entry_next(entry);
		size_t crc_u64s = extent_entry_u64s(entry);

		if (!extent_entry_is_crc(entry))
			goto next;

		crc = entry_to_crc(entry);

		if (next == extent_entry_last(e)) {
			/* crc entry with no pointers after it: */
			goto drop;
		}

		if (extent_entry_is_crc(next)) {
			/* no pointers before next crc entry: */
			goto drop;
		}

		if (prev && crc_cmp(crc, prev)) {
			/* identical to previous crc entry: */
			goto drop;
		}

		if (!prev &&
		    !crc_csum_type(crc) &&
		    !crc_compression_type(crc)) {
			/* null crc entry: */
			bch_extent_crc_narrow_pointers(e, crc);
			goto drop;
		}

		prev = crc;
next:
		entry = next;
		continue;
drop:
		memmove_u64s_down(crc, next,
				  (u64 *) extent_entry_last(e) - (u64 *) next);
		e.k->u64s -= crc_u64s;
	}

	EBUG_ON(bkey_val_u64s(e.k) && !bch_extent_nr_ptrs(e.c));
}

static bool should_drop_ptr(const struct cache_set *c,
			    struct bkey_s_c_extent e,
			    const struct bch_extent_ptr *ptr)
{
	struct cache *ca;

	return (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr);
}

static void bch_extent_drop_stale(struct cache_set *c, struct bkey_s_extent e)
{
	struct bch_extent_ptr *ptr = &e.v->start->ptr;
	bool dropped = false;

	rcu_read_lock();
	while ((ptr = extent_ptr_next(e, ptr)))
		if (should_drop_ptr(c, e.c, ptr)) {
			__bch_extent_drop_ptr(e, ptr);
			dropped = true;
		} else
			ptr++;
	rcu_read_unlock();

	if (dropped)
		bch_extent_drop_redundant_crcs(e);
}

static bool bch_ptr_normalize(struct cache_set *c, struct btree *bk,
			      struct bkey_s k)
{
	return bch_extent_normalize(c, k);
}

static void bch_ptr_swab(const struct bkey_format *f, struct bkey_packed *k)
{
	switch (k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED: {
		union bch_extent_entry *entry;
		u64 *d = (u64 *) bkeyp_val(f, k);
		unsigned i;

		for (i = 0; i < bkeyp_val_u64s(f, k); i++)
			d[i] = swab64(d[i]);

		for (entry = (union bch_extent_entry *) d;
		     entry < (union bch_extent_entry *) (d + bkeyp_val_u64s(f, k));
		     entry = extent_entry_next(entry)) {
			switch (extent_entry_type(entry)) {
			case BCH_EXTENT_ENTRY_crc32:
				entry->crc32.csum = swab32(entry->crc32.csum);
				break;
			case BCH_EXTENT_ENTRY_crc64:
				entry->crc64.csum_hi = swab16(entry->crc64.csum_hi);
				entry->crc64.csum_lo = swab64(entry->crc64.csum_lo);
				break;
			case BCH_EXTENT_ENTRY_crc128:
				entry->crc128.csum.hi = swab64(entry->crc64.csum_hi);
				entry->crc128.csum.lo = swab64(entry->crc64.csum_lo);
				break;
			case BCH_EXTENT_ENTRY_ptr:
				break;
			}
		}
		break;
	}
	}
}

static const char *extent_ptr_invalid(struct bkey_s_c_extent e,
				      const struct cache_member_rcu *mi,
				      const struct bch_extent_ptr *ptr,
				      unsigned size_ondisk)
{
	const struct bch_extent_ptr *ptr2;
	const struct cache_member_cpu *m = mi->m + ptr->dev;

	if (ptr->dev > mi->nr_in_set || !m->valid)
		return "pointer to invalid device";

	extent_for_each_ptr(e, ptr2)
		if (ptr != ptr2 && ptr->dev == ptr2->dev)
			return "multiple pointers to same device";

	if (ptr->offset + size_ondisk > m->bucket_size * m->nbuckets)
		return "offset past end of device";

	if (ptr->offset < m->bucket_size * m->first_bucket)
		return "offset before first bucket";

	if ((ptr->offset & (m->bucket_size - 1)) + size_ondisk > m->bucket_size)
		return "spans multiple buckets";

	return NULL;
}

static size_t extent_print_ptrs(struct cache_set *c, char *buf,
				size_t size, struct bkey_s_c_extent e)
{
	char *out = buf, *end = buf + size;
	const union bch_extent_entry *entry;
	const union bch_extent_crc *crc;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;
	bool first = true;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	rcu_read_lock();
	extent_for_each_entry(e, entry) {
		if (!first)
			p(" ");

		switch (__extent_entry_type(entry)) {
		case BCH_EXTENT_ENTRY_crc32:
		case BCH_EXTENT_ENTRY_crc64:
		case BCH_EXTENT_ENTRY_crc128:
			crc = entry_to_crc(entry);

			p("crc: c_size %u size %u offset %u csum %u compress %u",
			  crc_compressed_size(e.k, crc),
			  crc_uncompressed_size(e.k, crc),
			  crc_offset(crc), crc_csum_type(crc),
			  crc_compression_type(crc));
			break;
		case BCH_EXTENT_ENTRY_ptr:
			ptr = entry_to_ptr(entry);

			p("ptr: %u:%llu gen %u%s", ptr->dev,
			  (u64) ptr->offset, ptr->gen,
			  (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr)
			  ? " stale" : "");
			break;
		default:
			p("(invalid extent entry %.16llx)", *((u64 *) entry));
			goto out;
		}

		first = false;
	}
out:
	rcu_read_unlock();

	if (bkey_extent_is_cached(e.k))
		p(" cached");
#undef p
	return out - buf;
}

/* Btree ptrs */

static const char *bch_btree_ptr_invalid(const struct cache_set *c,
					 struct bkey_s_c k)
{
	if (bkey_extent_is_cached(k.k))
		return "cached";

	if (k.k->size)
		return "nonzero key size";

	if (bkey_val_u64s(k.k) > BKEY_BTREE_PTR_VAL_U64s_MAX)
		return "value too big";

	switch (k.k->type) {
	case BCH_EXTENT: {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const union bch_extent_entry *entry;
		const struct bch_extent_ptr *ptr;
		const union bch_extent_crc *crc;
		struct cache_member_rcu *mi;
		const char *reason;

		extent_for_each_entry(e, entry)
			if (__extent_entry_type(entry) >= BCH_EXTENT_ENTRY_MAX)
				return "invalid extent entry type";

		mi = cache_member_info_get(c);

		extent_for_each_ptr_crc(e, ptr, crc) {
			reason = extent_ptr_invalid(e, mi, ptr,
						c->sb.btree_node_size);

			if (reason) {
				cache_member_info_put();
				return reason;
			}
		}

		cache_member_info_put();

		if (crc)
			return "has crc field";

		return NULL;
	}

	default:
		return "invalid value type";
	}
}

static void btree_ptr_debugcheck(struct cache_set *c, struct btree *b,
				 struct bkey_s_c k)
{
	struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
	const struct bch_extent_ptr *ptr;
	unsigned seq;
	const char *err;
	char buf[160];
	struct bucket *g;
	struct cache *ca;
	unsigned replicas = 0;
	bool bad;

	rcu_read_lock();

	extent_for_each_online_device(c, e, ptr, ca) {
		replicas++;

		if ((ca = PTR_CACHE(c, ptr))) {
			g = PTR_BUCKET(ca, ptr);

			err = "stale";
			if (ptr_stale(ca, ptr))
				goto err;

			do {
				seq = read_seqcount_begin(&c->gc_pos_lock);
				bad = gc_pos_cmp(c->gc_pos, gc_pos_btree_node(b)) > 0 &&
				       !g->mark.is_metadata;
			} while (read_seqcount_retry(&c->gc_pos_lock, seq));

			err = "inconsistent";
			if (bad)
				goto err;
		}
	}

	rcu_read_unlock();

	if (replicas < c->sb.meta_replicas_have) {
		bch_bkey_val_to_text(c, btree_node_type(b),
				     buf, sizeof(buf), k);
		cache_set_bug(c,
			"btree key bad (too few replicas, %u < %u): %s",
			replicas, c->sb.meta_replicas_have, buf);
		return;
	}

	return;
err:
	bch_bkey_val_to_text(c, btree_node_type(b), buf, sizeof(buf), k);
	cache_set_bug(c, "%s btree pointer %s: bucket %zi prio %i "
		      "gen %i last_gc %i mark %08x",
		      err, buf, PTR_BUCKET_NR(ca, ptr),
		      g->read_prio, PTR_BUCKET(ca, ptr)->mark.gen,
		      ca->oldest_gens[PTR_BUCKET_NR(ca, ptr)],
		      (unsigned) g->mark.counter);
	rcu_read_unlock();
}

static void bch_btree_ptr_to_text(struct cache_set *c, char *buf,
				  size_t size, struct bkey_s_c k)
{
	char *out = buf, *end = buf + size;
	const char *invalid;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	if (bkey_extent_is_data(k.k))
		out += extent_print_ptrs(c, buf, size, bkey_s_c_to_extent(k));

	invalid = bch_btree_ptr_invalid(c, k);
	if (invalid)
		p(" invalid: %s", invalid);
#undef p
}

struct extent_pick_ptr
bch_btree_pick_ptr(struct cache_set *c, const struct btree *b)
{
	struct bkey_s_c_extent e = bkey_i_to_s_c_extent(&b->key);
	const union bch_extent_crc *crc;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	rcu_read_lock();

	extent_for_each_online_device_crc(c, e, crc, ptr, ca) {
		struct btree *root = btree_node_root(c, b);

		if (cache_set_inconsistent_on(crc, c,
				"btree node pointer with crc at btree %u level %u/%u bucket %zu",
				b->btree_id, b->level, root ? root->level : -1,
				PTR_BUCKET_NR(ca, ptr)))
			break;

		if (cache_inconsistent_on(ptr_stale(ca, ptr), ca,
				"stale btree node pointer at btree %u level %u/%u bucket %zu",
				b->btree_id, b->level, root ? root->level : -1,
				PTR_BUCKET_NR(ca, ptr)))
			continue;

		percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		return (struct extent_pick_ptr) { .ptr = *ptr, .ca = ca };
	}

	rcu_read_unlock();

	return (struct extent_pick_ptr) { .ca = NULL, };
}

const struct bkey_ops bch_bkey_btree_ops = {
	.key_invalid	= bch_btree_ptr_invalid,
	.key_debugcheck	= btree_ptr_debugcheck,
	.val_to_text	= bch_btree_ptr_to_text,
	.swab		= bch_ptr_swab,
};

/* Extents */

static bool __bch_cut_front(struct bpos where, struct bkey_s k)
{
	u64 len = 0;

	if (bkey_cmp(where, bkey_start_pos(k.k)) <= 0)
		return false;

	EBUG_ON(bkey_cmp(where, k.k->p) > 0);

	len = k.k->p.offset - where.offset;

	BUG_ON(len > k.k->size);

	/*
	 * Don't readjust offset if the key size is now 0, because that could
	 * cause offset to point to the next bucket:
	 */
	if (!len)
		__set_bkey_deleted(k.k);
	else if (bkey_extent_is_data(k.k)) {
		struct bkey_s_extent e = bkey_s_to_extent(k);
		struct bch_extent_ptr *ptr;
		union bch_extent_crc *crc, *prev_crc = NULL;

		extent_for_each_ptr_crc(e, ptr, crc) {
			switch (extent_crc_type(crc)) {
			case BCH_EXTENT_CRC_NONE:
				ptr->offset += e.k->size - len;
				break;
			case BCH_EXTENT_CRC32:
				if (prev_crc != crc)
					crc->crc32.offset += e.k->size - len;
				break;
			case BCH_EXTENT_CRC64:
				if (prev_crc != crc)
					crc->crc64.offset += e.k->size - len;
				break;
			case BCH_EXTENT_CRC128:
				if (prev_crc != crc)
					crc->crc128.offset += e.k->size - len;
				break;
			}
			prev_crc = crc;
		}
	}

	k.k->size = len;

	return true;
}

bool bch_cut_front(struct bpos where, struct bkey_i *k)
{
	return __bch_cut_front(where, bkey_i_to_s(k));
}

bool bch_cut_back(struct bpos where, struct bkey *k)
{
	u64 len = 0;

	if (bkey_cmp(where, k->p) >= 0)
		return false;

	EBUG_ON(bkey_cmp(where, bkey_start_pos(k)) < 0);

	len = where.offset - bkey_start_offset(k);

	BUG_ON(len > k->size);

	k->p = where;
	k->size = len;

	if (!len)
		__set_bkey_deleted(k);

	return true;
}

/**
 * bch_key_resize - adjust size of @k
 *
 * bkey_start_offset(k) will be preserved, modifies where the extent ends
 */
void bch_key_resize(struct bkey *k,
		    unsigned new_size)
{
	k->p.offset -= k->size;
	k->p.offset += new_size;
	k->size = new_size;
}

/*
 * In extent_sort_fix_overlapping(), insert_fixup_extent(),
 * extent_merge_inline() - we're modifying keys in place that are packed. To do
 * that we have to unpack the key, modify the unpacked key - then this
 * copies/repacks the unpacked to the original as necessary.
 */
static bool __extent_save(struct btree *b, struct btree_node_iter *iter,
			  struct bkey_packed *dst, struct bkey *src)
{
	struct bkey_format *f = &b->format;
	struct bkey_i *dst_unpacked;
	bool ret;

	if ((dst_unpacked = packed_to_bkey(dst))) {
		dst_unpacked->k = *src;
		ret = true;
	} else {
		ret = bkey_pack_key(dst, src, f);
	}

	if (ret && iter)
		bch_verify_key_order(b, iter, dst);

	return ret;
}

static void extent_save(struct btree *b, struct btree_node_iter *iter,
			struct bkey_packed *dst, struct bkey *src)
{
	BUG_ON(!__extent_save(b, iter, dst, src));
}

/*
 * Returns true if l > r - unless l == r, in which case returns true if l is
 * older than r.
 *
 * Necessary for sort_fix_overlapping() - if there are multiple keys that
 * compare equal in different sets, we have to process them newest to oldest.
 */
#define extent_sort_cmp(l, r)						\
({									\
	struct bkey _ul = bkey_unpack_key(b,				\
				__btree_node_offset_to_key(b, (l).k));	\
	struct bkey _ur = bkey_unpack_key(b,				\
				__btree_node_offset_to_key(b, (r).k));	\
									\
	int _c = bkey_cmp(bkey_start_pos(&_ul), bkey_start_pos(&_ur));	\
	_c ? _c > 0 : (l).k < (r).k;					\
})

static inline void extent_sort_sift(struct btree_node_iter *iter,
				    struct btree *b, size_t i)
{
	heap_sift(iter, i, extent_sort_cmp);
}

static inline void extent_sort_next(struct btree_node_iter *iter,
				    struct btree *b,
				    struct btree_node_iter_set *i)
{
	sort_key_next(iter, b, i);
	heap_sift(iter, i - iter->data, extent_sort_cmp);
}

static void extent_sort_append(struct cache_set *c,
			       struct btree *b,
			       struct btree_nr_keys *nr,
			       struct bkey_packed *start,
			       struct bkey_packed **prev,
			       struct bkey_packed *k)
{
	struct bkey_format *f = &b->format;
	BKEY_PADDED(k) tmp;

	if (bkey_whiteout(k))
		return;

	bkey_unpack(b, &tmp.k, k);

	if (*prev &&
	    bch_extent_merge(c, b, (void *) *prev, &tmp.k))
		return;

	if (*prev) {
		bkey_pack(*prev, (void *) *prev, f);

		btree_keys_account_key_add(nr, 0, *prev);
		*prev = bkey_next(*prev);
	} else {
		*prev = start;
	}

	bkey_copy(*prev, &tmp.k);
}

struct btree_nr_keys bch_extent_sort_fix_overlapping(struct cache_set *c,
					struct bset *dst,
					struct btree *b,
					struct btree_node_iter *iter)
{
	struct bkey_format *f = &b->format;
	struct btree_node_iter_set *_l = iter->data, *_r;
	struct bkey_packed *prev = NULL, *out, *lk, *rk;
	struct bkey l_unpacked, r_unpacked;
	struct bkey_s l, r;
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	heap_resort(iter, extent_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		lk = __btree_node_offset_to_key(b, _l->k);

		if (iter->used == 1) {
			extent_sort_append(c, b, &nr, dst->start, &prev, lk);
			extent_sort_next(iter, b, _l);
			continue;
		}

		_r = iter->data + 1;
		if (iter->used > 2 &&
		    extent_sort_cmp(_r[0], _r[1]))
			_r++;

		rk = __btree_node_offset_to_key(b, _r->k);

		l = __bkey_disassemble(b, lk, &l_unpacked);
		r = __bkey_disassemble(b, rk, &r_unpacked);

		/* If current key and next key don't overlap, just append */
		if (bkey_cmp(l.k->p, bkey_start_pos(r.k)) <= 0) {
			extent_sort_append(c, b, &nr, dst->start, &prev, lk);
			extent_sort_next(iter, b, _l);
			continue;
		}

		/* Skip 0 size keys */
		if (!r.k->size) {
			extent_sort_next(iter, b, _r);
			continue;
		}

		/*
		 * overlap: keep the newer key and trim the older key so they
		 * don't overlap. comparing pointers tells us which one is
		 * newer, since the bsets are appended one after the other.
		 */

		/* can't happen because of comparison func */
		BUG_ON(_l->k < _r->k &&
		       !bkey_cmp(bkey_start_pos(l.k), bkey_start_pos(r.k)));

		if (_l->k > _r->k) {
			/* l wins, trim r */
			if (bkey_cmp(l.k->p, r.k->p) >= 0) {
				sort_key_next(iter, b, _r);
			} else {
				__bch_cut_front(l.k->p, r);
				extent_save(b, NULL, rk, r.k);
			}

			extent_sort_sift(iter, b, _r - iter->data);
		} else if (bkey_cmp(l.k->p, r.k->p) > 0) {
			BKEY_PADDED(k) tmp;

			/*
			 * r wins, but it overlaps in the middle of l - split l:
			 */
			bkey_reassemble(&tmp.k, l.s_c);
			bch_cut_back(bkey_start_pos(r.k), &tmp.k.k);

			__bch_cut_front(r.k->p, l);
			extent_save(b, NULL, lk, l.k);

			extent_sort_sift(iter, b, 0);

			extent_sort_append(c, b, &nr, dst->start, &prev,
					   bkey_to_packed(&tmp.k));
		} else {
			bch_cut_back(bkey_start_pos(r.k), l.k);
			extent_save(b, NULL, lk, l.k);
		}
	}

	if (prev) {
		bkey_pack(prev, (void *) prev, f);
		btree_keys_account_key_add(&nr, 0, prev);
		out = bkey_next(prev);
	} else {
		out = dst->start;
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

struct extent_insert_state {
	struct btree_insert		*trans;
	struct btree_insert_entry	*insert;
	struct bpos			committed;
	struct bucket_stats_cache_set	stats;

	/* for deleting: */
	struct bkey_i			whiteout;
	bool				do_journal;
	bool				deleting;
};

static void bch_add_sectors(struct extent_insert_state *s,
			    struct bkey_s_c k, u64 offset, s64 sectors)
{
	struct cache_set *c = s->trans->c;
	struct btree *b = s->insert->iter->nodes[0];

	EBUG_ON(bkey_cmp(bkey_start_pos(k.k), b->data->min_key) < 0);

	if (!sectors)
		return;

	bch_mark_key(c, k, sectors, false, gc_pos_btree_node(b),
		     &s->stats, s->trans->journal_res.seq);

	if (bkey_extent_is_data(k.k) &&
	    !bkey_extent_is_cached(k.k))
		bcache_dev_sectors_dirty_add(c, k.k->p.inode, offset, sectors);
}

static void bch_subtract_sectors(struct extent_insert_state *s,
				 struct bkey_s_c k, u64 offset, s64 sectors)
{
	bch_add_sectors(s, k, offset, -sectors);
}

/* These wrappers subtract exactly the sectors that we're removing from @k */
static void bch_cut_subtract_back(struct extent_insert_state *s,
				  struct bpos where, struct bkey_s k)
{
	bch_subtract_sectors(s, k.s_c, where.offset,
			     k.k->p.offset - where.offset);
	bch_cut_back(where, k.k);
}

static void bch_cut_subtract_front(struct extent_insert_state *s,
				   struct bpos where, struct bkey_s k)
{
	bch_subtract_sectors(s, k.s_c, bkey_start_offset(k.k),
			     where.offset - bkey_start_offset(k.k));
	__bch_cut_front(where, k);
}

static void bch_drop_subtract(struct extent_insert_state *s, struct bkey_s k)
{
	if (k.k->size)
		bch_subtract_sectors(s, k.s_c,
				     bkey_start_offset(k.k), k.k->size);
	k.k->size = 0;
	__set_bkey_deleted(k.k);
}

/*
 * Note: If this returns true because only some pointers matched,
 * we can lose some caching that had happened in the interim.
 * Because cache promotion only promotes the part of the extent
 * actually read, and not the whole extent, and due to the key
 * splitting done in bch_extent_insert_fixup, preserving such
 * caching is difficult.
 */
static bool bch_extent_cmpxchg_cmp(struct bkey_s_c l, struct bkey_s_c r)
{
	struct bkey_s_c_extent le, re;
	const struct bch_extent_ptr *lp, *rp;
	s64 offset;

	BUG_ON(!l.k->size || !r.k->size);

	if (l.k->type != r.k->type ||
	    bversion_cmp(l.k->version, r.k->version))
		return false;

	switch (l.k->type) {
	case KEY_TYPE_COOKIE:
		return !memcmp(bkey_s_c_to_cookie(l).v,
			       bkey_s_c_to_cookie(r).v,
			       sizeof(struct bch_cookie));

	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		le = bkey_s_c_to_extent(l);
		re = bkey_s_c_to_extent(r);

		/*
		 * bkey_cmpxchg() handles partial matches - when either l or r
		 * has been trimmed - so we need just to handle l or r not
		 * starting at the same place when checking for a match here.
		 *
		 * If the starts of the keys are different, we just apply that
		 * offset to the device pointer offsets when checking those -
		 * matching how bch_cut_front() adjusts device pointer offsets
		 * when adjusting the start of a key:
		 */
		offset = bkey_start_offset(l.k) - bkey_start_offset(r.k);

		/*
		 * XXX: perhaps we only raced with copygc or tiering replacing
		 * one of the pointers: it should suffice to find _any_ matching
		 * pointer
		 */

		if (bkey_val_u64s(le.k) != bkey_val_u64s(re.k))
			return false;

		extent_for_each_ptr(le, lp) {
			const union bch_extent_entry *entry =
				bkey_idx(re.v, (u64 *) lp - le.v->_data);

			if (!extent_entry_is_ptr(entry))
				return false;

			rp = &entry->ptr;

			if (lp->offset	!= rp->offset + offset ||
			    lp->dev	!= rp->dev ||
			    lp->gen	!= rp->gen)
				return false;
		}

		return true;
	default:
		return false;
	}

}

/*
 * Returns true on success, false on failure (and false means @new no longer
 * overlaps with @k)
 *
 * If returned true, we may have inserted up to one key in @b.
 * If returned false, we may have inserted up to two keys in @b.
 *
 * On return, there is room in @res for at least one more key of the same size
 * as @new.
 */
enum extent_insert_hook_ret bch_extent_cmpxchg(struct extent_insert_hook *hook,
					       struct bpos committed_pos,
					       struct bpos next_pos,
					       struct bkey_s_c k,
					       const struct bkey_i *new)
{
	struct bch_replace_info *replace = container_of(hook,
					struct bch_replace_info, hook);
	struct bkey_i *old = &replace->key;

	EBUG_ON(bkey_cmp(committed_pos, bkey_start_pos(&new->k)) < 0);

	/* must have something to compare against */
	EBUG_ON(!bkey_val_u64s(&old->k));

	/* new must be a subset of old */
	EBUG_ON(bkey_cmp(new->k.p, old->k.p) > 0 ||
		bkey_cmp(bkey_start_pos(&new->k), bkey_start_pos(&old->k)) < 0);

	if (k.k && bch_extent_cmpxchg_cmp(k, bkey_i_to_s_c(old))) {
		replace->successes++;
		return BTREE_HOOK_DO_INSERT;
	} else {
		replace->failures++;
		return BTREE_HOOK_NO_INSERT;
	}
}

static bool bch_extent_merge_inline(struct cache_set *,
				    struct btree_iter *,
				    struct bkey_packed *,
				    struct bkey_packed *,
				    bool);

#define MAX_LOCK_HOLD_TIME	(5 * NSEC_PER_MSEC)

static enum btree_insert_ret
extent_insert_should_stop(struct extent_insert_state *s)
{
	struct btree *b = s->insert->iter->nodes[0];

	/*
	 * Check if we have sufficient space in both the btree node and the
	 * journal reservation:
	 *
	 * Each insert checks for room in the journal entry, but we check for
	 * room in the btree node up-front. In the worst case, bkey_cmpxchg()
	 * will insert two keys, and one iteration of this room will insert one
	 * key, so we need room for three keys.
	 */
	if (!bch_btree_node_insert_fits(s->trans->c, b, s->insert->k->k.u64s))
		return BTREE_INSERT_BTREE_NODE_FULL;
	else if (!journal_res_insert_fits(s->trans, s->insert))
		return BTREE_INSERT_JOURNAL_RES_FULL; /* XXX worth tracing */
	else
		return BTREE_INSERT_OK;
}

static void extent_bset_insert(struct cache_set *c, struct btree_iter *iter,
			       struct bkey_i *insert)
{
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	struct bset_tree *t = bset_tree_last(b);
	struct bkey_packed *where =
		bch_btree_node_iter_bset_pos(node_iter, b, t);
	struct bkey_packed *prev = bkey_prev(b, t, where);
	struct bkey_packed *next_live_key = where;
	unsigned clobber_u64s;

	if (prev)
		where = bkey_next(prev);

	while (next_live_key != btree_bkey_last(b, t) &&
	       bkey_deleted(next_live_key))
		next_live_key = bkey_next(next_live_key);

	/*
	 * Everything between where and next_live_key is now deleted keys, and
	 * is overwritten:
	 */
	clobber_u64s = (u64 *) next_live_key - (u64 *) where;

	if (prev &&
	    bch_extent_merge_inline(c, iter, prev, bkey_to_packed(insert), true))
		goto drop_deleted_keys;

	if (next_live_key != btree_bkey_last(b, t) &&
	    bch_extent_merge_inline(c, iter, bkey_to_packed(insert),
				    next_live_key, false))
		goto drop_deleted_keys;

	bch_bset_insert(b, node_iter, where, insert, clobber_u64s);
	bch_btree_node_iter_fix(iter, b, node_iter, t, where,
				clobber_u64s, where->u64s);
	return;
drop_deleted_keys:
	bch_bset_delete(b, where, clobber_u64s);
	bch_btree_node_iter_fix(iter, b, node_iter, t, where, clobber_u64s, 0);
}

static void extent_insert_committed(struct extent_insert_state *s)
{
	struct cache_set *c = s->trans->c;
	struct btree_iter *iter = s->insert->iter;
	struct bkey_i *insert = !s->deleting
		? s->insert->k
		: &s->whiteout;
	BKEY_PADDED(k) split;

	EBUG_ON(bkey_cmp(insert->k.p, s->committed) < 0);
	EBUG_ON(bkey_cmp(s->committed, bkey_start_pos(&insert->k)) < 0);

	if (!bkey_cmp(s->committed, bkey_start_pos(&insert->k)))
		return;

	if (s->deleting && !s->do_journal) {
		bch_cut_front(s->committed, insert);
		goto done;
	}

	EBUG_ON(bkey_deleted(&insert->k) || !insert->k.size);

	bkey_copy(&split.k, insert);

	if (!(s->trans->flags & BTREE_INSERT_JOURNAL_REPLAY) &&
	    bkey_cmp(s->committed, insert->k.p) &&
	    bkey_extent_is_compressed(bkey_i_to_s_c(insert))) {
		/* XXX: possibly need to increase our reservation? */
		bch_cut_subtract_back(s, s->committed,
				      bkey_i_to_s(&split.k));
		bch_cut_front(s->committed, insert);
		bch_add_sectors(s, bkey_i_to_s_c(insert),
				bkey_start_offset(&insert->k),
				insert->k.size);
	} else {
		bch_cut_back(s->committed, &split.k.k);
		bch_cut_front(s->committed, insert);
	}

	if (debug_check_bkeys(c))
		bkey_debugcheck(c, iter->nodes[iter->level],
				bkey_i_to_s_c(&split.k));

	bch_btree_journal_key(s->trans, iter, &split.k);

	if (!s->deleting)
		extent_bset_insert(c, iter, &split.k);
done:
	bch_btree_iter_set_pos_same_leaf(iter, s->committed);

	insert->k.needs_whiteout	= false;
	s->do_journal			= false;
	s->trans->did_work		= true;
}

static enum extent_insert_hook_ret
__extent_insert_advance_pos(struct extent_insert_state *s,
			    struct bpos next_pos,
			    struct bkey_s_c k)
{
	struct extent_insert_hook *hook = s->trans->hook;
	enum extent_insert_hook_ret ret;
#if 0
	/*
	 * Currently disabled for encryption - broken with fcollapse. Will have
	 * to reenable when versions are exposed for send/receive - versions
	 * will have to be monotonic then:
	 */
	if (k.k && k.k->size &&
	    !bversion_zero(s->insert->k->k.version) &&
	    bversion_cmp(k.k->version, s->insert->k->k.version) > 0) {
		ret = BTREE_HOOK_NO_INSERT;
	} else
#endif
	if (hook)
		ret = hook->fn(hook, s->committed, next_pos, k, s->insert->k);
	else
		ret = BTREE_HOOK_DO_INSERT;

	EBUG_ON(bkey_deleted(&s->insert->k->k) || !s->insert->k->k.size);

	switch (ret) {
	case BTREE_HOOK_DO_INSERT:
		break;
	case BTREE_HOOK_NO_INSERT:
		extent_insert_committed(s);
		bch_cut_subtract_front(s, next_pos, bkey_i_to_s(s->insert->k));

		bch_btree_iter_set_pos_same_leaf(s->insert->iter, next_pos);
		break;
	case BTREE_HOOK_RESTART_TRANS:
		return ret;
	}

	s->committed = next_pos;
	return ret;
}

/*
 * Update iter->pos, marking how much of @insert we've processed, and call hook
 * fn:
 */
static enum extent_insert_hook_ret
extent_insert_advance_pos(struct extent_insert_state *s, struct bkey_s_c k)
{
	struct btree *b = s->insert->iter->nodes[0];
	struct bpos next_pos = bpos_min(s->insert->k->k.p,
					k.k ? k.k->p : b->key.k.p);

	/* hole? */
	if (k.k && bkey_cmp(s->committed, bkey_start_pos(k.k)) < 0) {
		bool have_uncommitted = bkey_cmp(s->committed,
				bkey_start_pos(&s->insert->k->k)) > 0;

		switch (__extent_insert_advance_pos(s, bkey_start_pos(k.k),
						    bkey_s_c_null)) {
		case BTREE_HOOK_DO_INSERT:
			break;
		case BTREE_HOOK_NO_INSERT:
			/*
			 * we had to split @insert and insert the committed
			 * part - need to bail out and recheck journal
			 * reservation/btree node before we advance pos past @k:
			 */
			if (have_uncommitted)
				return BTREE_HOOK_NO_INSERT;
			break;
		case BTREE_HOOK_RESTART_TRANS:
			return BTREE_HOOK_RESTART_TRANS;
		}
	}

	/* avoid redundant calls to hook fn: */
	if (!bkey_cmp(s->committed, next_pos))
		return BTREE_HOOK_DO_INSERT;

	return __extent_insert_advance_pos(s, next_pos, k);
}

static enum btree_insert_ret
extent_insert_check_split_compressed(struct extent_insert_state *s,
				     struct bkey_s_c k,
				     enum bch_extent_overlap overlap)
{
	struct cache_set *c = s->trans->c;
	unsigned sectors;

	if (overlap == BCH_EXTENT_OVERLAP_MIDDLE &&
	    (sectors = bkey_extent_is_compressed(k))) {
		int flags = BCH_DISK_RESERVATION_BTREE_LOCKS_HELD;

		if (s->trans->flags & BTREE_INSERT_NOFAIL)
			flags |= BCH_DISK_RESERVATION_NOFAIL;

		switch (bch_disk_reservation_add(c,
				s->trans->disk_res,
				sectors, flags)) {
		case 0:
			break;
		case -ENOSPC:
			return BTREE_INSERT_ENOSPC;
		case -EINTR:
			return BTREE_INSERT_NEED_GC_LOCK;
		default:
			BUG();
		}
	}

	return BTREE_INSERT_OK;
}

static enum btree_insert_ret
extent_squash(struct extent_insert_state *s, struct bkey_i *insert,
	      struct bset_tree *t, struct bkey_packed *_k, struct bkey_s k,
	      enum bch_extent_overlap overlap)
{
	struct cache_set *c = s->trans->c;
	struct btree_iter *iter = s->insert->iter;
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];

	switch (overlap) {
	case BCH_EXTENT_OVERLAP_FRONT:
		/* insert overlaps with start of k: */
		bch_cut_subtract_front(s, insert->k.p, k);
		BUG_ON(bkey_deleted(k.k));
		extent_save(b, node_iter, _k, k.k);
		break;

	case BCH_EXTENT_OVERLAP_BACK:
		/* insert overlaps with end of k: */
		bch_cut_subtract_back(s, bkey_start_pos(&insert->k), k);
		BUG_ON(bkey_deleted(k.k));
		extent_save(b, node_iter, _k, k.k);

		/*
		 * As the auxiliary tree is indexed by the end of the
		 * key and we've just changed the end, update the
		 * auxiliary tree.
		 */
		bch_bset_fix_invalidated_key(b, t, _k);
		bch_btree_node_iter_fix(iter, b, node_iter, t,
					_k, _k->u64s, _k->u64s);
		break;

	case BCH_EXTENT_OVERLAP_ALL: {
		struct bpos orig_pos = k.k->p;

		/* The insert key completely covers k, invalidate k */
		if (!bkey_whiteout(k.k))
			btree_keys_account_key_drop(&b->nr,
						t - b->set, _k);

		bch_drop_subtract(s, k);
		k.k->p = bkey_start_pos(&insert->k);
		if (!__extent_save(b, node_iter, _k, k.k)) {
			/*
			 * Couldn't repack: we aren't necessarily able
			 * to repack if the new key is outside the range
			 * of the old extent, so we have to split
			 * @insert:
			 */
			k.k->p = orig_pos;
			extent_save(b, node_iter, _k, k.k);

			if (extent_insert_advance_pos(s, k.s_c) ==
			    BTREE_HOOK_RESTART_TRANS)
				return BTREE_INSERT_NEED_TRAVERSE;

			extent_insert_committed(s);
			/*
			 * We split and inserted upto at k.k->p - that
			 * has to coincide with iter->pos, so that we
			 * don't have anything more we have to insert
			 * until we recheck our journal reservation:
			 */
			EBUG_ON(bkey_cmp(s->committed, k.k->p));
		} else {
			bch_bset_fix_invalidated_key(b, t, _k);
			bch_btree_node_iter_fix(iter, b, node_iter, t,
						_k, _k->u64s, _k->u64s);
		}

		break;
	}
	case BCH_EXTENT_OVERLAP_MIDDLE: {
		BKEY_PADDED(k) split;
		/*
		 * The insert key falls 'in the middle' of k
		 * The insert key splits k in 3:
		 * - start only in k, preserve
		 * - middle common section, invalidate in k
		 * - end only in k, preserve
		 *
		 * We update the old key to preserve the start,
		 * insert will be the new common section,
		 * we manually insert the end that we are preserving.
		 *
		 * modify k _before_ doing the insert (which will move
		 * what k points to)
		 */
		bkey_reassemble(&split.k, k.s_c);
		split.k.k.needs_whiteout |= bset_written(b, bset(b, t));

		bch_cut_back(bkey_start_pos(&insert->k), &split.k.k);
		BUG_ON(bkey_deleted(&split.k.k));

		bch_cut_subtract_front(s, insert->k.p, k);
		BUG_ON(bkey_deleted(k.k));
		extent_save(b, node_iter, _k, k.k);

		bch_add_sectors(s, bkey_i_to_s_c(&split.k),
				bkey_start_offset(&split.k.k),
				split.k.k.size);
		extent_bset_insert(c, iter, &split.k);
		break;
	}
	}

	return BTREE_INSERT_OK;
}

static enum btree_insert_ret
bch_delete_fixup_extent(struct extent_insert_state *s)
{
	struct cache_set *c = s->trans->c;
	struct btree_iter *iter = s->insert->iter;
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	struct bkey_packed *_k;
	struct bkey unpacked;
	struct bkey_i *insert = s->insert->k;
	enum btree_insert_ret ret = BTREE_INSERT_OK;

	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k)));

	s->whiteout	= *insert;
	s->do_journal	= false;

	while (bkey_cmp(s->committed, insert->k.p) < 0 &&
	       (ret = extent_insert_should_stop(s)) == BTREE_INSERT_OK &&
	       (_k = bch_btree_node_iter_peek_all(node_iter, b))) {
		struct bset_tree *t = bch_bkey_to_bset(b, _k);
		struct bkey_s k = __bkey_disassemble(b, _k, &unpacked);
		enum bch_extent_overlap overlap;

		EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k)));
		EBUG_ON(bkey_cmp(iter->pos, k.k->p) >= 0);

		if (bkey_cmp(bkey_start_pos(k.k), insert->k.p) >= 0)
			break;

		if (bkey_whiteout(k.k)) {
			s->committed = bpos_min(insert->k.p, k.k->p);
			goto next;
		}

		overlap = bch_extent_overlap(&insert->k, k.k);

		ret = extent_insert_check_split_compressed(s, k.s_c, overlap);
		if (ret != BTREE_INSERT_OK)
			goto stop;

		switch (extent_insert_advance_pos(s, k.s_c)) {
		case BTREE_HOOK_DO_INSERT:
			break;
		case BTREE_HOOK_NO_INSERT:
			continue;
		case BTREE_HOOK_RESTART_TRANS:
			ret = BTREE_INSERT_NEED_TRAVERSE;
			goto stop;
		}

		s->do_journal = true;

		if (overlap == BCH_EXTENT_OVERLAP_ALL) {
			btree_keys_account_key_drop(&b->nr,
						t - b->set, _k);
			bch_subtract_sectors(s, k.s_c,
					     bkey_start_offset(k.k), k.k->size);
			_k->type = KEY_TYPE_DISCARD;
			reserve_whiteout(b, t, _k);
		} else if (k.k->needs_whiteout ||
			   bset_written(b, bset(b, t))) {
			struct bkey_i discard = *insert;

			switch (overlap) {
			case BCH_EXTENT_OVERLAP_FRONT:
				bch_cut_front(bkey_start_pos(k.k), &discard);
				break;
			case BCH_EXTENT_OVERLAP_BACK:
				bch_cut_back(k.k->p, &discard.k);
				break;
			default:
				break;
			}

			discard.k.needs_whiteout = true;

			ret = extent_squash(s, insert, t, _k, k, overlap);
			BUG_ON(ret != BTREE_INSERT_OK);

			extent_bset_insert(c, iter, &discard);
		} else {
			ret = extent_squash(s, insert, t, _k, k, overlap);
			BUG_ON(ret != BTREE_INSERT_OK);
		}
next:
		bch_cut_front(s->committed, insert);
		bch_btree_iter_set_pos_same_leaf(iter, s->committed);
	}

	if (bkey_cmp(s->committed, insert->k.p) < 0 &&
	    ret == BTREE_INSERT_OK &&
	    extent_insert_advance_pos(s, bkey_s_c_null) == BTREE_HOOK_RESTART_TRANS)
		ret = BTREE_INSERT_NEED_TRAVERSE;
stop:
	extent_insert_committed(s);

	bch_cache_set_stats_apply(c, &s->stats, s->trans->disk_res,
				  gc_pos_btree_node(b));

	EBUG_ON(bkey_cmp(iter->pos, s->committed));
	EBUG_ON((bkey_cmp(iter->pos, b->key.k.p) == 0) != iter->at_end_of_leaf);

	bch_cut_front(iter->pos, insert);

	if (insert->k.size && iter->at_end_of_leaf)
		ret = BTREE_INSERT_NEED_TRAVERSE;

	EBUG_ON(insert->k.size && ret == BTREE_INSERT_OK);

	return ret;
}

/**
 * bch_extent_insert_fixup - insert a new extent and deal with overlaps
 *
 * this may result in not actually doing the insert, or inserting some subset
 * of the insert key. For cmpxchg operations this is where that logic lives.
 *
 * All subsets of @insert that need to be inserted are inserted using
 * bch_btree_insert_and_journal(). If @b or @res fills up, this function
 * returns false, setting @iter->pos for the prefix of @insert that actually got
 * inserted.
 *
 * BSET INVARIANTS: this function is responsible for maintaining all the
 * invariants for bsets of extents in memory. things get really hairy with 0
 * size extents
 *
 * within one bset:
 *
 * bkey_start_pos(bkey_next(k)) >= k
 * or bkey_start_offset(bkey_next(k)) >= k->offset
 *
 * i.e. strict ordering, no overlapping extents.
 *
 * multiple bsets (i.e. full btree node):
 *
 * ∀ k, j
 *   k.size != 0 ∧ j.size != 0 →
 *     ¬ (k > bkey_start_pos(j) ∧ k < j)
 *
 * i.e. no two overlapping keys _of nonzero size_
 *
 * We can't realistically maintain this invariant for zero size keys because of
 * the key merging done in bch_btree_insert_key() - for two mergeable keys k, j
 * there may be another 0 size key between them in another bset, and it will
 * thus overlap with the merged key.
 *
 * In addition, the end of iter->pos indicates how much has been processed.
 * If the end of iter->pos is not the same as the end of insert, then
 * key insertion needs to continue/be retried.
 */
enum btree_insert_ret
bch_insert_fixup_extent(struct btree_insert *trans,
			struct btree_insert_entry *insert)
{
	struct cache_set *c = trans->c;
	struct btree_iter *iter = insert->iter;
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	struct bkey_packed *_k;
	struct bkey unpacked;
	enum btree_insert_ret ret = BTREE_INSERT_OK;

	struct extent_insert_state s = {
		.trans		= trans,
		.insert		= insert,
		.committed	= insert->iter->pos,
		.deleting	= bkey_whiteout(&insert->k->k),
	};

	EBUG_ON(iter->level);
	EBUG_ON(bkey_deleted(&insert->k->k) || !insert->k->k.size);

	if (s.deleting)
		return bch_delete_fixup_extent(&s);

	/*
	 * As we process overlapping extents, we advance @iter->pos both to
	 * signal to our caller (btree_insert_key()) how much of @insert->k has
	 * been inserted, and also to keep @iter->pos consistent with
	 * @insert->k and the node iterator that we're advancing:
	 */
	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k->k)));

	if (!(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))
		bch_add_sectors(&s, bkey_i_to_s_c(insert->k),
				bkey_start_offset(&insert->k->k),
				insert->k->k.size);

	while (bkey_cmp(s.committed, insert->k->k.p) < 0 &&
	       (ret = extent_insert_should_stop(&s)) == BTREE_INSERT_OK &&
	       (_k = bch_btree_node_iter_peek_all(node_iter, b))) {
		struct bset_tree *t = bch_bkey_to_bset(b, _k);
		struct bkey_s k = __bkey_disassemble(b, _k, &unpacked);
		enum bch_extent_overlap overlap;

		EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k->k)));
		EBUG_ON(bkey_cmp(iter->pos, k.k->p) >= 0);

		if (bkey_cmp(bkey_start_pos(k.k), insert->k->k.p) >= 0)
			break;

		overlap = bch_extent_overlap(&insert->k->k, k.k);

		ret = extent_insert_check_split_compressed(&s, k.s_c, overlap);
		if (ret != BTREE_INSERT_OK)
			goto stop;

		if (!k.k->size)
			goto squash;

		/*
		 * Only call advance pos & call hook for nonzero size extents:
		 * If hook returned BTREE_HOOK_NO_INSERT, @insert->k no longer
		 * overlaps with @k:
		 */
		switch (extent_insert_advance_pos(&s, k.s_c)) {
		case BTREE_HOOK_DO_INSERT:
			break;
		case BTREE_HOOK_NO_INSERT:
			continue;
		case BTREE_HOOK_RESTART_TRANS:
			ret = BTREE_INSERT_NEED_TRAVERSE;
			goto stop;
		}

		if (k.k->size &&
		    (k.k->needs_whiteout || bset_written(b, bset(b, t))))
			insert->k->k.needs_whiteout = true;

		if (overlap == BCH_EXTENT_OVERLAP_ALL &&
		    bkey_whiteout(k.k) &&
		    k.k->needs_whiteout) {
			unreserve_whiteout(b, t, _k);
			_k->needs_whiteout = false;
		}
squash:
		ret = extent_squash(&s, insert->k, t, _k, k, overlap);
		if (ret != BTREE_INSERT_OK)
			goto stop;
	}

	if (bkey_cmp(s.committed, insert->k->k.p) < 0 &&
	    ret == BTREE_INSERT_OK &&
	    extent_insert_advance_pos(&s, bkey_s_c_null) == BTREE_HOOK_RESTART_TRANS)
		ret = BTREE_INSERT_NEED_TRAVERSE;
stop:
	extent_insert_committed(&s);
	/*
	 * Subtract any remaining sectors from @insert, if we bailed out early
	 * and didn't fully insert @insert:
	 */
	if (insert->k->k.size &&
	    !(trans->flags & BTREE_INSERT_JOURNAL_REPLAY))
		bch_subtract_sectors(&s, bkey_i_to_s_c(insert->k),
				     bkey_start_offset(&insert->k->k),
				     insert->k->k.size);

	bch_cache_set_stats_apply(c, &s.stats, trans->disk_res,
				  gc_pos_btree_node(b));

	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k->k)));
	EBUG_ON(bkey_cmp(iter->pos, s.committed));
	EBUG_ON((bkey_cmp(iter->pos, b->key.k.p) == 0) != iter->at_end_of_leaf);

	if (insert->k->k.size && iter->at_end_of_leaf)
		ret = BTREE_INSERT_NEED_TRAVERSE;

	EBUG_ON(insert->k->k.size && ret == BTREE_INSERT_OK);

	return ret;
}

static const char *bch_extent_invalid(const struct cache_set *c,
				      struct bkey_s_c k)
{
	if (bkey_val_u64s(k.k) > BKEY_EXTENT_VAL_U64s_MAX)
		return "value too big";

	if (!k.k->size)
		return "zero key size";

	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED: {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const union bch_extent_entry *entry;
		const union bch_extent_crc *crc;
		const struct bch_extent_ptr *ptr;
		struct cache_member_rcu *mi = cache_member_info_get(c);
		unsigned size_ondisk = e.k->size;
		const char *reason;

		extent_for_each_entry(e, entry) {
			reason = "invalid extent entry type";
			if (__extent_entry_type(entry) >= BCH_EXTENT_ENTRY_MAX)
				goto invalid;

			if (extent_entry_is_crc(entry)) {
				crc = entry_to_crc(entry);

				reason = "checksum offset + key size > uncompressed size";
				if (crc_offset(crc) + e.k->size >
				    crc_uncompressed_size(e.k, crc))
					goto invalid;

				size_ondisk = crc_compressed_size(e.k, crc);

				reason = "invalid checksum type";
				if (crc_csum_type(crc) >= BCH_CSUM_NR)
					goto invalid;

				reason = "invalid compression type";
				if (crc_compression_type(crc) >= BCH_COMPRESSION_NR)
					goto invalid;
			} else {
				ptr = entry_to_ptr(entry);

				reason = extent_ptr_invalid(e, mi,
						&entry->ptr, size_ondisk);
				if (reason)
					goto invalid;
			}
		}

		cache_member_info_put();
		return NULL;
invalid:
		cache_member_info_put();
		return reason;
	}

	case BCH_RESERVATION: {
		struct bkey_s_c_reservation r = bkey_s_c_to_reservation(k);

		if (bkey_val_bytes(k.k) != sizeof(struct bch_reservation))
			return "incorrect value size";

		if (!r.v->nr_replicas || r.v->nr_replicas > BCH_REPLICAS_MAX)
			return "invalid nr_replicas";

		return NULL;
	}

	default:
		return "invalid value type";
	}
}

static void bch_extent_debugcheck_extent(struct cache_set *c, struct btree *b,
					 struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	struct cache *ca;
	struct bucket *g;
	unsigned seq, stale;
	char buf[160];
	bool bad;
	unsigned ptrs_per_tier[CACHE_TIERS];
	unsigned tier, replicas = 0;

	/*
	 * XXX: we should be doing most/all of these checks at startup time,
	 * where we check bkey_invalid() in btree_node_read_done()
	 *
	 * But note that we can't check for stale pointers or incorrect gc marks
	 * until after journal replay is done (it might be an extent that's
	 * going to get overwritten during replay)
	 */

	memset(ptrs_per_tier, 0, sizeof(ptrs_per_tier));

	mi = cache_member_info_get(c);

	extent_for_each_ptr(e, ptr) {
		replicas++;

		if (ptr->dev >= mi->nr_in_set)
			goto bad_device;

		/*
		 * If journal replay hasn't finished, we might be seeing keys
		 * that will be overwritten by the time journal replay is done:
		 */
		if (!test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags))
			continue;

		if (!mi->m[ptr->dev].valid)
			goto bad_device;

		tier = mi->m[ptr->dev].tier;
		ptrs_per_tier[tier]++;

		stale = 0;

		if ((ca = PTR_CACHE(c, ptr))) {
			g = PTR_BUCKET(ca, ptr);

			do {
				struct bucket_mark mark;

				seq = read_seqcount_begin(&c->gc_pos_lock);
				mark = READ_ONCE(g->mark);

				/* between mark and bucket gen */
				smp_rmb();

				stale = ptr_stale(ca, ptr);

				cache_set_bug_on(stale && !ptr->cached, c,
						 "stale dirty pointer");

				cache_set_bug_on(stale > 96, c,
						 "key too stale: %i",
						 stale);

				if (stale)
					break;

				bad = (mark.is_metadata ||
				       (gc_pos_cmp(c->gc_pos, gc_pos_btree_node(b)) > 0 &&
					!mark.owned_by_allocator &&
					!(ptr->cached
					  ? mark.cached_sectors
					  : mark.dirty_sectors)));
			} while (read_seqcount_retry(&c->gc_pos_lock, seq));

			if (bad)
				goto bad_ptr;
		}
	}
	cache_member_info_put();

	if (replicas > BCH_REPLICAS_MAX) {
		bch_bkey_val_to_text(c, btree_node_type(b), buf,
				     sizeof(buf), e.s_c);
		cache_set_bug(c,
			"extent key bad (too many replicas: %u): %s",
			replicas, buf);
		return;
	}

	if (!bkey_extent_is_cached(e.k) &&
	    replicas < c->sb.data_replicas_have) {
		bch_bkey_val_to_text(c, btree_node_type(b), buf,
				     sizeof(buf), e.s_c);
		cache_set_bug(c,
			"extent key bad (too few replicas, %u < %u): %s",
			replicas, c->sb.data_replicas_have, buf);
		return;
	}

	return;

bad_device:
	bch_bkey_val_to_text(c, btree_node_type(b), buf,
			     sizeof(buf), e.s_c);
	cache_set_bug(c, "extent pointer to dev %u missing device: %s",
		      ptr->dev, buf);
	cache_member_info_put();
	return;

bad_ptr:
	bch_bkey_val_to_text(c, btree_node_type(b), buf,
			     sizeof(buf), e.s_c);
	cache_set_bug(c, "extent pointer bad gc mark: %s:\nbucket %zu prio %i "
		      "gen %i last_gc %i mark 0x%08x",
		      buf, PTR_BUCKET_NR(ca, ptr),
		      g->read_prio, PTR_BUCKET(ca, ptr)->mark.gen,
		      ca->oldest_gens[PTR_BUCKET_NR(ca, ptr)],
		      (unsigned) g->mark.counter);
	cache_member_info_put();
	return;
}

static void bch_extent_debugcheck(struct cache_set *c, struct btree *b,
				  struct bkey_s_c k)
{
	switch (k.k->type) {
	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		bch_extent_debugcheck_extent(c, b, bkey_s_c_to_extent(k));
		break;
	case BCH_RESERVATION:
		break;
	default:
		BUG();
	}
}

static void bch_extent_to_text(struct cache_set *c, char *buf,
			       size_t size, struct bkey_s_c k)
{
	char *out = buf, *end = buf + size;
	const char *invalid;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	if (bkey_extent_is_data(k.k))
		out += extent_print_ptrs(c, buf, size, bkey_s_c_to_extent(k));

	invalid = bch_extent_invalid(c, k);
	if (invalid)
		p(" invalid: %s", invalid);
#undef p
}

static unsigned PTR_TIER(struct cache_member_rcu *mi,
			 const struct bch_extent_ptr *ptr)
{
	return ptr->dev < mi->nr_in_set
		? mi->m[ptr->dev].tier
		: UINT_MAX;
}

static void bch_extent_crc_init(union bch_extent_crc *crc,
				unsigned compressed_size,
				unsigned uncompressed_size,
				unsigned compression_type,
				unsigned nonce,
				struct bch_csum csum, unsigned csum_type)
{
	if (bch_crc_bytes[csum_type]	<= 4 &&
	    uncompressed_size		<= CRC32_SIZE_MAX &&
	    nonce			<= CRC32_NONCE_MAX) {
		crc->crc32 = (struct bch_extent_crc32) {
			.type = 1 << BCH_EXTENT_ENTRY_crc32,
			._compressed_size	= compressed_size - 1,
			._uncompressed_size	= uncompressed_size - 1,
			.offset			= 0,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= *((__le32 *) &csum.lo),
		};
		return;
	}

	if (bch_crc_bytes[csum_type]	<= 10 &&
	    uncompressed_size		<= CRC64_SIZE_MAX &&
	    nonce			<= CRC64_NONCE_MAX) {
		crc->crc64 = (struct bch_extent_crc64) {
			.type = 1 << BCH_EXTENT_ENTRY_crc64,
			._compressed_size	= compressed_size - 1,
			._uncompressed_size	= uncompressed_size - 1,
			.offset			= 0,
			.nonce			= nonce,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum_lo		= csum.lo,
			.csum_hi		= *((__le16 *) &csum.hi),
		};
		return;
	}

	if (bch_crc_bytes[csum_type]	<= 16 &&
	    uncompressed_size		<= CRC128_SIZE_MAX &&
	    nonce			<= CRC128_NONCE_MAX) {
		crc->crc128 = (struct bch_extent_crc128) {
			.type = 1 << BCH_EXTENT_ENTRY_crc128,
			._compressed_size	= compressed_size - 1,
			._uncompressed_size	= uncompressed_size - 1,
			.offset			= 0,
			.nonce			= nonce,
			.compression_type	= compression_type,
			.csum_type		= csum_type,
			.csum			= csum,
		};
		return;
	}

	BUG();
}

void bch_extent_crc_append(struct bkey_i_extent *e,
			   unsigned compressed_size,
			   unsigned uncompressed_size,
			   unsigned compression_type,
			   unsigned nonce,
			   struct bch_csum csum, unsigned csum_type)
{
	union bch_extent_crc *crc;

	BUG_ON(compressed_size > uncompressed_size);
	BUG_ON(uncompressed_size != e->k.size);
	BUG_ON(!compressed_size || !uncompressed_size);

	/*
	 * Look up the last crc entry, so we can check if we need to add
	 * another:
	 */
	extent_for_each_crc(extent_i_to_s(e), crc)
		;

	if (!crc && !csum_type && !compression_type)
		return;

	if (crc &&
	    crc_compressed_size(&e->k, crc)	== compressed_size &&
	    crc_uncompressed_size(&e->k, crc)	== uncompressed_size &&
	    crc_offset(crc)			== 0 &&
	    crc_nonce(crc)			== nonce &&
	    crc_csum_type(crc)			== csum_type &&
	    crc_compression_type(crc)		== compression_type &&
	    crc_csum(crc).lo			== csum.lo &&
	    crc_csum(crc).hi			== csum.hi)
		return;

	bch_extent_crc_init((void *) extent_entry_last(extent_i_to_s(e)),
			    compressed_size,
			    uncompressed_size,
			    compression_type,
			    nonce, csum, csum_type);
	__extent_entry_push(e);
}

/*
 * bch_extent_normalize - clean up an extent, dropping stale pointers etc.
 *
 * Returns true if @k should be dropped entirely
 *
 * For existing keys, only called when btree nodes are being rewritten, not when
 * they're merely being compacted/resorted in memory.
 */
bool bch_extent_normalize(struct cache_set *c, struct bkey_s k)
{
	struct bkey_s_extent e;

	switch (k.k->type) {
	case KEY_TYPE_ERROR:
		return false;

	case KEY_TYPE_DELETED:
	case KEY_TYPE_COOKIE:
		return true;

	case KEY_TYPE_DISCARD:
		return bversion_zero(k.k->version);

	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		e = bkey_s_to_extent(k);

		bch_extent_drop_stale(c, e);

		if (!bkey_val_u64s(e.k)) {
			if (bkey_extent_is_cached(e.k)) {
				k.k->type = KEY_TYPE_DISCARD;
				if (bversion_zero(k.k->version))
					return true;
			} else {
				k.k->type = KEY_TYPE_ERROR;
			}
		}

		return false;
	case BCH_RESERVATION:
		return false;
	default:
		BUG();
	}
}

void bch_extent_mark_replicas_cached(struct cache_set *c,
				     struct bkey_s_extent e,
				     unsigned nr_cached)
{
	struct bch_extent_ptr *ptr;
	struct cache_member_rcu *mi;
	bool have_higher_tier;
	unsigned tier = 0;

	if (!nr_cached)
		return;

	mi = cache_member_info_get(c);

	do {
		have_higher_tier = false;

		extent_for_each_ptr(e, ptr) {
			if (!ptr->cached &&
			    PTR_TIER(mi, ptr) == tier) {
				ptr->cached = true;
				nr_cached--;
				if (!nr_cached)
					goto out;
			}

			if (PTR_TIER(mi, ptr) > tier)
				have_higher_tier = true;
		}

		tier++;
	} while (have_higher_tier);
out:
	cache_member_info_put();
}

/*
 * This picks a non-stale pointer, preferabbly from a device other than
 * avoid.  Avoid can be NULL, meaning pick any.  If there are no non-stale
 * pointers to other devices, it will still pick a pointer from avoid.
 * Note that it prefers lowered-numbered pointers to higher-numbered pointers
 * as the pointers are sorted by tier, hence preferring pointers to tier 0
 * rather than pointers to tier 1.
 */
void bch_extent_pick_ptr_avoiding(struct cache_set *c, struct bkey_s_c k,
				  struct cache *avoid,
				  struct extent_pick_ptr *ret)
{
	struct bkey_s_c_extent e;
	const union bch_extent_crc *crc;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	switch (k.k->type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_COOKIE:
		ret->ca = NULL;
		return;

	case KEY_TYPE_ERROR:
		ret->ca = ERR_PTR(-EIO);
		return;

	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		e = bkey_s_c_to_extent(k);
		rcu_read_lock();
		ret->ca = NULL;

		extent_for_each_online_device_crc(c, e, crc, ptr, ca)
			if (!ptr_stale(ca, ptr)) {
				*ret = (struct extent_pick_ptr) {
					.crc = crc_to_128(e.k, crc),
					.ptr = *ptr,
					.ca = ca,
				};

				if (ca != avoid)
					break;
			}

		if (ret->ca)
			percpu_ref_get(&ret->ca->ref);
		else if (!bkey_extent_is_cached(e.k))
			ret->ca = ERR_PTR(-EIO);

		rcu_read_unlock();
		return;

	case BCH_RESERVATION:
		ret->ca = NULL;
		return;

	default:
		BUG();
	}
}

static enum merge_result bch_extent_merge(struct cache_set *c,
					  struct btree *bk,
					  struct bkey_i *l, struct bkey_i *r)
{
	struct bkey_s_extent el, er;
	union bch_extent_entry *en_l, *en_r;

	if (key_merging_disabled(c))
		return BCH_MERGE_NOMERGE;

	/*
	 * Generic header checks
	 * Assumes left and right are in order
	 * Left and right must be exactly aligned
	 */

	if (l->k.u64s		!= r->k.u64s ||
	    l->k.type		!= r->k.type ||
	    bversion_cmp(l->k.version, r->k.version) ||
	    bkey_cmp(l->k.p, bkey_start_pos(&r->k)))
		return BCH_MERGE_NOMERGE;

	switch (l->k.type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
		/* These types are mergeable, and no val to check */
		break;

	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		el = bkey_i_to_s_extent(l);
		er = bkey_i_to_s_extent(r);

		extent_for_each_entry(el, en_l) {
			struct bch_extent_ptr *lp, *rp;
			struct cache_member_cpu *m;

			en_r = bkey_idx(er.v, (u64 *) en_l - el.v->_data);

			if ((extent_entry_type(en_l) !=
			     extent_entry_type(en_r)) ||
			    extent_entry_is_crc(en_l))
				return BCH_MERGE_NOMERGE;

			lp = &en_l->ptr;
			rp = &en_r->ptr;

			if (lp->offset + el.k->size	!= rp->offset ||
			    lp->dev			!= rp->dev ||
			    lp->gen			!= rp->gen)
				return BCH_MERGE_NOMERGE;

			/* We don't allow extents to straddle buckets: */

			m = cache_member_info_get(c)->m + lp->dev;
			if ((lp->offset & ~((u64) m->bucket_size - 1)) !=
			    (rp->offset & ~((u64) m->bucket_size - 1))) {
				cache_member_info_put();
				return BCH_MERGE_NOMERGE;

			}
			cache_member_info_put();
		}

		break;
	case BCH_RESERVATION: {
		struct bkey_i_reservation *li = bkey_i_to_reservation(l);
		struct bkey_i_reservation *ri = bkey_i_to_reservation(r);

		if (li->v.generation != ri->v.generation ||
		    li->v.nr_replicas != ri->v.nr_replicas)
			return BCH_MERGE_NOMERGE;
		break;
	}
	default:
		return BCH_MERGE_NOMERGE;
	}

	l->k.needs_whiteout |= r->k.needs_whiteout;

	/* Keys with no pointers aren't restricted to one bucket and could
	 * overflow KEY_SIZE
	 */
	if ((u64) l->k.size + r->k.size > KEY_SIZE_MAX) {
		bch_key_resize(&l->k, KEY_SIZE_MAX);
		bch_cut_front(l->k.p, r);
		return BCH_MERGE_PARTIAL;
	}

	bch_key_resize(&l->k, l->k.size + r->k.size);

	return BCH_MERGE_MERGE;
}

static void extent_i_save(struct btree *b, struct bkey_packed *dst,
			  struct bkey_i *src)
{
	struct bkey_format *f = &b->format;
	struct bkey_i *dst_unpacked;

	BUG_ON(bkeyp_val_u64s(f, dst) != bkey_val_u64s(&src->k));

	/*
	 * We don't want the bch_verify_key_order() call in extent_save(),
	 * because we may be out of order with deleted keys that are about to be
	 * removed by extent_bset_insert()
	 */

	if ((dst_unpacked = packed_to_bkey(dst)))
		bkey_copy(dst_unpacked, src);
	else
		BUG_ON(!bkey_pack(dst, src, f));
}

static bool extent_merge_one_overlapping(struct btree_iter *iter,
					 struct bpos new_pos,
					 struct bset_tree *t,
					 struct bkey_packed *k, struct bkey uk,
					 bool check, bool could_pack)
{
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];

	BUG_ON(!bkey_deleted(k));

	if (check) {
		return !bkey_packed(k) || could_pack;
	} else {
		uk.p = new_pos;
		extent_save(b, node_iter, k, &uk);
		bch_bset_fix_invalidated_key(b, t, k);
		bch_btree_node_iter_fix(iter, b, node_iter, t,
					k, k->u64s, k->u64s);
		return true;
	}
}

static bool extent_merge_do_overlapping(struct btree_iter *iter,
					struct bkey *m, bool back_merge)
{
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	struct bset_tree *t;
	struct bkey_packed *k;
	struct bkey uk;
	struct bpos new_pos = back_merge ? m->p : bkey_start_pos(m);
	bool could_pack = bkey_pack_pos((void *) &uk, new_pos, b);
	bool check = true;

	/*
	 * @m is the new merged extent:
	 *
	 * The merge took place in the last bset; we know there can't be any 0
	 * size extents overlapping with m there because if so they would have
	 * been between the two extents we merged.
	 *
	 * But in the other bsets, we have to check for and fix such extents:
	 */
do_fixup:
	for_each_bset(b, t) {
		if (t == bset_tree_last(b))
			break;

		/*
		 * if we don't find this bset in the iterator we already got to
		 * the end of that bset, so start searching from the end.
		 */
		k = bch_btree_node_iter_bset_pos(node_iter, b, t);

		if (k == btree_bkey_last(b, t))
			k = bkey_prev_all(b, t, k);
		if (!k)
			continue;

		if (back_merge) {
			/*
			 * Back merge: 0 size extents will be before the key
			 * that was just inserted (and thus the iterator
			 * position) - walk backwards to find them
			 */
			for (;
			     k &&
			     (uk = bkey_unpack_key(b, k),
			      bkey_cmp(uk.p, bkey_start_pos(m)) > 0);
			     k = bkey_prev_all(b, t, k)) {
				if (bkey_cmp(uk.p, m->p) >= 0)
					continue;

				if (!extent_merge_one_overlapping(iter, new_pos,
						t, k, uk, check, could_pack))
					return false;
			}
		} else {
			/* Front merge - walk forwards */
			for (;
			     k != btree_bkey_last(b, t) &&
			     (uk = bkey_unpack_key(b, k),
			      bkey_cmp(uk.p, m->p) < 0);
			     k = bkey_next(k)) {
				if (bkey_cmp(uk.p,
					     bkey_start_pos(m)) <= 0)
					continue;

				if (!extent_merge_one_overlapping(iter, new_pos,
						t, k, uk, check, could_pack))
					return false;
			}
		}
	}

	if (check) {
		check = false;
		goto do_fixup;
	}

	return true;
}

/*
 * When merging an extent that we're inserting into a btree node, the new merged
 * extent could overlap with an existing 0 size extent - if we don't fix that,
 * it'll break the btree node iterator so this code finds those 0 size extents
 * and shifts them out of the way.
 *
 * Also unpacks and repacks.
 */
static bool bch_extent_merge_inline(struct cache_set *c,
				    struct btree_iter *iter,
				    struct bkey_packed *l,
				    struct bkey_packed *r,
				    bool back_merge)
{
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	const struct bkey_format *f = &b->format;
	struct bset_tree *t = bset_tree_last(b);
	struct bkey_packed *m;
	BKEY_PADDED(k) li;
	BKEY_PADDED(k) ri;
	struct bkey_i *mi;
	struct bkey tmp;

	/*
	 * We need to save copies of both l and r, because we might get a
	 * partial merge (which modifies both) and then fails to repack
	 */
	bkey_unpack(b, &li.k, l);
	bkey_unpack(b, &ri.k, r);

	m = back_merge ? l : r;
	mi = back_merge ? &li.k : &ri.k;

	/* l & r should be in last bset: */
	EBUG_ON(bch_bkey_to_bset(b, m) != t);

	switch (bch_extent_merge(c, b, &li.k, &ri.k)) {
	case BCH_MERGE_NOMERGE:
		return false;
	case BCH_MERGE_PARTIAL:
		if (bkey_packed(m) && !bkey_pack_key((void *) &tmp, &mi->k, f))
			return false;

		if (!extent_merge_do_overlapping(iter, &li.k.k, back_merge))
			return false;

		extent_i_save(b, m, mi);
		bch_bset_fix_invalidated_key(b, t, m);

		/*
		 * Update iterator to reflect what we just inserted - otherwise,
		 * the iter_fix() call is going to put us _before_ the key we
		 * just partially merged with:
		 */
		if (back_merge)
			bch_btree_iter_set_pos_same_leaf(iter, li.k.k.p);

		bch_btree_node_iter_fix(iter, iter->nodes[0], node_iter,
					t, m, m->u64s, m->u64s);

		if (!back_merge)
			bkey_copy(packed_to_bkey(l), &li.k);
		else
			bkey_copy(packed_to_bkey(r), &ri.k);
		return false;
	case BCH_MERGE_MERGE:
		if (bkey_packed(m) && !bkey_pack_key((void *) &tmp, &li.k.k, f))
			return false;

		if (!extent_merge_do_overlapping(iter, &li.k.k, back_merge))
			return false;

		extent_i_save(b, m, &li.k);
		bch_bset_fix_invalidated_key(b, t, m);

		bch_btree_node_iter_fix(iter, iter->nodes[0], node_iter,
					t, m, m->u64s, m->u64s);
		return true;
	default:
		BUG();
	}
}

const struct bkey_ops bch_bkey_extent_ops = {
	.key_invalid	= bch_extent_invalid,
	.key_debugcheck	= bch_extent_debugcheck,
	.val_to_text	= bch_extent_to_text,
	.swab		= bch_ptr_swab,
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.is_extents	= true,
};
