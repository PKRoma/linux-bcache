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

static void sort_key_next(struct btree_node_iter *iter,
			  struct btree_keys *b,
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
	int _c = bkey_cmp_packed(&b->format,				\
				 __btree_node_offset_to_key(b, (l).k),	\
				 __btree_node_offset_to_key(b, (r).k));	\
									\
	_c ? _c > 0 : (l).k > (r).k;					\
})

static inline bool should_drop_next_key(struct btree_node_iter *iter,
					struct btree_keys *b)
{
	const struct bkey_format *f = &b->format;
	struct btree_node_iter_set *l = iter->data, *r = iter->data + 1;

	if (bkey_deleted(__btree_node_offset_to_key(b, l->k)))
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
	return !bkey_cmp_packed(f,
				__btree_node_offset_to_key(b, l->k),
				__btree_node_offset_to_key(b, r->k));
}

struct btree_nr_keys bch_key_sort_fix_overlapping(struct btree_keys *b,
						  struct bset *bset,
						  struct btree_node_iter *iter)
{
	struct bkey_packed *out = bset->start;
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	heap_resort(iter, key_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		if (!should_drop_next_key(iter, b)) {
			struct bkey_packed *k =
				__btree_node_offset_to_key(b, iter->data->k);

			/* XXX: need better bkey_copy */
			memcpy(out, k, bkey_bytes(k));
			btree_keys_account_key_add(&nr, out);
			out = bkey_next(out);
		}

		sort_key_next(iter, b, iter->data);
		heap_sift(iter, 0, key_sort_cmp);
	}

	bset->u64s = cpu_to_le16((u64 *) out - bset->_data);
	return nr;
}

/* This returns true if insert should be inserted, false otherwise */

enum btree_insert_ret
bch_insert_fixup_key(struct btree_iter *iter,
		     struct bkey_i *insert,
		     struct journal_res *res)
{
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	int cmp;

	BUG_ON(iter->level);
	EBUG_ON((k = bch_btree_node_iter_prev_all(node_iter, &b->keys)) &&
		(bkey_deleted(k)
		 ? bkey_cmp_packed(f, k, &insert->k) > 0
		 : bkey_cmp_packed(f, k, &insert->k) >= 0));

	while ((k = bch_btree_node_iter_peek_all(node_iter, &b->keys)) &&
	       (cmp = bkey_cmp_packed(f, k, &insert->k)) <= 0) {
		if (!cmp && !bkey_deleted(k)) {
			k->type = KEY_TYPE_DELETED;
			btree_keys_account_key_drop(&b->keys.nr, k);
		}

		bch_btree_node_iter_next_all(node_iter, &b->keys);
	}

	bch_btree_insert_and_journal(iter, insert, res);
	return BTREE_INSERT_OK;
}

/* Common among btree and extent ptrs */

bool bch_extent_has_device(struct bkey_s_c_extent e, unsigned dev)
{
	const struct bch_extent_ptr *ptr;

	extent_for_each_ptr(e, ptr)
		if (ptr->dev == dev)
			return true;

	return false;
}

unsigned bch_extent_nr_ptrs_from(struct bkey_s_c_extent e,
				 const struct bch_extent_ptr *start)
{
	const struct bch_extent_ptr *ptr;
	unsigned nr_ptrs = 0;

	extent_for_each_ptr_from(e, ptr, start)
		nr_ptrs++;

	return nr_ptrs;
}

unsigned bch_extent_nr_ptrs(struct bkey_s_c_extent e)
{
	return bch_extent_nr_ptrs_from(e, &e.v->start->ptr);
}

/* returns true if equal */
static bool crc_cmp(union bch_extent_entry *l, union bch_extent_entry *r)
{
	return extent_entry_type(l) == extent_entry_type(r) &&
		!memcmp(l, r, extent_entry_bytes(l));
}

/* Increment pointers after @crc by crc's offset until the next crc entry: */
void extent_adjust_pointers(struct bkey_s_extent e, union bch_extent_entry *crc)
{
	union bch_extent_entry *entry;
	unsigned offset = crc_to_64((void *) crc).offset;

	extent_for_each_entry_from(e, entry, extent_entry_next(crc)) {
		if (!extent_entry_is_ptr(entry))
			return;

		entry->ptr.offset += offset;
	}
}

static void extent_cleanup_crcs(struct bkey_s_extent e)
{
	union bch_extent_entry *crc = e.v->start, *prev = NULL;

	while (crc != extent_entry_last(e)) {
		union bch_extent_entry *next = extent_entry_next(crc);
		size_t crc_u64s = extent_entry_u64s(crc);

		if (!extent_entry_is_crc(crc))
			goto next;

		if (next != extent_entry_last(e) &&
		    extent_entry_is_crc(next)) {
			/*
			 * Two crc entries right after the other, the first one
			 * doesn't have any pointers and we can just drop it:
			 */
			goto drop;
		}

		if (prev && crc_cmp(crc, prev)) {
			/*
			 * This crc entry is identical to the previous one, drop
			 * it:
			 */
			goto drop;
		}

		if (!prev &&
		    !crc_to_64((void *) crc).csum_type &&
		    !crc_to_64((void *) crc).compression_type){
			extent_adjust_pointers(e, crc);
			goto drop;
		}

		prev = crc;
next:
		crc = next;
		continue;
drop:
		memmove(crc, next,
			(void *) extent_entry_last(e) - (void *) next);
		e.k->u64s -= crc_u64s;
	}
}

void bch_extent_drop_ptr(struct bkey_s_extent e, struct bch_extent_ptr *ptr)
{
	__bch_extent_drop_ptr(e, ptr);
	extent_cleanup_crcs(e);
}

static bool should_drop_ptr(const struct cache_set *c,
			    struct bkey_s_c_extent e,
			    const struct bch_extent_ptr *ptr)
{
	struct cache *ca;

	return (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr);
}

void bch_extent_drop_stale(struct cache_set *c, struct bkey_s_extent e)
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
		extent_cleanup_crcs(e);
}

static bool bch_ptr_normalize(struct btree_keys *bk, struct bkey_s k)
{
	struct btree *b = container_of(bk, struct btree, keys);

	return bch_extent_normalize(b->c, k);
}

static void bch_ptr_swab(const struct bkey_format *f, struct bkey_packed *k)
{
	u64 *d = (u64 *) bkeyp_val(f, k);
	unsigned i;

	for (i = 0; i < bkeyp_val_u64s(f, k); i++)
		d[i] = swab64(d[i]);
}

static const char *extent_ptr_invalid(const struct cache_member_rcu *mi,
				      const struct bch_extent_ptr *ptr,
				      unsigned size_ondisk)
{
	const struct cache_member_cpu *m = mi->m + ptr->dev;

	if (ptr->dev > mi->nr_in_set || !m->valid)
		return "pointer to invalid device";

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
	const struct bch_extent_ptr *ptr;
	struct bch_extent_crc64 crc;
	struct cache *ca;
	bool first = true;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	rcu_read_lock();
	extent_for_each_entry(e, entry) {
		if (!first)
			p(" ");

		switch (extent_entry_type(entry)) {
		case BCH_EXTENT_ENTRY_crc32:
		case BCH_EXTENT_ENTRY_crc64:
			crc = crc_to_64((void *) entry);
			p("crc: c_size %u size %u offset %u csum %u compress %u",
			  crc.compressed_size, crc.uncompressed_size,
			  crc.offset, crc.csum_type, crc.compression_type);
			break;
		case BCH_EXTENT_ENTRY_ptr:
			ptr = &entry->ptr;
			p("ptr: %u:%llu gen %u%s", ptr->dev,
			  (u64) ptr->offset, ptr->gen,
			  (ca = PTR_CACHE(c, ptr)) && ptr_stale(ca, ptr)
			  ? " stale" : "");
			break;
		}

		first = false;
	}
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
			reason = extent_ptr_invalid(mi, ptr,
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
		      g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		      g->oldest_gen, g->mark.counter);
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
	union bch_extent_crc *crc;
	const struct bch_extent_ptr *ptr;
	struct cache *ca;

	rcu_read_lock();

	extent_for_each_online_device_crc(c, e, crc, ptr, ca) {
		if (cache_set_inconsistent_on(crc, c,
				"btree node pointer with crc at btree %u level %u/%u bucket %zu",
				b->btree_id, b->level, btree_node_root(b)
				? btree_node_root(b)->level : -1,
				PTR_BUCKET_NR(ca, ptr)))
			break;

		if (cache_inconsistent_on(ptr_stale(ca, ptr), ca,
				"stale btree node pointer at btree %u level %u/%u bucket %zu",
				b->btree_id, b->level, btree_node_root(b)
				? btree_node_root(b)->level : -1,
				PTR_BUCKET_NR(ca, ptr)))
			continue;

		percpu_ref_get(&ca->ref);
		rcu_read_unlock();

		return (struct extent_pick_ptr) { .ptr = *ptr, .ca = ca };
	}

	rcu_read_unlock();

	return (struct extent_pick_ptr) { .ca = NULL, };
}

const struct btree_keys_ops bch_btree_interior_node_ops = {
};

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
			switch (bch_extent_crc_type(crc)) {
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

/*
 * Returns a key corresponding to the start of @k split at @where, @k will be
 * the second half of the split
 */
#define bch_key_split(_where, _k)				\
({								\
	BKEY_PADDED(k) __tmp;					\
								\
	bkey_copy(&__tmp.k, _k);				\
	bch_cut_back(_where, &__tmp.k.k);			\
	bch_cut_front(_where, _k);				\
	&__tmp.k;						\
})

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
static bool __extent_save(struct bkey_packed *dst, struct bkey *src,
			  const struct bkey_format *f)
{
	struct bkey_i *dst_unpacked;

	if ((dst_unpacked = packed_to_bkey(dst))) {
		dst_unpacked->k = *src;
		return true;
	} else {
		return bkey_pack_key(dst, src, f);
	}
}

static void extent_save(struct bkey_packed *dst, struct bkey *src,
			const struct bkey_format *f)
{
	BUG_ON(!__extent_save(dst, src, f));
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
	const struct bkey_format *_f = &b->format;			\
	struct bkey _ul = bkey_unpack_key(_f,				\
				__btree_node_offset_to_key(b, (l).k));	\
	struct bkey _ur = bkey_unpack_key(_f,				\
				__btree_node_offset_to_key(b, (r).k));	\
									\
	int _c = bkey_cmp(bkey_start_pos(&_ul), bkey_start_pos(&_ur));	\
	_c ? _c > 0 : (l).k < (r).k;					\
})

static inline void extent_sort_sift(struct btree_node_iter *iter,
				    struct btree_keys *b, size_t i)
{
	heap_sift(iter, i, extent_sort_cmp);
}

static inline void extent_sort_next(struct btree_node_iter *iter,
				    struct btree_keys *b,
				    struct btree_node_iter_set *i)
{
	sort_key_next(iter, b, i);
	heap_sift(iter, i - iter->data, extent_sort_cmp);
}

static struct bkey_packed *extent_sort_append(struct btree_keys *b,
					      struct btree_nr_keys *nr,
					      struct bkey_packed *out,
					      struct bkey_packed **prev,
					      struct bkey_packed *k)
{
	if (bkey_deleted(k))
		return out;

	btree_keys_account_key_add(nr, k);

	/* XXX: need better bkey_copy */
	memcpy(out, k, bkey_bytes(k));

	/*
	 * prev/out are packed, try_merge() works on unpacked keys... may make
	 * this work again later, but the main btree_mergesort() handles
	 * unpacking/merging/repacking
	 */
#if 0
	if (*prev && bch_bkey_try_merge(b, *prev, out))
		return out;
#endif

	*prev = out;
	return bkey_next(out);
}

struct btree_nr_keys bch_extent_sort_fix_overlapping(struct btree_keys *b,
					struct bset *bset,
					struct btree_node_iter *iter)
{
	struct bkey_format *f = &b->format;
	struct btree_node_iter_set *_l = iter->data, *_r;
	struct bkey_packed *prev = NULL, *out = bset->start, *lk, *rk;
	struct bkey l_unpacked, r_unpacked;
	struct bkey_s l, r;
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	heap_resort(iter, extent_sort_cmp);

	while (!bch_btree_node_iter_end(iter)) {
		lk = __btree_node_offset_to_key(b, _l->k);

		if (iter->used == 1) {
			out = extent_sort_append(b, &nr, out, &prev, lk);
			extent_sort_next(iter, b, _l);
			continue;
		}

		_r = iter->data + 1;
		if (iter->used > 2 &&
		    extent_sort_cmp(_r[0], _r[1]))
			_r++;

		rk = __btree_node_offset_to_key(b, _r->k);

		l = __bkey_disassemble(f, lk, &l_unpacked);
		r = __bkey_disassemble(f, rk, &r_unpacked);

		/* If current key and next key don't overlap, just append */
		if (bkey_cmp(l.k->p, bkey_start_pos(r.k)) <= 0) {
			out = extent_sort_append(b, &nr, out, &prev, lk);
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
				extent_save(rk, r.k, f);
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
			extent_save(lk, l.k, f);

			extent_sort_sift(iter, b, 0);

			out = extent_sort_append(b, &nr, out, &prev,
						 bkey_to_packed(&tmp.k));
		} else {
			bch_cut_back(bkey_start_pos(r.k), l.k);
			extent_save(lk, l.k, f);
		}
	}

	bset->u64s = cpu_to_le16((u64 *) out - bset->_data);
	return nr;
}

static int bch_add_sectors(struct btree_iter *iter, struct bkey_s_c k,
			   u64 offset, s64 sectors, bool fail_if_stale,
			   struct bucket_stats_cache_set *stats)
{
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];
	int ret;

	EBUG_ON(iter->level);
	EBUG_ON(bkey_cmp(bkey_start_pos(k.k), b->data->min_key) < 0);

	if (!sectors)
		return 0;

	ret = bch_mark_key(c, k, sectors, fail_if_stale, false,
			   gc_pos_btree_node(b), stats);
	if (ret)
		return ret;

	if (bkey_extent_is_data(k.k) &&
	    !bkey_extent_is_cached(k.k))
		bcache_dev_sectors_dirty_add(c, k.k->p.inode, offset, sectors);

	return 0;
}

static void bch_subtract_sectors(struct btree_iter *iter, struct bkey_s_c k,
				 u64 offset, s64 sectors,
				 struct bucket_stats_cache_set *stats)
{
	bch_add_sectors(iter, k, offset, -sectors, false, stats);
}

/* These wrappers subtract exactly the sectors that we're removing from @k */
static void bch_cut_subtract_back(struct btree_iter *iter,
				  struct bpos where, struct bkey_s k,
				  struct bucket_stats_cache_set *stats)
{
	bch_subtract_sectors(iter, k.s_c, where.offset,
			     k.k->p.offset - where.offset,
			     stats);
	bch_cut_back(where, k.k);
}

static void bch_cut_subtract_front(struct btree_iter *iter,
				   struct bpos where, struct bkey_s k,
				   struct bucket_stats_cache_set *stats)
{
	bch_subtract_sectors(iter, k.s_c, bkey_start_offset(k.k),
			     where.offset - bkey_start_offset(k.k),
			     stats);
	__bch_cut_front(where, k);
}

static void bch_drop_subtract(struct btree_iter *iter, struct bkey_s k,
			      struct bucket_stats_cache_set *stats)
{
	if (k.k->size)
		bch_subtract_sectors(iter, k.s_c,
				     bkey_start_offset(k.k), k.k->size,
				     stats);
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
	    l.k->version != r.k->version)
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
					       struct btree_iter *iter,
					       struct bpos next_pos,
					       struct bkey_s_c k,
					       const struct bkey_i *new)
{
	struct bch_replace_info *replace = container_of(hook,
					struct bch_replace_info, hook);
	struct bkey_i *old = &replace->key;

	EBUG_ON(iter->btree_id != BTREE_ID_EXTENTS);

	/* iter->pos tracks what we've checked so far: */
	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&new->k)) < 0);

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

#define MAX_LOCK_HOLD_TIME	(5 * NSEC_PER_MSEC)

static enum btree_insert_ret extent_insert_should_stop(struct btree_iter *iter,
						       struct bkey_i *insert,
						       struct journal_res *res,
						       u64 start_time,
						       unsigned nr_done)
{
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];

	/*
	 * Check if we have sufficient space in both the btree node and the
	 * journal reservation:
	 *
	 * Each insert checks for room in the journal entry, but we check for
	 * room in the btree node up-front. In the worst case, bkey_cmpxchg()
	 * will insert two keys, and one iteration of this room will insert one
	 * key, so we need room for three keys.
	 *
	 * A discard operation can end up overwriting a _lot_ of extents and
	 * doing a lot of work under the btree node write lock - bail out if
	 * we've been running for too long and readers are waiting on the lock:
	 */
	if (!bch_btree_node_insert_fits(c, b, insert->k.u64s))
		return BTREE_INSERT_BTREE_NODE_FULL;
	else if (!journal_res_insert_fits(c, res, insert))
		return BTREE_INSERT_JOURNAL_RES_FULL; /* XXX worth tracing */
	else if (nr_done > 10 &&
		 time_after64(local_clock(), start_time +
			      MAX_LOCK_HOLD_TIME) &&
		 !list_empty_careful(&b->lock.wait_list[SIX_LOCK_read]))
		return BTREE_INSERT_NEED_RESCHED;
	else
		return BTREE_INSERT_OK;
}

static void extent_insert_committed(struct btree_iter *iter,
				    struct bkey_i *insert,
				    struct journal_res *res)
{
	EBUG_ON(bkey_cmp(insert->k.p, iter->pos) < 0);
	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k)) < 0);

	if (bkey_cmp(iter->pos, bkey_start_pos(&insert->k)) > 0) {
		EBUG_ON(bkey_deleted(&insert->k) || !insert->k.size);

		bch_btree_insert_and_journal(iter,
				bch_key_split(iter->pos, insert), res);
	}
}

static enum extent_insert_hook_ret
__extent_insert_advance_pos(struct extent_insert_hook *hook,
			    struct btree_iter *iter,
			    struct bpos next_pos,
			    struct bkey_i *insert,
			    struct bkey_s_c k,
			    struct journal_res *res,
			    struct bucket_stats_cache_set *stats)
{
	enum extent_insert_hook_ret ret;

	if (k.k && k.k->size &&
	    insert->k.version &&
	    k.k->version > insert->k.version)
		ret = BTREE_HOOK_NO_INSERT;
	else if (hook)
		ret = hook->fn(hook, iter, next_pos, k, insert);
	else
		ret = BTREE_HOOK_DO_INSERT;

	EBUG_ON(bkey_deleted(&insert->k) || !insert->k.size);

	switch (ret) {
	case BTREE_HOOK_DO_INSERT:
		break;
	case BTREE_HOOK_NO_INSERT:
		extent_insert_committed(iter, insert, res);
		bch_cut_subtract_front(iter, next_pos,
				       bkey_i_to_s(insert), stats);
		break;
	}

	/*
	 * Don't update iter->pos until after calling the hook,
	 * because the hook fn may use it:
	 */
	bch_btree_iter_set_pos(iter, next_pos);
	return ret;
}

/*
 * Update iter->pos, marking how much of @insert we've processed, and call hook
 * fn:
 */
static enum extent_insert_hook_ret
extent_insert_advance_pos(struct extent_insert_hook *hook,
			  struct btree_iter *iter,
			  struct bkey_i *insert,
			  struct bkey_s_c k,
			  struct journal_res *res,
			  struct bucket_stats_cache_set *stats)
{
	struct btree *b = iter->nodes[0];
	struct bpos next_pos = k.k
		? bpos_min(insert->k.p, k.k->p)
		: bpos_min(insert->k.p, b->key.k.p);

	/* hole? */
	if (k.k && bkey_cmp(iter->pos, bkey_start_pos(k.k)) < 0) {
		bool might_split = bkey_cmp(iter->pos,
				bkey_start_pos(&insert->k)) > 0;

		/*
		 * If a hole causes us to split and insert a previously
		 * comitted portion, return BTREE_HOOK_NO_INSERT to recheck
		 * if we have room in journal res/btree node:
		 */
		if (__extent_insert_advance_pos(hook, iter, bkey_start_pos(k.k),
						insert, bkey_s_c_null, res,
						stats) == BTREE_HOOK_NO_INSERT &&
		    might_split)
			return BTREE_HOOK_NO_INSERT;
	}

	/* avoid redundant calls to hook fn: */
	if (!bkey_cmp(iter->pos, next_pos))
		return BTREE_HOOK_DO_INSERT;

	return __extent_insert_advance_pos(hook, iter, next_pos,
					   insert, k, res, stats);
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
bch_insert_fixup_extent(struct btree_iter *iter,
			struct bkey_i *insert,
			struct disk_reservation *disk_res,
			struct extent_insert_hook *hook,
			struct journal_res *res,
			unsigned flags)
{
	struct cache_set *c = iter->c;
	struct btree *b = iter->nodes[0];
	struct btree_node_iter *node_iter = &iter->node_iters[0];
	const struct bkey_format *f = &b->keys.format;
	struct bkey_packed *_k;
	struct bkey unpacked;
	struct bucket_stats_cache_set stats = { 0 };
	unsigned nr_done = 0;
	u64 start_time = local_clock();
	enum btree_insert_ret ret = BTREE_INSERT_OK;

	EBUG_ON(iter->level);
	EBUG_ON(bkey_deleted(&insert->k) || !insert->k.size);

	/*
	 * As we process overlapping extents, we advance @iter->pos both to
	 * signal to our caller (btree_insert_key()) how much of @insert has
	 * been inserted, and also to keep @iter->pos consistent with @insert
	 * and the node iterator that we're advancing:
	 */
	EBUG_ON(bkey_cmp(iter->pos, bkey_start_pos(&insert->k)));

	/*
	 * If this is a cmpxchg operation, @insert doesn't necessarily exist in
	 * the btree, and may have pointers not pinned by open buckets; thus
	 * some of the pointers might be stale because we raced with foreground
	 * writes.
	 *
	 * If that happens bkey_cmpxchg() is going to fail; bail out here
	 * instead of calling subtract_sectors() in the fail path to avoid
	 * various races (we definitely don't want to increment/decrement
	 * sectors_dirty on a bucket that's been reused, or worse have a bucket
	 * go stale between here and subtract_sectors()).
	 *
	 * But only bail out here for cmpxchg operations - in journal replay we
	 * can also insert keys with stale pointers, but for those we still need
	 * to proceed with the insertion.
	 */
	if (!(flags & BTREE_INSERT_NO_MARK_KEY) &&
	    bch_add_sectors(iter, bkey_i_to_s_c(insert),
			    bkey_start_offset(&insert->k),
			    insert->k.size,
			    true,
			    &stats)) {
		/* We raced - a dirty pointer was stale */
		bch_btree_iter_set_pos(iter, bpos_min(insert->k.p, b->key.k.p));
		bch_cut_back(iter->pos, &insert->k);
		goto apply_stats;
	}

	while (insert->k.size &&
	       (_k = bch_btree_node_iter_peek_overlapping(node_iter, &b->keys,
							  &insert->k))) {
		struct bkey_s k = __bkey_disassemble(f, _k, &unpacked);

		ret = extent_insert_should_stop(iter, insert, res,
						start_time, nr_done);
		if (ret != BTREE_INSERT_OK)
			goto stop;

		/*
		 * Only call advance pos & call hook for nonzero size extents:
		 * If hook returned BTREE_HOOK_NO_INSERT, @insert no longer
		 * overlaps with @k:
		 */
		if (k.k->size &&
		    (extent_insert_advance_pos(hook, iter, insert, k.s_c, res,
					       &stats) == BTREE_HOOK_NO_INSERT))
			continue;

		/* k is the key currently in the tree, 'insert' is the new key */
		switch (bch_extent_overlap(&insert->k, k.k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			/* insert and k share the start, invalidate in k */
			bch_cut_subtract_front(iter, insert->k.p, k, &stats);
			extent_save(_k, k.k, f);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			/* insert and k share the end, invalidate in k */
			bch_cut_subtract_back(iter,
					      bkey_start_pos(&insert->k),
					      k, &stats);
			extent_save(_k, k.k, f);

			/*
			 * As the auxiliary tree is indexed by the end of the
			 * key and we've just changed the end, update the
			 * auxiliary tree.
			 */
			bch_bset_fix_invalidated_key(&b->keys, _k);
			bch_btree_node_iter_advance(node_iter, &b->keys);
			break;

		case BCH_EXTENT_OVERLAP_ALL: {
			struct bpos orig_pos = k.k->p;

			/* The insert key completely covers k, invalidate k */
			if (!bkey_deleted(_k))
				btree_keys_account_key_drop(&b->keys.nr, _k);

			bch_drop_subtract(iter, k, &stats);
			k.k->p = bkey_start_pos(&insert->k);
			if (!__extent_save(_k, k.k, f)) {
				/*
				 * Couldn't repack: we aren't necessarily able
				 * to repack if the new key is outside the range
				 * of the old extent, so we have to split
				 * @insert:
				 */
				k.k->p = orig_pos;
				extent_save(_k, k.k, f);

				extent_insert_advance_pos(hook, iter, insert,
							  k.s_c, res, &stats);
				extent_insert_committed(iter, insert, res);
				/*
				 * We split and inserted upto at k.k->p - that
				 * has to coincide with iter->pos, so that we
				 * don't have anything more we have to insert
				 * until we recheck our journal reservation:
				 */
				EBUG_ON(bkey_cmp(iter->pos, k.k->p));
			}

			bch_bset_fix_invalidated_key(&b->keys, _k);
			bch_btree_node_iter_advance(node_iter, &b->keys);
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
			bch_cut_back(bkey_start_pos(&insert->k), &split.k.k);

			__bch_cut_front(bkey_start_pos(&insert->k), k);
			bch_cut_subtract_front(iter, insert->k.p, k, &stats);
			extent_save(_k, k.k, f);

			bch_btree_bset_insert(iter, b, node_iter, &split.k);
			break;
		}
		}
	}

	if (insert->k.size)
		extent_insert_advance_pos(hook, iter, insert, bkey_s_c_null,
					  res, &stats);
stop:
	extent_insert_committed(iter, insert, res);

	/*
	 * Subtract any remaining sectors from @insert, if we bailed out early
	 * and didn't fully insert @insert:
	 */
	if (insert->k.size)
		bch_subtract_sectors(iter, bkey_i_to_s_c(insert),
				     iter->pos.offset,
				     insert->k.p.offset - iter->pos.offset,
				     &stats);
apply_stats:
	bch_cache_set_stats_apply(c, &stats, disk_res);

	if (insert->k.size && !bkey_cmp(iter->pos, b->key.k.p))
		ret = BTREE_INSERT_NEED_TRAVERSE;

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
		struct bch_extent_crc64 crc64;
		struct cache_member_rcu *mi = cache_member_info_get(c);
		unsigned size_ondisk = e.k->size;
		const char *reason;

		extent_for_each_entry(e, entry) {
			reason = "invalid extent entry type";
			if (__extent_entry_type(entry) >= BCH_EXTENT_ENTRY_MAX)
				goto invalid;

			switch (extent_entry_type(entry)) {
			case BCH_EXTENT_ENTRY_crc32:
			case BCH_EXTENT_ENTRY_crc64:
				crc64 = crc_to_64((void *) entry);

				reason = "checksum uncompressed size < key size";
				if (crc64.uncompressed_size < e.k->size)
					goto invalid;

				reason = "checksum offset > uncompressed size";
				if (crc64.offset >= crc64.uncompressed_size)
					goto invalid;

				size_ondisk = crc64.compressed_size;

				reason = "invalid checksum type";
				if (crc64.csum_type >= BCH_CSUM_NR)
					goto invalid;

				reason = "invalid compression type";
				if (crc64.csum_type >= BCH_COMPRESSION_NR)
					goto invalid;
				break;
			case BCH_EXTENT_ENTRY_ptr:
				reason = extent_ptr_invalid(mi, &entry->ptr, size_ondisk);
				if (reason)
					goto invalid;
				break;
			}
		}

		cache_member_info_put();
		return NULL;
invalid:
		cache_member_info_put();
		return reason;
	}

	case BCH_RESERVATION:
		return NULL;

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
		bool dirty = bch_extent_ptr_is_dirty(c, e, ptr);

		replicas++;

		if (ptr->dev >= mi->nr_in_set)
			goto bad_device;

		do {
			seq = read_seqcount_begin(&c->gc_pos_lock);
			bad = !test_bit(ptr->dev, c->cache_slots_used) &&
				c->gc_pos.phase == GC_PHASE_DONE;
		} while (read_seqcount_retry(&c->gc_pos_lock, seq));

		if (bad)
			goto bad_device;

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

				cache_set_bug_on(stale && dirty, c,
						 "stale dirty pointer");

				cache_set_bug_on(stale > 96, c,
						 "key too stale: %i",
						 stale);

				if (stale)
					break;

				bad = (mark.is_metadata ||
				       (gc_pos_cmp(c->gc_pos, gc_pos_btree_node(b)) > 0 &&
					!mark.owned_by_allocator &&
					!(dirty
					  ? mark.dirty_sectors
					  : mark.cached_sectors)));
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
		      g->read_prio, PTR_BUCKET_GEN(ca, ptr),
		      g->oldest_gen, g->mark.counter);
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

static void __extent_sort_ptrs(struct cache_member_rcu *mi,
			       struct bkey_s_extent src)
{
	struct bch_extent_ptr *src_ptr, *dst_ptr;
	union bch_extent_entry *src_crc, *dst_crc;
	BKEY_PADDED(k) tmp;
	struct bkey_s_extent dst;
	size_t u64s, crc_u64s;
	u64 *p;

	/*
	 * Insertion sort:
	 *
	 * Note: this sort needs to be stable, because pointer order determines
	 * pointer dirtyness.
	 */

	tmp.k.k = *src.k;
	dst = bkey_i_to_s_extent(&tmp.k);
	set_bkey_val_u64s(dst.k, 0);

	extent_for_each_ptr_crc(src, src_ptr, src_crc) {
		extent_for_each_ptr_crc(dst, dst_ptr, dst_crc)
			if (PTR_TIER(mi, src_ptr) < PTR_TIER(mi, dst_ptr))
				break;

		/* found insert position: */

		/*
		 * we're making sure everything has a crc at this point, if
		 * dst_ptr points to a pointer it better have a crc:
		 */
		BUG_ON(dst_ptr != &extent_entry_last(dst)->ptr && !dst_crc);
		BUG_ON(dst_crc && extent_entry_next(dst_crc) != (void *) dst_ptr);

		p = dst_ptr != &extent_entry_last(dst)->ptr
			? (void *) dst_crc
			: (void *) dst_ptr;

		if (!src_crc)
			src_crc = (void *) &((struct bch_extent_crc32) {
				.type			= 1 << BCH_EXTENT_ENTRY_crc32,
				.compressed_size	= src.k->size,
				.uncompressed_size	= src.k->size,
				.offset			= 0,
				.compression_type	= BCH_COMPRESSION_NONE,
				.csum_type		= BCH_CSUM_NONE,
				.csum			= 0,
			});

		crc_u64s = extent_entry_u64s((void *) src_crc);
		u64s = crc_u64s + sizeof(*dst_ptr) / sizeof(u64);

		memmove(p + u64s, p,
			(void *) extent_entry_last(dst) - (void *) p);
		set_bkey_val_u64s(dst.k, bkey_val_u64s(dst.k) + u64s);

		memcpy(p, src_crc, crc_u64s * sizeof(u64));
		memcpy(p + crc_u64s, src_ptr, sizeof(*src_ptr));
	}

	/* Sort done - now drop redundant crc entries: */
	extent_cleanup_crcs(dst);

	memcpy(src.v, dst.v, bkey_val_bytes(dst.k));
	set_bkey_val_u64s(src.k, bkey_val_u64s(dst.k));
}

static void extent_sort_ptrs(struct cache_set *c, struct bkey_s_extent e)
{
	struct cache_member_rcu *mi;
	struct bch_extent_ptr *ptr, *prev = NULL;
	union bch_extent_crc *crc;

	/*
	 * First check if any pointers are out of order before doing the actual
	 * sort:
	 */
	mi = cache_member_info_get(c);

	extent_for_each_ptr_crc(e, ptr, crc)
		if (prev &&
		    PTR_TIER(mi, ptr) < PTR_TIER(mi, prev)) {
			__extent_sort_ptrs(mi, e);
			break;
		}

	cache_member_info_put();
}

/*
 * bch_extent_normalize - clean up an extent, dropping stale pointers etc.
 *
 * Returns true if @k should be dropped entirely (when compacting/rewriting
 * btree nodes).
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
		return !k.k->version;

	case BCH_EXTENT:
	case BCH_EXTENT_CACHED:
		e = bkey_s_to_extent(k);

		bch_extent_drop_stale(c, e);
		extent_sort_ptrs(c, e);

		if (!bch_extent_nr_ptrs(e.c)) {
			set_bkey_val_u64s(e.k, 0);
			if (bkey_extent_is_cached(e.k)) {
				k.k->type = KEY_TYPE_DISCARD;
				if (!k.k->version)
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
					.crc = crc_to_64(crc),
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

static enum merge_result bch_extent_merge(struct btree_keys *bk,
					  struct bkey_i *l, struct bkey_i *r)
{
	struct btree *b = container_of(bk, struct btree, keys);
	struct cache_set *c = b->c;
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
	    l->k.version	!= r->k.version ||
	    bkey_cmp(l->k.p, bkey_start_pos(&r->k)))
		return BCH_MERGE_NOMERGE;

	switch (l->k.type) {
	case KEY_TYPE_DELETED:
	case KEY_TYPE_DISCARD:
	case KEY_TYPE_ERROR:
	case BCH_RESERVATION:
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
	default:
		return BCH_MERGE_NOMERGE;
	}

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

static bool extent_i_save(struct bkey_packed *dst, struct bkey_i *src,
			  const struct bkey_format *f)
{
	BUG_ON(bkeyp_val_u64s(f, dst) != bkey_val_u64s(&src->k));

	if (!__extent_save(dst, &src->k, f))
		return false;

	memcpy(bkeyp_val(f, dst), &src->v, bkey_val_bytes(&src->k));
	return true;
}

static bool extent_merge_one_overlapping(struct btree_keys *b,
				struct bkey *m, struct bpos new_pos,
				struct bkey_packed *k, struct bkey uk,
				bool check, bool could_pack)
{
	BUG_ON(!bkey_deleted(k));

	if (check) {
		if (bkey_packed(k) && !could_pack)
			return false;
	} else {
		uk.p = new_pos;
		extent_save(k, &uk, &b->format);
		bch_bset_fix_invalidated_key(b, k);
	}

	return true;
}

static bool extent_merge_do_overlapping(struct btree_keys *b,
					struct btree_node_iter *iter,
					struct bkey *m,
					bool back_merge, bool check)
{
	const struct bkey_format *f = &b->format;
	struct bset_tree *t;
	struct bkey_packed *k;
	struct bkey uk;
	struct bpos new_pos = back_merge ? bkey_start_pos(m) : m->p;
	bool could_pack = bkey_pack_pos((void *) &uk, new_pos, f);

	/*
	 * @m is the new merged extent:
	 *
	 * The merge took place in the last bset; we know there can't be any 0
	 * size extents overlapping with m there because if so they would have
	 * been between the two extents we merged.
	 *
	 * But in the other bsets, we have to check for and fix such extents:
	 */
	for (t = b->set; t < b->set + b->nsets; t++) {
		if (!t->data->u64s)
			continue;

		/*
		 * if we don't find this bset in the iterator we already got to
		 * the end of that bset, so start searching from the end.
		 */
		k = bch_btree_node_iter_bset_pos(iter, b, t->data) ?:
			bkey_prev(t, bset_bkey_last(t->data));

		if (back_merge) {
			/*
			 * Back merge: 0 size extents will be before the key
			 * that was just inserted (and thus the iterator
			 * position) - walk backwards to find them
			 */
			for (;
			     k &&
			     (uk = bkey_unpack_key(f, k),
			      bkey_cmp(uk.p, bkey_start_pos(m)) > 0);
			     k = bkey_prev(t, k)) {
				if (bkey_cmp(uk.p, m->p) >= 0)
					continue;

				if (!extent_merge_one_overlapping(b, m, new_pos,
						k, uk, check, could_pack))
					return false;
			}
		} else {
			/* Front merge - walk forwards */
			for (;
			     k != bset_bkey_last(t->data) &&
			     (uk = bkey_unpack_key(f, k),
			      bkey_cmp(uk.p, m->p) < 0);
			     k = bkey_next(k)) {
				if (bkey_cmp(uk.p,
					     bkey_start_pos(m)) <= 0)
					continue;

				if (!extent_merge_one_overlapping(b, m, new_pos,
						k, uk, check, could_pack))
					return false;
			}
		}
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
static bool bch_extent_merge_inline(struct btree_keys *b,
				    struct btree_node_iter *iter,
				    struct bkey_packed *l,
				    struct bkey_packed *r,
				    bool back_merge)
{
	const struct bkey_format *f = &b->format;
	struct bkey_packed *m;
	BKEY_PADDED(k) li;
	BKEY_PADDED(k) ri;
	struct bkey_i *mi;
	bool ret;

	/*
	 * We need to save copies of both l and r, because we might get a
	 * partial merge (which modifies both) and then fails to repack
	 */
	bkey_unpack(&li.k, f, l);
	bkey_unpack(&ri.k, f, r);

	m = back_merge ? l : r;
	mi = back_merge ? &li.k : &ri.k;

	/* l & r should be in last bset: */
	BUG_ON(m < bset_tree_last(b)->data->start ||
	       m >= bset_bkey_last(bset_tree_last(b)->data));

	switch (bch_extent_merge(b, &li.k, &ri.k)) {
	case BCH_MERGE_NOMERGE:
		return false;
	case BCH_MERGE_PARTIAL:
		if (!extent_merge_do_overlapping(b, iter, &li.k.k,
						 back_merge, true))
			return false;

		if (!extent_i_save(m, mi, f))
			return false;

		if (!back_merge)
			bkey_copy(packed_to_bkey(l), &li.k);
		else
			bkey_copy(packed_to_bkey(r), &ri.k);

		ret = false;
		break;
	case BCH_MERGE_MERGE:
		if (!extent_merge_do_overlapping(b, iter, &li.k.k,
						 back_merge, true))
			return false;

		if (!extent_i_save(m, &li.k, f))
			return false;

		ret = true;
		break;
	default:
		BUG();
	}

	extent_merge_do_overlapping(b, iter, &li.k.k, back_merge, false);
	return ret;
}

static const struct btree_keys_ops bch_extent_ops = {
	.key_normalize	= bch_ptr_normalize,
	.key_merge	= bch_extent_merge,
	.key_merge_inline = bch_extent_merge_inline,
	.is_extents	= true,
};

const struct bkey_ops bch_bkey_extent_ops = {
	.key_invalid	= bch_extent_invalid,
	.key_debugcheck	= bch_extent_debugcheck,
	.val_to_text	= bch_extent_to_text,
	.swab		= bch_ptr_swab,
	.is_extents	= true,
};

const struct btree_keys_ops *bch_btree_ops[] = {
	[BTREE_ID_EXTENTS]	= &bch_extent_ops,
	[BTREE_ID_INODES]	= &bch_inode_ops,
	[BTREE_ID_DIRENTS]	= &bch_dirent_ops,
	[BTREE_ID_XATTRS]	= &bch_xattr_ops,
};
