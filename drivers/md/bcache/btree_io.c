
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_cache.h"
#include "btree_update.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "buckets.h"
#include "checksum.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "io.h"
#include "journal.h"

#include <trace/events/bcache.h>

static void btree_bounce_free(struct cache_set *c, unsigned order,
			      bool used_mempool, void *p)
{
	if (used_mempool)
		mempool_free(virt_to_page(p), &c->btree_bounce_pool);
	else
		free_pages((unsigned long) p, order);
}

static void *btree_bounce_alloc(struct cache_set *c, unsigned order,
				bool *used_mempool)
{
	void *p;

	BUG_ON(1 << order > btree_pages(c));

	*used_mempool = false;
	p = (void *) __get_free_pages(__GFP_NOWARN|GFP_NOWAIT, order);
	if (p)
		return p;

	*used_mempool = true;
	return page_address(mempool_alloc(&c->btree_bounce_pool, GFP_NOIO));
}

typedef int (*sort_cmp_fn)(struct btree_keys *,
			   struct bkey_packed *,
			   struct bkey_packed *);

struct sort_iter {
	struct btree_keys	*b;
	unsigned		used;

	struct sort_iter_set {
		struct bkey_packed *k, *end;
	} data[MAX_BSETS + 1];
};

static void sort_iter_init(struct sort_iter *iter, struct btree_keys *b)
{
	memset(iter, 0, sizeof(*iter));
	iter->b = b;
}

static inline void __sort_iter_sift(struct sort_iter *iter,
				    unsigned from,
				    sort_cmp_fn cmp)
{
	unsigned i;

	for (i = from;
	     i + 1 < iter->used &&
	     cmp(iter->b, iter->data[i].k, iter->data[i + 1].k) > 0;
	     i++)
		swap(iter->data[i], iter->data[i + 1]);
}

static inline void sort_iter_sift(struct sort_iter *iter, sort_cmp_fn cmp)
{

	__sort_iter_sift(iter, 0, cmp);
}

static inline void sort_iter_sort(struct sort_iter *iter, sort_cmp_fn cmp)
{
	unsigned i = iter->used;

	while (i--)
		__sort_iter_sift(iter, i, cmp);
}

static void sort_iter_add(struct sort_iter *iter,
			  struct bkey_packed *k,
			  struct bkey_packed *end)
{
	BUG_ON(iter->used >= ARRAY_SIZE(iter->data));

	if (k != end)
		iter->data[iter->used++] = (struct sort_iter_set) { k, end };
}

static inline struct bkey_packed *sort_iter_peek(struct sort_iter *iter)
{
	return iter->used ? iter->data->k : NULL;
}

static inline void sort_iter_advance(struct sort_iter *iter, sort_cmp_fn cmp)
{
	iter->data->k = bkey_next(iter->data->k);

	BUG_ON(iter->data->k > iter->data->end);

	if (iter->data->k == iter->data->end)
		memmove(&iter->data[0],
			&iter->data[1],
			sizeof(iter->data[0]) * --iter->used);
	else
		sort_iter_sift(iter, cmp);
}

static inline struct bkey_packed *sort_iter_next(struct sort_iter *iter,
						 sort_cmp_fn cmp)
{
	struct bkey_packed *ret = sort_iter_peek(iter);

	if (ret)
		sort_iter_advance(iter, cmp);

	return ret;
}

static inline int sort_keys_cmp(struct btree_keys *b,
				struct bkey_packed *l,
				struct bkey_packed *r)
{
	return bkey_cmp_packed(&b->format, l, r) ?:
		(int) bkey_deleted(r) - (int) bkey_deleted(l);
}

static unsigned sort_keys(struct bkey_packed *dst,
			  struct sort_iter *iter,
			  bool filter_whiteouts)
{
	struct bkey_packed *in, *next, *out = dst;

	sort_iter_sort(iter, sort_keys_cmp);

	while ((in = sort_iter_next(iter, sort_keys_cmp))) {
		if ((next = sort_iter_peek(iter)) &&
		    !bkey_cmp_packed(&iter->b->format, in, next))
			continue;

		if (filter_whiteouts && bkey_deleted(in))
			continue;

		bkey_copy(out, in);
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static inline int sort_extents_cmp(struct btree_keys *b,
				   struct bkey_packed *l,
				   struct bkey_packed *r)
{
	return bkey_cmp_packed(&b->format, l, r) ?:
		(int) bkey_deleted(l) - (int) bkey_deleted(r);
}

static unsigned sort_extents(struct bkey_packed *dst,
			     struct sort_iter *iter,
			     bool filter_whiteouts)
{
	struct bkey_packed *in, *out = dst;

	sort_iter_sort(iter, sort_extents_cmp);

	while ((in = sort_iter_next(iter, sort_extents_cmp))) {
		if (bkey_deleted(in))
			continue;

		if (filter_whiteouts && bkey_packed_is_whiteout(iter->b, in))
			continue;

		bkey_copy(out, in);
		out = bkey_next(out);
	}

	return (u64 *) out - (u64 *) dst;
}

static void btree_node_sort(struct cache_set *c, struct btree *b,
			    struct btree_iter *iter, unsigned from,
			    bool is_write_locked)
{
	struct btree_node *out;
	struct sort_iter sort_iter;
	struct bset_tree *t;
	bool used_mempool = false, filter_whiteouts;
	u64 start_time;
	unsigned i, u64s, order, shift = b->keys.nsets - from - 1;
	bool sorting_entire_node = from == 0;

	sort_iter_init(&sort_iter, &b->keys);

	for (t = b->keys.set + from;
	     t < b->keys.set + b->keys.nsets;
	     t++) {
		u64s += le16_to_cpu(t->data->u64s);
		sort_iter_add(&sort_iter, t->data->start,
			      bset_bkey_last(t->data));
	}

	order = sorting_entire_node
		? b->keys.page_order
		: get_order(__set_bytes(b->data, u64s));

	out = btree_bounce_alloc(c, order, &used_mempool);

	start_time = local_clock();

	filter_whiteouts = bset_written(b, b->keys.set[from].data);

	u64s = btree_node_is_extents(b)
		? sort_extents(out->keys.start, &sort_iter, filter_whiteouts)
		: sort_keys(out->keys.start, &sort_iter, filter_whiteouts);

	out->keys.u64s = cpu_to_le16(u64s);

	BUG_ON((void *) bset_bkey_last(&out->keys) >
	       (void *) out + (PAGE_SIZE << order));

	if (!from)
		bch_time_stats_update(&c->btree_sort_time, start_time);

	if (!is_write_locked)
		__btree_node_lock_write(b, iter);

	/* Make sure we preserve bset journal_seq: */
	for (t = b->keys.set + from + 1;
	     t < b->keys.set + b->keys.nsets;
	     t++)
		b->keys.set[from].data->journal_seq =
			max(b->keys.set[from].data->journal_seq,
			    t->data->journal_seq);

	if (sorting_entire_node) {
		unsigned u64s = le16_to_cpu(out->keys.u64s);

		BUG_ON(order != b->keys.page_order);

		/*
		 * Our temporary buffer is the same size as the btree node's
		 * buffer, we can just swap buffers instead of doing a big
		 * memcpy()
		 */
		*out = *b->data;
		out->keys.u64s = cpu_to_le16(u64s);
		swap(out, b->data);
		b->keys.set->data = &b->data->keys;
	} else {
		b->keys.set[from].data->u64s = out->keys.u64s;
		memcpy_u64s(b->keys.set[from].data->start,
			    out->keys.start,
			    le16_to_cpu(out->keys.u64s));
	}

	for (i = from + 1; i < b->keys.nsets; i++)
		b->keys.nr.bset_u64s[from] +=
			b->keys.nr.bset_u64s[i];

	b->keys.nsets -= shift;

	for (i = from + 1; i < b->keys.nsets; i++) {
		b->keys.nr.bset_u64s[i]	= b->keys.nr.bset_u64s[i + shift];
		b->keys.set[i]		= b->keys.set[i + shift];
	}

	for (i = b->keys.nsets; i < MAX_BSETS; i++)
		b->keys.nr.bset_u64s[i] = 0;

	bch_bset_set_no_aux_tree(&b->keys, &b->keys.set[from]);

	if (!is_write_locked)
		__btree_node_unlock_write(b, iter);

	btree_bounce_free(c, order, used_mempool, out);

	bch_verify_btree_nr_keys(&b->keys);
}

/* Sort + repack in a new format: */
static struct btree_nr_keys sort_repack(struct bset *dst,
					struct btree_keys *src,
					struct btree_node_iter *src_iter,
					struct bkey_format *in_f,
					struct bkey_format *out_f,
					bool filter_whiteouts)
{
	struct bkey_packed *in, *out = bset_bkey_last(dst);
	struct btree_nr_keys nr;

	memset(&nr, 0, sizeof(nr));

	while ((in = bch_btree_node_iter_next_all(src_iter, src))) {
		if (filter_whiteouts && bkey_packed_is_whiteout(src, in))
			continue;

		if (bch_bkey_transform(out_f, out, bkey_packed(in)
				       ? in_f : &bch_bkey_format_current, in))
			out->format = KEY_FORMAT_LOCAL_BTREE;
		else
			bkey_unpack((void *) out, in_f, in);

		btree_keys_account_key_add(&nr, 0, out);
		out = bkey_next(out);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

/* Sort, repack, and merge: */
static struct btree_nr_keys sort_repack_merge(struct cache_set *c,
					      struct bset *dst,
					      struct btree_keys *src,
					      struct btree_node_iter *iter,
					      struct bkey_format *in_f,
					      struct bkey_format *out_f,
					      bool filter_whiteouts,
					      key_filter_fn filter,
					      key_merge_fn merge)
{
	struct bkey_packed *k, *prev = NULL, *out;
	struct btree_nr_keys nr;
	BKEY_PADDED(k) tmp;

	memset(&nr, 0, sizeof(nr));

	while ((k = bch_btree_node_iter_next_all(iter, src))) {
		if (filter_whiteouts && bkey_packed_is_whiteout(src, k))
			continue;

		/*
		 * The filter might modify pointers, so we have to unpack the
		 * key and values to &tmp.k:
		 */
		bkey_unpack(&tmp.k, in_f, k);

		if (filter && filter(c, src, bkey_i_to_s(&tmp.k)))
			continue;

		/* prev is always unpacked, for key merging: */

		if (prev &&
		    merge &&
		    merge(c, src, (void *) prev, &tmp.k) == BCH_MERGE_MERGE)
			continue;

		/*
		 * the current key becomes the new prev: advance prev, then
		 * copy the current key - but first pack prev (in place):
		 */
		if (prev) {
			bkey_pack(prev, (void *) prev, out_f);

			btree_keys_account_key_add(&nr, 0, prev);
			prev = bkey_next(prev);
		} else {
			prev = bset_bkey_last(dst);
		}

		bkey_copy(prev, &tmp.k);
	}

	if (prev) {
		bkey_pack(prev, (void *) prev, out_f);
		btree_keys_account_key_add(&nr, 0, prev);
		out = bkey_next(prev);
	} else {
		out = bset_bkey_last(dst);
	}

	dst->u64s = cpu_to_le16((u64 *) out - dst->_data);
	return nr;
}

void bch_btree_sort_into(struct cache_set *c,
			 struct btree *dst,
			 struct btree *src)
{
	struct btree_nr_keys nr;
	struct btree_node_iter src_iter;
	u64 start_time = local_clock();

	BUG_ON(dst->keys.nsets != 1);

	bch_bset_set_no_aux_tree(&dst->keys, dst->keys.set);

	bch_btree_node_iter_init_from_start(&src_iter, &src->keys,
					    btree_node_is_extents(src));

	if (btree_node_ops(src)->key_normalize ||
	    btree_node_ops(src)->key_merge)
		nr = sort_repack_merge(c, dst->keys.set->data,
				&src->keys, &src_iter,
				&src->keys.format,
				&dst->keys.format,
				true,
				btree_node_ops(src)->key_normalize,
				btree_node_ops(src)->key_merge);
	else
		nr = sort_repack(dst->keys.set->data,
				&src->keys, &src_iter,
				&src->keys.format,
				&dst->keys.format,
				true);

	bch_time_stats_update(&c->btree_sort_time, start_time);

	dst->keys.nr.live_u64s		+= nr.live_u64s;
	dst->keys.nr.bset_u64s[0]	+= nr.bset_u64s[0];
	dst->keys.nr.packed_keys	+= nr.packed_keys;
	dst->keys.nr.unpacked_keys	+= nr.unpacked_keys;

	bch_verify_btree_nr_keys(&dst->keys);
}

#define SORT_CRIT	(4096 / sizeof(u64))

/*
 * We're about to add another bset to the btree node, so if there's currently
 * too many bsets - sort some of them together:
 */
static bool btree_node_compact(struct cache_set *c, struct btree *b,
			       struct btree_iter *iter)
{
	unsigned crit = SORT_CRIT;
	unsigned crit_factor = int_sqrt(btree_pages(c));
	int i = 0;

	/* Don't sort if nothing to do */
	if (b->keys.nsets == 1)
		return false;

	/* If not a leaf node, always sort */
	if (b->level)
		goto sort;

	for (i = b->keys.nsets - 2; i >= 0; --i) {
		crit *= crit_factor;

		if (le16_to_cpu(b->keys.set[i].data->u64s) < crit)
			goto sort;
	}

	/* Sort if we'd overflow */
	if (b->keys.nsets == MAX_BSETS) {
		i = 0;
		goto sort;
	}

	return false;
sort:
	btree_node_sort(c, b, iter, i, false);
	return true;
}

void bch_btree_build_aux_trees(struct btree *b)
{
	struct bset_tree *t;

	for_each_bset(&b->keys, t)
		bch_bset_build_aux_tree(&b->keys, t,
				bset_unwritten(b, t->data) &&
				t == bset_tree_last(&b->keys));
}

/*
 * @bch_btree_init_next - initialize a new (unwritten) bset that can then be
 * inserted into
 *
 * Safe to call if there already is an unwritten bset - will only add a new bset
 * if @b doesn't already have one.
 *
 * Returns true if we sorted (i.e. invalidated iterators
 */
void bch_btree_init_next(struct cache_set *c, struct btree *b,
			 struct btree_iter *iter)
{
	bool did_sort;

	BUG_ON(iter && iter->nodes[b->level] != b);

	did_sort = btree_node_compact(c, b, iter);

	/* do verify if we sorted down to a single set: */
	if (did_sort && b->keys.nsets == 1)
		bch_btree_verify(c, b);

	__btree_node_lock_write(b, iter);

	if (b->written < c->sb.btree_node_size) {
		struct btree_node_entry *bne = write_block(b);

		bch_bset_init_next(&b->keys, &bne->keys);
	}

	bch_btree_build_aux_trees(b);

	__btree_node_unlock_write(b, iter);

	if (iter && did_sort)
		bch_btree_iter_reinit_node(iter, b);
}

/*
 * We seed the checksum with the entire first pointer (dev, gen and offset),
 * since for btree nodes we have to store the checksum with the data instead of
 * the pointer - this helps guard against reading a valid btree node that is not
 * the node we actually wanted:
 */
#define btree_csum_set(_b, _i)						\
({									\
	void *_data = (void *) (_i) + 8;				\
	void *_end = bset_bkey_last(&(_i)->keys);			\
									\
	bch_checksum_update(BSET_CSUM_TYPE(&(_i)->keys),		\
			    bkey_i_to_extent_c(&(_b)->key)->v._data[0],	\
			    _data,					\
			    _end - _data) ^ 0xffffffffffffffffULL;	\
})

#define btree_node_error(b, c, ptr, fmt, ...)				\
	cache_set_inconsistent(c,					\
		"btree node error at btree %u level %u/%u bucket %zu block %u u64s %u: " fmt,\
		(b)->btree_id, (b)->level, btree_node_root(c, b)	\
			    ? btree_node_root(c, b)->level : -1,	\
		PTR_BUCKET_NR(ca, ptr), (b)->written,			\
		(i)->u64s, ##__VA_ARGS__)

static const char *validate_bset(struct cache_set *c, struct btree *b,
				 struct cache *ca,
				 const struct bch_extent_ptr *ptr,
				 struct bset *i, unsigned sectors,
				 unsigned *whiteout_u64s)
{
	struct bkey_format *f = &b->keys.format;
	struct bkey_packed *k;
	bool seen_non_whiteout = false;

	if (le16_to_cpu(i->version) != BCACHE_BSET_VERSION)
		return "unsupported bset version";

	if (b->written + sectors > c->sb.btree_node_size)
		return  "bset past end of btree node";

	if (i != &b->data->keys && !i->u64s)
		btree_node_error(b, c, ptr, "empty set");

	for (k = i->start;
	     k != bset_bkey_last(i);) {
		struct bkey_s_c u;
		struct bkey tmp;
		const char *invalid;

		if (!k->u64s) {
			btree_node_error(b, c, ptr,
				"KEY_U64s 0: %zu bytes of metadata lost",
				(void *) bset_bkey_last(i) - (void *) k);

			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (bkey_next(k) > bset_bkey_last(i)) {
			btree_node_error(b, c, ptr,
					 "key extends past end of bset");

			i->u64s = cpu_to_le16((u64 *) k - i->_data);
			break;
		}

		if (k->format > KEY_FORMAT_CURRENT) {
			btree_node_error(b, c, ptr,
					 "invalid bkey format %u", k->format);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) bset_bkey_last(i) - (u64 *) k);
			continue;
		}

		if (BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN)
			bch_bkey_swab(btree_node_type(b), &b->keys.format, k);

		u = bkey_disassemble(f, k, &tmp);

		invalid = btree_bkey_invalid(c, b, u);
		if (invalid) {
			char buf[160];

			bch_bkey_val_to_text(c, btree_node_type(b),
					     buf, sizeof(buf), u);
			btree_node_error(b, c, ptr,
					 "invalid bkey %s", buf);

			i->u64s = cpu_to_le16(le16_to_cpu(i->u64s) - k->u64s);
			memmove_u64s_down(k, bkey_next(k),
					  (u64 *) bset_bkey_last(i) - (u64 *) k);
			continue;
		}

		if (BSET_SEPARATE_WHITEOUTS(i) &&
		    !seen_non_whiteout &&
		    !bkey_packed_is_whiteout(&b->keys, k)) {
			*whiteout_u64s = k->_data - i->_data;
			seen_non_whiteout = true;
		}

		k = bkey_next(k);
	}

	SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);

	b->written += sectors;
	return NULL;
}

void bch_btree_node_read_done(struct cache_set *c, struct btree *b,
			      struct cache *ca,
			      const struct bch_extent_ptr *ptr)
{
	struct btree_node_entry *bne;
	struct bset *i = &b->data->keys;
	struct btree_node_iter *iter;
	struct btree_node *sorted;
	bool used_mempool;
	unsigned u64s;
	const char *err;
	int ret;

	iter = mempool_alloc(&c->fill_iter, GFP_NOIO);
	__bch_btree_node_iter_init(iter, btree_node_is_extents(b));

	err = "dynamic fault";
	if (bch_meta_read_fault("btree"))
		goto err;

	while (b->written < c->sb.btree_node_size) {
		unsigned sectors, whiteout_u64s = 0;

		if (!b->written) {
			i = &b->data->keys;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			/* XXX: retry checksum errors */

			err = "bad checksum";
			if (le64_to_cpu(b->data->csum) !=
			    btree_csum_set(b, b->data))
				goto err;

			sectors = __set_blocks(b->data,
					       le16_to_cpu(b->data->keys.u64s),
					       block_bytes(c)) << c->block_bits;

			err = "bad magic";
			if (le64_to_cpu(b->data->magic) != bset_magic(&c->disk_sb))
				goto err;

			err = "bad btree header";
			if (!b->data->keys.seq)
				goto err;

			if (BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN) {
				bch_bpos_swab(&b->data->min_key);
				bch_bpos_swab(&b->data->max_key);
			}

			err = "incorrect max key";
			if (bkey_cmp(b->data->max_key, b->key.k.p))
				goto err;

			err = "incorrect level";
			if (BSET_BTREE_LEVEL(i) != b->level)
				goto err;

			err = bch_bkey_format_validate(&b->data->format);
			if (err)
				goto err;

			b->keys.format = b->data->format;
			b->keys.set->data = &b->data->keys;
		} else {
			bne = write_block(b);
			i = &bne->keys;

			if (i->seq != b->data->keys.seq)
				break;

			err = "unknown checksum type";
			if (BSET_CSUM_TYPE(i) >= BCH_CSUM_NR)
				goto err;

			err = "bad checksum";
			if (le64_to_cpu(bne->csum) !=
			    btree_csum_set(b, bne))
				goto err;

			sectors = __set_blocks(bne,
					       le16_to_cpu(bne->keys.u64s),
					       block_bytes(c)) << c->block_bits;
		}

		err = validate_bset(c, b, ca, ptr, i, sectors, &whiteout_u64s);
		if (err)
			goto err;

		err = "insufficient memory";
		ret = bch_journal_seq_should_ignore(c, le64_to_cpu(i->journal_seq), b);
		if (ret < 0)
			goto err;

		if (ret)
			continue;

		__bch_btree_node_iter_push(iter, &b->keys,
					   i->start,
					   bkey_idx(i, whiteout_u64s));

		__bch_btree_node_iter_push(iter, &b->keys,
					   bkey_idx(i, whiteout_u64s),
					   bset_bkey_last(i));
	}

	err = "corrupted btree";
	for (bne = write_block(b);
	     bset_byte_offset(b, bne) < btree_bytes(c);
	     bne = (void *) bne + block_bytes(c))
		if (bne->keys.seq == b->data->keys.seq)
			goto err;

	sorted = btree_bounce_alloc(c, ilog2(btree_pages(c)), &used_mempool);
	sorted->keys.u64s = 0;

	b->keys.nr = btree_node_is_extents(b)
		? bch_extent_sort_fix_overlapping(c, &sorted->keys, &b->keys, iter)
		: bch_key_sort_fix_overlapping(&sorted->keys, &b->keys, iter);

	u64s = le16_to_cpu(sorted->keys.u64s);
	*sorted = *b->data;
	sorted->keys.u64s = cpu_to_le16(u64s);
	swap(sorted, b->data);
	b->keys.set->data = &b->data->keys;
	b->keys.nsets = 1;

	BUG_ON(b->keys.nr.live_u64s != u64s);

	btree_bounce_free(c, ilog2(btree_pages(c)), used_mempool, sorted);

	bch_bset_build_aux_tree(&b->keys, b->keys.set, false);

	btree_node_reset_sib_u64s(b);

	err = "short btree key";
	if (b->keys.set[0].size &&
	    bkey_cmp_packed(&b->keys.format, &b->key.k,
			    &b->keys.set[0].end) < 0)
		goto err;

out:
	mempool_free(iter, &c->fill_iter);
	return;
err:
	set_btree_node_read_error(b);
	btree_node_error(b, c, ptr, "%s", err);
	goto out;
}

static void btree_node_read_endio(struct bio *bio)
{
	closure_put(bio->bi_private);
}

void bch_btree_node_read(struct cache_set *c, struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bio *bio;
	struct extent_pick_ptr pick;

	trace_bcache_btree_read(c, b);

	closure_init_stack(&cl);

	pick = bch_btree_pick_ptr(c, b);
	if (cache_set_fatal_err_on(!pick.ca, c,
				   "no cache device for btree node")) {
		set_btree_node_read_error(b);
		return;
	}

	bio = bio_alloc_bioset(GFP_NOIO, btree_pages(c), &c->btree_read_bio);
	bio->bi_bdev		= pick.ca->disk_sb.bdev;
	bio->bi_iter.bi_sector	= pick.ptr.offset;
	bio->bi_iter.bi_size	= btree_bytes(c);
	bio->bi_end_io		= btree_node_read_endio;
	bio->bi_private		= &cl;
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_META|READ_SYNC);

	bch_bio_map(bio, b->data);

	closure_get(&cl);
	bch_generic_make_request(bio, c);
	closure_sync(&cl);

	if (cache_fatal_io_err_on(bio->bi_error,
				  pick.ca, "IO error reading bucket %zu",
				  PTR_BUCKET_NR(pick.ca, &pick.ptr)) ||
	    bch_meta_read_fault("btree")) {
		set_btree_node_read_error(b);
		goto out;
	}

	bch_btree_node_read_done(c, b, pick.ca, &pick.ptr);
	bch_time_stats_update(&c->btree_read_time, start_time);
out:
	bio_put(bio);
	percpu_ref_put(&pick.ca->ref);
}

int bch_btree_root_read(struct cache_set *c, enum btree_id id,
			const struct bkey_i *k, unsigned level)
{
	struct closure cl;
	struct btree *b;
	int ret;

	closure_init_stack(&cl);

	do {
		ret = mca_cannibalize_lock(c, &cl);
		closure_sync(&cl);
	} while (ret);

	b = mca_alloc(c);
	mca_cannibalize_unlock(c);

	BUG_ON(IS_ERR(b));

	bkey_copy(&b->key, k);
	BUG_ON(mca_hash_insert(c, b, level, id));

	bch_btree_node_read(c, b);
	six_unlock_write(&b->lock);

	if (btree_node_read_error(b)) {
		six_unlock_intent(&b->lock);
		return -EIO;
	}

	bch_btree_set_root_initial(c, b, NULL);
	six_unlock_intent(&b->lock);

	return 0;
}

void bch_btree_complete_write(struct cache_set *c, struct btree *b,
			      struct btree_write *w)
{
	bch_journal_pin_drop(&c->journal, &w->journal);
	closure_wake_up(&w->wait);
}

static void btree_node_write_done(struct cache_set *c, struct btree *b)
{
	struct btree_write *w = btree_prev_write(b);

	/*
	 * Before calling bch_btree_complete_write() - if the write errored, we
	 * have to halt new journal writes before they see this btree node
	 * write as completed:
	 */
	if (btree_node_write_error(b))
		bch_journal_halt(&c->journal);

	bch_btree_complete_write(c, b, w);
	btree_node_io_unlock(b);
}

static void btree_node_write_endio(struct bio *bio)
{
	struct btree *b = bio->bi_private;
	struct bch_write_bio *wbio = to_wbio(bio);
	struct cache_set *c	= wbio->c;
	struct bio *orig	= wbio->split ? wbio->orig : NULL;
	struct closure *cl	= !wbio->split ? wbio->cl : NULL;
	struct cache *ca	= wbio->ca;

	if (cache_fatal_io_err_on(bio->bi_error, ca, "btree write") ||
	    bch_meta_write_fault("btree"))
		set_btree_node_write_error(b);

	if (wbio->bounce)
		bch_bio_free_pages_pool(c, bio);

	if (wbio->put_bio)
		bio_put(bio);

	if (orig) {
		bio_endio(orig);
	} else {
		btree_node_write_done(c, b);
		if (cl)
			closure_put(cl);
	}

	if (ca)
		percpu_ref_put(&ca->ref);
}

void __bch_btree_node_write(struct cache_set *c, struct btree *b,
			    struct closure *parent,
			    int idx_to_write)
{
	struct bio *bio;
	struct bch_write_bio *wbio;
	struct bset *i;
	BKEY_PADDED(key) k;
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct cache *ca;
	size_t sectors_to_write;
	void *data;

	/*
	 * We may only have a read lock on the btree node - the dirty bit is our
	 * "lock" against racing with other threads that may be trying to start
	 * a write, we do a write iff we clear the dirty bit. Since setting the
	 * dirty bit requires a write lock, we can't race with other threads
	 * redirtying it:
	 */
	if (!test_and_clear_bit(BTREE_NODE_dirty, &b->flags))
		return;

	btree_node_io_lock(b);

	BUG_ON(!list_empty(&b->write_blocked));
#if 0
	/*
	 * This is an optimization for when journal flushing races with the
	 * btree node being written for some other reason, and the write the
	 * journal wanted to flush has already happened - in that case we'd
	 * prefer not to write a mostly empty bset. It seemed to be buggy,
	 * though:
	 */
	if (idx_to_write != -1 &&
	    idx_to_write != btree_node_write_idx(b)) {
		btree_node_io_unlock(b);
		return;
	}
#endif
	trace_bcache_btree_write(c, b);

	i = btree_bset_last(b);
	BUG_ON(b->written >= c->sb.btree_node_size);
	BUG_ON(b->written && !i->u64s);
	BUG_ON(btree_bset_first(b)->seq != i->seq);
	BUG_ON(BSET_BIG_ENDIAN(i) != CPU_BIG_ENDIAN);

	change_bit(BTREE_NODE_write_idx, &b->flags);

	i->version	= cpu_to_le16(BCACHE_BSET_VERSION);

	SET_BSET_CSUM_TYPE(i, c->opts.metadata_checksum);

	if (!b->written) {
		BUG_ON(le64_to_cpu(b->data->magic) != bset_magic(&c->disk_sb));

		b->data->format	= b->keys.format;
		data		= b->data;
		b->data->csum	= cpu_to_le64(btree_csum_set(b, b->data));
		sectors_to_write = __set_blocks(b->data,
						le16_to_cpu(b->data->keys.u64s),
						block_bytes(c)) << c->block_bits;

	} else {
		struct btree_node_entry *bne = write_block(b);

		data		= bne;
		bne->csum	= cpu_to_le64(btree_csum_set(b, bne));
		sectors_to_write = __set_blocks(bne,
						le16_to_cpu(bne->keys.u64s),
						block_bytes(c)) << c->block_bits;
	}

	BUG_ON(b->written + sectors_to_write > c->sb.btree_node_size);

	/*
	 * We handle btree write errors by immediately halting the journal -
	 * after we've done that, we can't issue any subsequent btree writes
	 * because they might have pointers to new nodes that failed to write.
	 *
	 * Furthermore, there's no point in doing any more btree writes because
	 * with the journal stopped, we're never going to update the journal to
	 * reflect that those writes were done and the data flushed from the
	 * journal:
	 *
	 * Make sure to update b->written so bch_btree_init_next() doesn't
	 * break:
	 */
	if (bch_journal_error(&c->journal)) {
		set_btree_node_write_error(b);
		b->written += sectors_to_write;

		btree_node_write_done(c, b);
		return;
	}

	bio = bio_alloc_bioset(GFP_NOIO, btree_pages(c), &c->bio_write);

	wbio			= to_wbio(bio);
	wbio->cl		= parent;
	wbio->bounce		= true;
	wbio->put_bio		= true;
	bio->bi_end_io		= btree_node_write_endio;
	bio->bi_private		= b;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_META|WRITE_SYNC|REQ_FUA);

	if (parent)
		closure_get(parent);

	bch_bio_alloc_pages_pool(c, bio, sectors_to_write << 9);
	memcpy_to_bio(bio, bio->bi_iter, data);

	/*
	 * If we're appending to a leaf node, we don't technically need FUA -
	 * this write just needs to be persisted before the next journal write,
	 * which will be marked FLUSH|FUA.
	 *
	 * Similarly if we're writing a new btree root - the pointer is going to
	 * be in the next journal entry.
	 *
	 * But if we're writing a new btree node (that isn't a root) or
	 * appending to a non leaf btree node, we need either FUA or a flush
	 * when we write the parent with the new pointer. FUA is cheaper than a
	 * flush, and writes appending to leaf nodes aren't blocking anything so
	 * just make all btree node writes FUA to keep things sane.
	 */

	bkey_copy(&k.key, &b->key);
	e = bkey_i_to_s_extent(&k.key);

	extent_for_each_ptr(e, ptr)
		ptr->offset += b->written;

	rcu_read_lock();
	extent_for_each_online_device(c, e, ptr, ca)
		atomic64_add(sectors_to_write, &ca->btree_sectors_written);
	rcu_read_unlock();

	b->written += sectors_to_write;

	bch_submit_wbio_replicas(wbio, c, &k.key, true);
}

void bch_btree_node_write(struct cache_set *c, struct btree *b,
			  struct closure *parent,
			  enum six_lock_type lock_type_held,
			  struct btree_iter *iter,
			  int idx_to_write)
{
	BUG_ON(lock_type_held == SIX_LOCK_write);

	__bch_btree_node_write(c, b, parent, -1);

	if (lock_type_held == SIX_LOCK_intent ||
	    six_trylock_convert(&b->lock, SIX_LOCK_read,
				SIX_LOCK_intent)) {
		bch_btree_init_next(c, b, iter);

		if (lock_type_held == SIX_LOCK_read)
			six_lock_downgrade(&b->lock);
	}
}

static void bch_btree_node_write_dirty(struct cache_set *c, struct btree *b,
				       struct closure *parent)
{
	six_lock_read(&b->lock);
	BUG_ON(b->level);

	bch_btree_node_write(c, b, parent, SIX_LOCK_read, NULL, -1);
	six_unlock_read(&b->lock);
}

/* buffer up 4k before writing out a bset */
#define BTREE_WRITE_SET_BUFFER         (4 << 10)

/*
 * Write leaf nodes if the unwritten bset is getting too big:
 */
void bch_btree_node_write_lazy(struct cache_set *c, struct btree *b,
			       struct btree_iter *iter)
{
	struct btree_node_entry *bne =
		container_of(btree_bset_last(b),
			     struct btree_node_entry, keys);
	unsigned long bytes = __set_bytes(bne, le16_to_cpu(bne->keys.u64s));

	if ((max(round_up(bytes, block_bytes(iter->c)),
		 PAGE_SIZE) - bytes < 48 ||
	     bytes > BTREE_WRITE_SET_BUFFER) &&
	    !btree_node_write_in_flight(b))
		bch_btree_node_write(c, b, NULL, SIX_LOCK_intent, iter, -1);
}

/*
 * Write all dirty btree nodes to disk, including roots
 */
void bch_btree_flush(struct cache_set *c)
{
	struct closure cl;
	struct btree *b;
	struct bucket_table *tbl;
	struct rhash_head *pos;
	bool dropped_lock;
	unsigned i;

	closure_init_stack(&cl);

	rcu_read_lock();

	do {
		dropped_lock = false;
		i = 0;
restart:
		tbl = rht_dereference_rcu(c->btree_cache_table.tbl,
					  &c->btree_cache_table);

		for (; i < tbl->size; i++)
			rht_for_each_entry_rcu(b, pos, tbl, i, hash)
				/*
				 * XXX - locking for b->level, when called from
				 * bch_journal_move()
				 */
				if (!b->level && btree_node_dirty(b)) {
					rcu_read_unlock();
					bch_btree_node_write_dirty(c, b, &cl);
					dropped_lock = true;
					rcu_read_lock();
					goto restart;
				}
	} while (dropped_lock);

	rcu_read_unlock();

	closure_sync(&cl);
}

/**
 * bch_btree_node_flush_journal - flush any journal entries that contain keys
 * from this node
 *
 * The bset's journal sequence number is used for preserving ordering of index
 * updates across unclean shutdowns - it's used to ignore bsets newer than the
 * most recent journal entry.
 *
 * But when rewriting btree nodes we compact all the bsets in a btree node - and
 * if we compacted a bset that should be ignored with bsets we do need, that
 * would be bad. So to avoid that, prior to making the new node visible ensure
 * that the journal has been flushed so that all the bsets we compacted should
 * be visible.
 */
void bch_btree_node_flush_journal_entries(struct cache_set *c,
					  struct btree *b,
					  struct closure *cl)
{
	int i = b->keys.nsets;

	/*
	 * Journal sequence numbers in the different bsets will always be in
	 * ascending order, we only need to flush the highest - except that the
	 * most recent bset might not have a journal sequence number yet, so we
	 * need to loop:
	 */
	while (i--) {
		u64 seq = le64_to_cpu(b->keys.set[i].data->journal_seq);

		if (seq) {
			bch_journal_flush_seq_async(&c->journal, seq, cl);
			break;
		}
	}
}

