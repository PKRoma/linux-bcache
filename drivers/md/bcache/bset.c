/*
 * Code for working with individual keys, and sorted sets of keys with in a
 * btree node
 *
 * Copyright 2012 Google, Inc.
 */

#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include "util.h"
#include "bset.h"

#include <asm/unaligned.h>
#include <linux/dynamic_fault.h>
#include <linux/console.h>
#include <linux/random.h>
#include <linux/prefetch.h>

/* hack.. */
#include "alloc_types.h"
#include <trace/events/bcache.h>

struct bset_tree *bch_bkey_to_bset(struct btree_keys *b, struct bkey_packed *k)
{
	struct bset_tree *t;

	for_each_bset(b, t)
		if (k >= t->data->start &&
		    k < bset_bkey_last(t->data))
			return t;

	BUG();
}

/*
 * There are never duplicate live keys in the btree - but including keys that
 * have been flagged as deleted (and will be cleaned up later) we _will_ see
 * duplicates.
 *
 * Thus the sort order is: usual key comparison first, but for keys that compare
 * equal the deleted key(s) come first, and the (at most one) live version comes
 * last.
 *
 * The main reason for this is insertion: to handle overwrites, we first iterate
 * over keys that compare equal to our insert key, and then insert immediately
 * prior to the first key greater than the key we're inserting - our insert
 * position will be after all keys that compare equal to our insert key, which
 * by the time we actually do the insert will all be deleted.
 */

void bch_dump_bset(struct btree_keys *b, struct bset *i, unsigned set)
{
	struct bkey_packed *_k, *_n;
	struct bkey k, n;
	char buf[120];

	if (!i->u64s)
		return;

	for (_k = i->start, k = bkey_unpack_key(b, _k);
	     _k < bset_bkey_last(i);
	     _k = _n, k = n) {
		_n = bkey_next(_k);

		bch_bkey_to_text(buf, sizeof(buf), &k);
		printk(KERN_ERR "block %u key %zi/%u: %s\n", set,
		       _k->_data - i->_data, i->u64s, buf);

		if (_n == bset_bkey_last(i))
			continue;

		n = bkey_unpack_key(b, _n);

		if (bkey_cmp(bkey_start_pos(&n), k.p) < 0) {
			printk(KERN_ERR "Key skipped backwards\n");
			continue;
		}

		/*
		 * Weird check for duplicate non extent keys: extents are
		 * deleted iff they have 0 size, so if it has zero size and it's
		 * not deleted these aren't extents:
		 */
		if (((!k.size && !bkey_deleted(&k)) ||
		     (!n.size && !bkey_deleted(&n))) &&
		    !bkey_deleted(&k) &&
		    !bkey_cmp(n.p, k.p))
			printk(KERN_ERR "Duplicate keys\n");
	}
}

void bch_dump_btree_node(struct btree_keys *b)
{
	struct bset_tree *t;

	console_lock();
	for_each_bset(b, t)
		bch_dump_bset(b, t->data, t - b->set);
	console_unlock();
}

void bch_dump_btree_node_iter(struct btree_keys *b,
			      struct btree_node_iter *iter)
{
	struct btree_node_iter_set *set;

	printk(KERN_ERR "btree node iter with %u sets:\n", b->nsets);

	btree_node_iter_for_each(iter, set) {
		struct bkey_packed *k = __btree_node_offset_to_key(b, set->k);
		struct bset_tree *t = bch_bkey_to_bset(b, k);
		struct bkey uk = bkey_unpack_key(b, k);
		char buf[100];

		bch_bkey_to_text(buf, sizeof(buf), &uk);
		printk(KERN_ERR "set %zu key %zi/%u: %s\n", t - b->set,
		       k->_data - t->data->_data, t->data->u64s, buf);
	}
}

#ifdef CONFIG_BCACHE_DEBUG

static bool keys_out_of_order(struct btree_keys *b,
			      const struct bkey_packed *prev,
			      const struct bkey_packed *next,
			      bool is_extents)
{
	struct bkey nextu = bkey_unpack_key(b, next);

	return bkey_cmp_left_packed(b, prev, bkey_start_pos(&nextu)) > 0 ||
		((is_extents
		  ? !bkey_deleted(next)
		  : !bkey_deleted(prev)) &&
		 !bkey_cmp_packed(b, prev, next));
}

void __bch_verify_btree_nr_keys(struct btree_keys *b)
{
	struct bset_tree *t;
	struct bkey_packed *k;
	struct btree_nr_keys nr = { 0 };

	for_each_bset(b, t)
		for (k = t->data->start;
		     k != bset_bkey_last(t->data);
		     k = bkey_next(k))
			if (!bkey_whiteout(k))
				btree_keys_account_key_add(&nr, t - b->set, k);

	BUG_ON(memcmp(&nr, &b->nr, sizeof(nr)));
}

static void bch_btree_node_iter_next_check(struct btree_node_iter *iter,
					   struct btree_keys *b,
					   struct bkey_packed *k)
{
	const struct bkey_packed *n = bch_btree_node_iter_peek_all(iter, b);

	bkey_unpack_key(b, k);

	if (n &&
	    keys_out_of_order(b, k, n, iter->is_extents)) {
		struct bkey ku = bkey_unpack_key(b, k);
		struct bkey nu = bkey_unpack_key(b, n);
		char buf1[80], buf2[80];

		bch_dump_btree_node(b);
		bch_bkey_to_text(buf1, sizeof(buf1), &ku);
		bch_bkey_to_text(buf2, sizeof(buf2), &nu);
		panic("out of order/overlapping:\n%s\n%s\n", buf1, buf2);
	}
}

void bch_btree_node_iter_verify(struct btree_node_iter *iter,
				struct btree_keys *b)
{
	struct btree_node_iter_set *set;
	struct bset_tree *t;
	struct bkey_packed *k, *first;

	BUG_ON(iter->used > MAX_BSETS);

	if (!iter->used)
		return;

	btree_node_iter_for_each(iter, set) {
		k = __btree_node_offset_to_key(b, set->k);
		t = bch_bkey_to_bset(b, k);

		BUG_ON(__btree_node_offset_to_key(b, set->end) !=
		       bset_bkey_last(t->data));

		BUG_ON(set + 1 < iter->data + iter->used &&
		       btree_node_iter_cmp(iter, b, set[0], set[1]) > 0);
	}

	first = __btree_node_offset_to_key(b, iter->data[0].k);

	for_each_bset(b, t)
		if (bch_btree_node_iter_bset_pos(iter, b, t->data) ==
		    bset_bkey_last(t->data) &&
		    (k = bkey_prev_all(t, bset_bkey_last(t->data))))
			BUG_ON(__btree_node_iter_cmp(iter->is_extents, b,
						     k, first) > 0);
}

void bch_verify_key_order(struct btree_keys *b,
			  struct btree_node_iter *iter,
			  struct bkey_packed *where)
{
	struct bset_tree *t = bch_bkey_to_bset(b, where);
	struct bkey_packed *k, *prev;
	struct bkey uk, uw = bkey_unpack_key(b, where);

	k = bkey_prev_all(t, where);
	if (k &&
	    keys_out_of_order(b, k, where, iter->is_extents)) {
		char buf1[100], buf2[100];

		bch_dump_btree_node(b);
		uk = bkey_unpack_key(b, k);
		bch_bkey_to_text(buf1, sizeof(buf1), &uk);
		bch_bkey_to_text(buf2, sizeof(buf2), &uw);
		panic("out of order with prev:\n%s\n%s\n",
		      buf1, buf2);
	}

	k = bkey_next(where);
	BUG_ON(k != bset_bkey_last(t->data) &&
	       keys_out_of_order(b, where, k, iter->is_extents));

	for_each_bset(b, t) {
		if (!t->data->u64s)
			continue;

		if (where >= t->data->start &&
		    where < bset_bkey_last(t->data))
			continue;

		k = bch_btree_node_iter_bset_pos(iter, b, t->data);

		if (k == bset_bkey_last(t->data))
			k = bkey_prev_all(t, k);

		while (bkey_cmp_left_packed(b, k, bkey_start_pos(&uw)) > 0 &&
		       (prev = bkey_prev_all(t, k)))
			k = prev;

		for (;
		     k != bset_bkey_last(t->data);
		     k = bkey_next(k)) {
			uk = bkey_unpack_key(b, k);

			if (iter->is_extents) {
				BUG_ON(!(bkey_cmp(uw.p, bkey_start_pos(&uk)) <= 0 ||
					 bkey_cmp(uk.p, bkey_start_pos(&uw)) <= 0));
			} else {
				BUG_ON(!bkey_cmp(uw.p, uk.p) &&
				       !bkey_deleted(&uk));
			}

			if (bkey_cmp(uw.p, bkey_start_pos(&uk)) <= 0)
				break;
		}
	}
}

#else

static void bch_btree_node_iter_next_check(struct btree_node_iter *iter,
					   struct btree_keys *b,
					   struct bkey_packed *k) {}

#endif

/* Auxiliary search trees */

/* 32 bits total: */
#define BKEY_MID_BITS		8U
#define BKEY_EXPONENT_BITS	8U
#define BKEY_MANTISSA_BITS	(32 - BKEY_MID_BITS - BKEY_EXPONENT_BITS)
#define BKEY_MANTISSA_MASK	((1 << BKEY_MANTISSA_BITS) - 1)

#define BFLOAT_EXPONENT_MAX	((1 << BKEY_EXPONENT_BITS) - 1)

#define BFLOAT_FAILED_UNPACKED	(BFLOAT_EXPONENT_MAX - 0)
#define BFLOAT_FAILED_PREV	(BFLOAT_EXPONENT_MAX - 1)
#define BFLOAT_FAILED_OVERFLOW	(BFLOAT_EXPONENT_MAX - 2)
#define BFLOAT_FAILED		(BFLOAT_EXPONENT_MAX - 2)

#define KEY_WORDS		BITS_TO_LONGS(1 << BKEY_EXPONENT_BITS)

struct bkey_float {
	unsigned	exponent:BKEY_EXPONENT_BITS;
	unsigned	m:BKEY_MID_BITS;
	unsigned	mantissa:BKEY_MANTISSA_BITS;
} __packed;

/*
 * BSET_CACHELINE was originally intended to match the hardware cacheline size -
 * it used to be 64, but I realized the lookup code would touch slightly less
 * memory if it was 128.
 *
 * It definites the number of bytes (in struct bset) per struct bkey_float in
 * the auxiliar search tree - when we're done searching the bset_float tree we
 * have this many bytes left that we do a linear search over.
 *
 * Since (after level 5) every level of the bset_tree is on a new cacheline,
 * we're touching one fewer cacheline in the bset tree in exchange for one more
 * cacheline in the linear search - but the linear search might stop before it
 * gets to the second cacheline.
 */

#define BSET_CACHELINE		128

/* Space required for the btree node keys */
static inline size_t btree_keys_bytes(struct btree_keys *b)
{
	return PAGE_SIZE << b->page_order;
}

static inline size_t btree_keys_cachelines(struct btree_keys *b)
{
	return btree_keys_bytes(b) / BSET_CACHELINE;
}

/* Space required for the auxiliary search trees */
static inline size_t bset_tree_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(struct bkey_float);
}

/* Space required for the prev pointers */
static inline size_t bset_prev_bytes(struct btree_keys *b)
{
	return btree_keys_cachelines(b) * sizeof(u8);
}

/* Memory allocation */

void bch_btree_keys_free(struct btree_keys *b)
{
	struct bset_tree *t = b->set;

	vfree(b->unpack_fn);

	if (bset_prev_bytes(b) < PAGE_SIZE)
		kfree(t->prev);
	else
		free_pages((unsigned long) t->prev,
			   get_order(bset_prev_bytes(b)));

	if (bset_tree_bytes(b) < PAGE_SIZE)
		kfree(t->tree);
	else
		free_pages((unsigned long) t->tree,
			   get_order(bset_tree_bytes(b)));

	t->prev = NULL;
	t->tree = NULL;
}
EXPORT_SYMBOL(bch_btree_keys_free);

int bch_btree_keys_alloc(struct btree_keys *b, unsigned page_order, gfp_t gfp)
{
	struct bset_tree *t = b->set;

	BUG_ON(t->tree || t->prev);

	b->page_order = page_order;

	t->tree = bset_tree_bytes(b) < PAGE_SIZE
		? kmalloc(bset_tree_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_tree_bytes(b)));
	if (!t->tree)
		goto err;

	t->prev = bset_prev_bytes(b) < PAGE_SIZE
		? kmalloc(bset_prev_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_prev_bytes(b)));
	if (!t->prev)
		goto err;

	b->unpack_fn = vmalloc_exec(200);
	if (!b->unpack_fn)
		goto err;

	return 0;
err:
	bch_btree_keys_free(b);
	return -ENOMEM;
}
EXPORT_SYMBOL(bch_btree_keys_alloc);

void bch_btree_keys_init(struct btree_keys *b, bool *expensive_debug_checks)
{
	struct bkey_format_state s;
	unsigned i;

	bch_bkey_format_init(&s);
	b->format = bch_bkey_format_done(&s);

	b->nsets		= 0;
	memset(&b->nr, 0, sizeof(b->nr));
#ifdef CONFIG_BCACHE_DEBUG
	b->expensive_debug_checks = expensive_debug_checks;
#endif
	for (i = 0; i < MAX_BSETS; i++)
		b->set[i].data = NULL;

	bch_bset_set_no_aux_tree(b, b->set);
}
EXPORT_SYMBOL(bch_btree_keys_init);

/* Binary tree stuff for auxiliary search trees */

static unsigned inorder_next(unsigned j, unsigned size)
{
	if (j * 2 + 1 < size) {
		j = j * 2 + 1;

		j <<= fls(size) - fls(j);
		j >>= j >= size;
	} else
		j >>= ffz(j) + 1;

	return j;
}

static unsigned inorder_prev(unsigned j, unsigned size)
{
	if (j * 2 < size) {
		unsigned shift;

		j = j * 2;

		shift = fls(size) - fls(j);
		j += 1;
		j <<= shift;
		j -= 1;
		j >>= j >= size;
	} else
		j >>= ffs(j);

	return j;
}

/* I have no idea why this code works... and I'm the one who wrote it
 *
 * However, I do know what it does:
 * Given a binary tree constructed in an array (i.e. how you normally implement
 * a heap), it converts a node in the tree - referenced by array index - to the
 * index it would have if you did an inorder traversal.
 *
 * Also tested for every j, size up to size somewhere around 6 million.
 *
 * The binary tree starts at array index 1, not 0
 * extra is a function of size:
 *   extra = (size - rounddown_pow_of_two(size - 1)) << 1;
 */
static inline unsigned __to_inorder(unsigned j, unsigned size, unsigned extra)
{
	unsigned b = fls(j);
	unsigned shift = fls(size - 1) - b;

	j  ^= 1U << (b - 1);
	j <<= 1;
	j  |= 1;
	j <<= shift;

	/* sign bit trick: */
#if 0
	if (j > extra)
		j -= (j - extra) >> 1;
#else
	j -= ((j - extra) >> 1) & (((int) (extra - j)) >> 31);
#endif

	return j;
}

static inline unsigned to_inorder(unsigned j, struct bset_tree *t)
{
	return __to_inorder(j, t->size, t->extra);
}

static unsigned __inorder_to_tree(unsigned j, unsigned size, unsigned extra)
{
	unsigned shift;

	if (j > extra)
		j += j - extra;

	shift = ffs(j);

	j >>= shift;
	j  |= roundup_pow_of_two(size) >> shift;

	return j;
}

static unsigned inorder_to_tree(unsigned j, struct bset_tree *t)
{
	return __inorder_to_tree(j, t->size, t->extra);
}

#if 0
void inorder_test(void)
{
	unsigned long done = 0;
	ktime_t start = ktime_get();

	for (unsigned size = 2;
	     size < 65536000;
	     size++) {
		unsigned extra = (size - rounddown_pow_of_two(size - 1)) << 1;
		unsigned i = 1, j = rounddown_pow_of_two(size - 1);

		if (!(size % 4096))
			printk(KERN_NOTICE "loop %u, %llu per us\n", size,
			       done / ktime_us_delta(ktime_get(), start));

		while (1) {
			if (__inorder_to_tree(i, size, extra) != j)
				panic("size %10u j %10u i %10u", size, j, i);

			if (__to_inorder(j, size, extra) != i)
				panic("size %10u j %10u i %10u", size, j, i);

			if (j == rounddown_pow_of_two(size) - 1)
				break;

			BUG_ON(inorder_prev(inorder_next(j, size), size) != j);

			j = inorder_next(j, size);
			i++;
		}

		done += size - 1;
	}
}
#endif

/*
 * Cacheline/offset <-> bkey pointer arithmetic:
 *
 * t->tree is a binary search tree in an array; each node corresponds to a key
 * in one cacheline in t->set (BSET_CACHELINE bytes).
 *
 * This means we don't have to store the full index of the key that a node in
 * the binary tree points to; to_inorder() gives us the cacheline, and then
 * bkey_float->m gives us the offset within that cacheline, in units of 8 bytes.
 *
 * cacheline_to_bkey() and friends abstract out all the pointer arithmetic to
 * make this work.
 *
 * To construct the bfloat for an arbitrary key we need to know what the key
 * immediately preceding it is: we have to check if the two keys differ in the
 * bits we're going to store in bkey_float->mantissa. t->prev[j] stores the size
 * of the previous key so we can walk backwards to it from t->tree[j]'s key.
 */

static struct bkey_packed *cacheline_to_bkey(struct bset_tree *t,
					     unsigned cacheline,
					     int offset)
{
	return ((void *) t->data) + cacheline * BSET_CACHELINE + offset * 8;
}

static unsigned bkey_to_cacheline(struct bset_tree *t, struct bkey_packed *k)
{
	return ((void *) k - (void *) t->data) / BSET_CACHELINE;
}

static ssize_t __bkey_to_cacheline_offset(struct bset_tree *t,
					  unsigned cacheline,
					  struct bkey_packed *k)
{
	return (u64 *) k - (u64 *) cacheline_to_bkey(t, cacheline, 0);
}

static unsigned bkey_to_cacheline_offset(struct bset_tree *t,
					 unsigned cacheline,
					 struct bkey_packed *k)
{
	size_t m = __bkey_to_cacheline_offset(t, cacheline, k);

	BUG_ON(m > (1U << BKEY_MID_BITS) - 1);
	return m;
}

static struct bkey_packed *tree_to_bkey(struct bset_tree *t, unsigned j)
{
	return cacheline_to_bkey(t, to_inorder(j, t), t->tree[j].m);
}

static struct bkey_packed *tree_to_prev_bkey(struct bset_tree *t, unsigned j)
{
	return (void *) (((u64 *) tree_to_bkey(t, j)) - t->prev[j]);
}

/*
 * For the write set - the one we're currently inserting keys into - we don't
 * maintain a full search tree, we just keep a simple lookup table in t->prev.
 */
static struct bkey_packed *table_to_bkey(struct bset_tree *t,
					 unsigned cacheline)
{
	return cacheline_to_bkey(t, cacheline, t->prev[cacheline]);
}

static inline unsigned bfloat_mantissa(const struct bkey_packed *k,
				       const struct bkey_float *f)
{
	u64 v;

	EBUG_ON(!bkey_packed(k));

	v = get_unaligned((u64 *) (((u8 *) k->_data) + (f->exponent >> 3)));

	/*
	 * In little endian, we're shifting off low bits (and then the bits we
	 * want are at the low end), in big endian we're shifting off high bits
	 * (and then the bits we want are at the high end, so we shift them
	 * back down):
	 */
#ifdef __LITTLE_ENDIAN
	v >>= f->exponent & 7;
#else
	v >>= 64 - BKEY_MANTISSA_BITS - (f->exponent & 7);
#endif
	return v & BKEY_MANTISSA_MASK;
}

static void make_bfloat(const struct btree_keys *b,
			struct bset_tree *t, unsigned j)
{
	struct bkey_float *f = &t->tree[j];
	struct bkey_packed *m = tree_to_bkey(t, j);
	struct bkey_packed *p = tree_to_prev_bkey(t, j);

	struct bkey_packed *l = is_power_of_2(j)
		? t->data->start
		: tree_to_prev_bkey(t, j >> ffs(j));

	struct bkey_packed *r = is_power_of_2(j + 1)
		? bset_bkey_idx(t->data,
				le16_to_cpu(t->data->u64s) - t->end.u64s)
		: tree_to_bkey(t, j >> (ffz(j) + 1));
	int shift, exponent;

	EBUG_ON(m < l || m > r);
	EBUG_ON(bkey_next(p) != m);

	/*
	 * for failed bfloats, the lookup code falls back to comparing against
	 * the original key.
	 */

	if (!bkey_packed(l) || !bkey_packed(r) ||
	    !bkey_packed(p) || !bkey_packed(m)) {
		f->exponent = BFLOAT_FAILED_UNPACKED;
		return;
	}

	/*
	 * The greatest differing bit of l and r is the first bit we must
	 * include in the bfloat mantissa we're creating in order to do
	 * comparisons - that bit always becomes the high bit of
	 * bfloat->mantissa, and thus the exponent we're calculating here is
	 * the position of what will become the low bit in bfloat->mantissa:
	 *
	 * Note that this may be negative - we may be running off the low end
	 * of the key: we handle this later:
	 */
	exponent = (int) bkey_greatest_differing_bit(b, l, r) -
		(BKEY_MANTISSA_BITS - 1);

	/*
	 * Then we calculate the actual shift value, from the start of the key
	 * (k->_data), to get the key bits starting at exponent:
	 */
#ifdef __LITTLE_ENDIAN
	shift = (int) (b->format.key_u64s * 64 - b->nr_key_bits) + exponent;

	EBUG_ON(shift + BKEY_MANTISSA_BITS > b->format.key_u64s * 64);
#else
	shift = high_bit_offset +
		b->nr_key_bits -
		exponent -
		BKEY_MANTISSA_BITS;

	EBUG_ON(shift < KEY_PACKED_BITS_START);
#endif
	EBUG_ON(shift < 0 || shift >= BFLOAT_FAILED);

	f->exponent = shift;
	f->mantissa = bfloat_mantissa(m, f);

	/*
	 * If we've got garbage bits, set them to all 1s - it's legal for the
	 * bfloat to compare larger than the original key, but not smaller:
	 */
	if (exponent < 0)
		f->mantissa |= ~(~0U << -exponent);

	/*
	 * The bfloat must be able to tell its key apart from the previous key -
	 * if its key and the previous key don't differ in the required bits,
	 * flag as failed - unless the keys are actually equal, in which case
	 * we aren't required to return a specific one:
	 */
	if (exponent > 0 &&
	    f->mantissa == bfloat_mantissa(p, f) &&
	    bkey_cmp_packed(b, p, m)) {
		f->exponent = BFLOAT_FAILED_PREV;
		return;
	}

	/*
	 * f->mantissa must compare >= the original key - for transitivity with
	 * the comparison in bset_search_tree. If we're dropping set bits,
	 * increment it:
	 */
	if (exponent > (int) bkey_ffs(b, m)) {
		if (f->mantissa == BKEY_MANTISSA_MASK)
			f->exponent = BFLOAT_FAILED_OVERFLOW;

		f->mantissa++;
	}
}

/* Only valid for the last bset: */
static unsigned bset_tree_capacity(struct btree_keys *b, struct bset_tree *t)
{
	return b->set->tree + btree_keys_cachelines(b) - t->tree;
}

static void bch_bset_lookup_table_add_entries(struct btree_keys *b,
					      struct bset_tree *t)
{
	struct bkey_packed *k;

	BUG_ON(!bset_has_rw_aux_tree(t));
	BUG_ON(t->size > bset_tree_capacity(b, t));

	for (k = table_to_bkey(t, t->size - 1);
	     k != bset_bkey_last(t->data);
	     k = bkey_next(k))
		while (bkey_to_cacheline(t, k) >= t->size) {
			if (t->size == bset_tree_capacity(b, t))
				return;

			t->prev[t->size] = bkey_to_cacheline_offset(t, t->size, k);
			t->size++;
		}
}

static void __build_rw_aux_tree(struct btree_keys *b, struct bset_tree *t)
{
	t->prev[0] = bkey_to_cacheline_offset(t, 0, t->data->start);
	t->size = 1;
	t->extra = BSET_RW_AUX_TREE_VAL;

	bch_bset_lookup_table_add_entries(b, t);
}

static void __build_ro_aux_tree(struct btree_keys *b, struct bset_tree *t)
{
	struct bkey_packed *prev = NULL, *k = t->data->start;
	unsigned j, cacheline = 1;

	t->size = min(bkey_to_cacheline(t, bset_bkey_last(t->data)),
		      bset_tree_capacity(b, t));
retry:
	if (t->size < 2) {
		bch_bset_set_no_aux_tree(b, t);
		return;
	}

	t->extra = (t->size - rounddown_pow_of_two(t->size - 1)) << 1;

	/* First we figure out where the first key in each cacheline is */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size)) {
		while (bkey_to_cacheline(t, k) < cacheline)
			prev = k, k = bkey_next(k);

		if (k >= bset_bkey_last(t->data)) {
			t->size--;
			goto retry;
		}

		t->prev[j] = prev->u64s;
		t->tree[j].m = bkey_to_cacheline_offset(t, cacheline++, k);

		BUG_ON(tree_to_prev_bkey(t, j) != prev);
		BUG_ON(tree_to_bkey(t, j) != k);
	}

	while (bkey_next(k) != bset_bkey_last(t->data))
		k = bkey_next(k);

	t->end = *k;

	/* Then we build the tree */
	for (j = inorder_next(0, t->size);
	     j;
	     j = inorder_next(j, t->size))
		make_bfloat(b, t, j);
}

static void bset_alloc_tree(struct btree_keys *b, struct bset_tree *t)
{
	struct bset_tree *i;

	for (i = b->set; i != t; i++)
		BUG_ON(bset_has_rw_aux_tree(i));

	if (t != b->set) {
		unsigned j = round_up(t[-1].size,
				      64 / sizeof(struct bkey_float));

		t->tree = t[-1].tree + j;
		t->prev = t[-1].prev + j;

		BUG_ON(t->tree > b->set->tree + btree_keys_cachelines(b));
	}

	bch_bset_set_no_aux_tree(b, t);
}

void bch_bset_build_aux_tree(struct btree_keys *b, struct bset_tree *t,
			     bool writeable)
{
	if (writeable
	    ? bset_has_rw_aux_tree(t)
	    : bset_has_ro_aux_tree(t))
		return;

	bset_alloc_tree(b, t);

	if (!bset_tree_capacity(b, t)) {
		bch_bset_set_no_aux_tree(b, t);
		return;
	}

	if (writeable)
		__build_rw_aux_tree(b, t);
	else
		__build_ro_aux_tree(b, t);

}

void bch_bset_init_first(struct btree_keys *b, struct bset *i)
{
	struct bset_tree *t;

	BUG_ON(b->nsets);

	t = &b->set[b->nsets++];
	t->data = i;
	memset(i, 0, sizeof(*i));
	get_random_bytes(&i->seq, sizeof(i->seq));
	SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);
}

void bch_bset_init_next(struct btree_keys *b, struct bset *i)
{
	struct bset_tree *t;

	BUG_ON(b->nsets >= MAX_BSETS);

	t = &b->set[b->nsets++];
	t->data = i;
	memset(i, 0, sizeof(*i));
	i->seq = b->set->data->seq;
	SET_BSET_BIG_ENDIAN(i, CPU_BIG_ENDIAN);
}

static struct bkey_packed *__bkey_prev(struct bset_tree *t, struct bkey_packed *k)
{
	struct bkey_packed *p;
	int j;

	EBUG_ON(k < t->data->start || k > bset_bkey_last(t->data));

	if (k == t->data->start)
		return NULL;

	j = min(bkey_to_cacheline(t, k), t->size);

	do {
		if (--j <= 0) {
			p = t->data->start;
			break;

		}

		switch (bset_aux_tree_type(t)) {
		case BSET_NO_AUX_TREE:
			p = t->data->start;
			break;
		case BSET_RO_AUX_TREE:
			p = tree_to_bkey(t, inorder_to_tree(j, t));
			break;
		case BSET_RW_AUX_TREE:
			p = table_to_bkey(t, j);
			break;
		}
	} while (p >= k);

	return p;
}

struct bkey_packed *bkey_prev_all(struct bset_tree *t, struct bkey_packed *k)
{
	struct bkey_packed *p;

	p = __bkey_prev(t, k);
	if (!p)
		return NULL;

	while (bkey_next(p) != k)
		p = bkey_next(p);

	return p;
}

struct bkey_packed *bkey_prev(struct bset_tree *t, struct bkey_packed *k)
{
	while (1) {
		struct bkey_packed *p, *i, *ret = NULL;

		p = __bkey_prev(t, k);
		if (!p)
			return NULL;

		for (i = p; i != k; i = bkey_next(i))
			if (!bkey_deleted(i))
				ret = i;

		if (ret)
			return ret;

		k = p;
	}
}

/* Insert */

/**
 * bch_bset_fix_invalidated_key() - given an existing  key @k that has been
 * modified, fix any auxiliary search tree by remaking all the nodes in the
 * auxiliary search tree that @k corresponds to
 */
void bch_bset_fix_invalidated_key(struct btree_keys *b, struct bset_tree *t,
				  struct bkey_packed *k)
{
	unsigned inorder, j = 1;

	if (bset_aux_tree_type(t) != BSET_RO_AUX_TREE)
		return;

	inorder = bkey_to_cacheline(t, k);

	if (k == t->data->start)
		for (j = 1; j < t->size; j = j * 2)
			make_bfloat(b, t, j);

	if (bkey_next(k) == bset_bkey_last(t->data)) {
		t->end = *k;

		for (j = 1; j < t->size; j = j * 2 + 1)
			make_bfloat(b, t, j);
	}

	j = inorder_to_tree(inorder, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_bkey(t, j)) {
		/* Fix the auxiliary search tree node this key corresponds to */
		make_bfloat(b, t, j);

		/* Children for which this key is the right side boundary */
		for (j = j * 2; j < t->size; j = j * 2 + 1)
			make_bfloat(b, t, j);
	}

	j = inorder_to_tree(inorder + 1, t);

	if (j &&
	    j < t->size &&
	    k == tree_to_prev_bkey(t, j)) {
		make_bfloat(b, t, j);

		/* Children for which this key is the left side boundary */
		for (j = j * 2 + 1; j < t->size; j = j * 2)
			make_bfloat(b, t, j);
	}
}
EXPORT_SYMBOL(bch_bset_fix_invalidated_key);

static void bch_bset_fix_lookup_table(struct btree_keys *b,
				      struct bset_tree *t,
				      struct bkey_packed *where,
				      unsigned clobber_u64s,
				      unsigned new_u64s)
{
	struct bkey_packed *k;
	int shift = new_u64s - clobber_u64s;
	unsigned j;

	BUG_ON(bset_has_ro_aux_tree(t));

	if (!bset_has_rw_aux_tree(t))
		return;

	/* Did we just truncate? */
	if (where == bset_bkey_last(t->data)) {
		while (t->size > 1 &&
		       table_to_bkey(t, t->size - 1) >= bset_bkey_last(t->data))
			t->size--;
		return;
	}

	/* Find first entry in the lookup table strictly greater than where: */
	j = bkey_to_cacheline(t, where);
	while (j < t->size && table_to_bkey(t, j) <= where)
		j++;

	BUG_ON(!j);

	/* Adjust all the lookup table entries, and find a new key for any that
	 * have gotten too big
	 */
	for (; j < t->size; j++) {
		/* Avoid overflow - might temporarily be larger than a u8 */
		ssize_t new_offset;

		if (table_to_bkey(t, j) <
		    (struct bkey_packed *) ((u64 *) where + clobber_u64s))
			new_offset = __bkey_to_cacheline_offset(t, j, where);
		else
			new_offset = (int) t->prev[j] + shift;

		if (new_offset > 7) {
			k = table_to_bkey(t, j - 1);
			new_offset = __bkey_to_cacheline_offset(t, j, k);
		}

		while (new_offset < 0) {
			k = bkey_next(cacheline_to_bkey(t, j, new_offset));
			if (k == bset_bkey_last(t->data)) {
				t->size = j;
				return;
			}

			new_offset = __bkey_to_cacheline_offset(t, j, k);
		}

		BUG_ON(new_offset > U8_MAX);
		t->prev[j] = new_offset;
	}

	bch_bset_lookup_table_add_entries(b, t);
}

static void bch_bset_verify_lookup_table(struct btree_keys *b,
					 struct bset_tree *t)
{
	struct bkey_packed *k;
	unsigned j = 0;

	if (!btree_keys_expensive_checks(b))
		return;

	BUG_ON(bset_has_ro_aux_tree(t));

	if (!bset_has_rw_aux_tree(t))
		return;

	BUG_ON(t->size < 1);
	BUG_ON(table_to_bkey(t, 0) != t->data->start);

	if (!t->data->u64s) {
		BUG_ON(t->size != 1);
		return;
	}

	for (k = t->data->start;
	     k != bset_bkey_last(t->data);
	     k = bkey_next(k))
		while (k == table_to_bkey(t, j))
			if (++j == t->size)
				return;

	BUG();
}

void bch_bset_insert(struct btree_keys *b,
		    struct btree_node_iter *iter,
		    struct bkey_packed *where,
		    struct bkey_i *insert,
		    unsigned clobber_u64s)
{
	struct bkey_format *f = &b->format;
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = t->data;
	struct bkey_packed packed, *src = bkey_to_packed(insert);

	if (bkey_pack_key(&packed, &insert->k, f))
		src = &packed;

	if (!bkey_whiteout(&insert->k))
		btree_keys_account_key_add(&b->nr, t - b->set, src);

	if (src->u64s != clobber_u64s) {
		u64 *src_p = where->_data + clobber_u64s;
		u64 *dst_p = where->_data + src->u64s;

		memmove_u64s(dst_p, src_p, bset_bkey_last(i)->_data - src_p);
		le16_add_cpu(&i->u64s, src->u64s - clobber_u64s);
	}

	memcpy_u64s(where, src,
		    bkeyp_key_u64s(f, src));
	memcpy_u64s(bkeyp_val(f, where), &insert->v,
		    bkeyp_val_u64s(f, src));

	bch_bset_fix_lookup_table(b, t, where, clobber_u64s, src->u64s);
	bch_bset_verify_lookup_table(b, t);

	bch_verify_key_order(b, iter, where);
	bch_verify_btree_nr_keys(b);
}

void bch_bset_delete(struct btree_keys *b,
		     struct bkey_packed *where,
		     unsigned clobber_u64s)
{
	struct bset_tree *t = bset_tree_last(b);
	struct bset *i = t->data;
	u64 *src_p = where->_data + clobber_u64s;
	u64 *dst_p = where->_data;

	memmove_u64s_down(dst_p, src_p, bset_bkey_last(i)->_data - src_p);
	le16_add_cpu(&i->u64s, -clobber_u64s);

	bch_bset_fix_lookup_table(b, t, where, clobber_u64s, 0);
	bch_bset_verify_lookup_table(b, t);
}

/* Lookup */

__flatten
static struct bkey_packed *bset_search_write_set(const struct btree_keys *b,
				struct bset_tree *t,
				struct bpos search,
				const struct bkey_packed *packed_search)
{
	unsigned li = 0, ri = t->size;

	while (li + 1 != ri) {
		unsigned m = (li + ri) >> 1;

		if (bkey_cmp_p_or_unp(b, table_to_bkey(t, m),
				      packed_search, search) >= 0)
			ri = m;
		else
			li = m;
	}

	return table_to_bkey(t, li);
}

__flatten
static struct bkey_packed *bset_search_tree(const struct btree_keys *b,
				struct bset_tree *t,
				struct bpos search,
				const struct bkey_packed *packed_search)
{
	struct bkey_float *f = &t->tree[1];
	unsigned inorder, n = 1;

	while (1) {
		if (likely(n << 4 < t->size)) {
			prefetch(&t->tree[n << 4]);
		} else if (n << 3 < t->size) {
			inorder = to_inorder(n, t);
			prefetch(cacheline_to_bkey(t, inorder, 0));
			prefetch(cacheline_to_bkey(t, inorder + 1, 0));
			prefetch(cacheline_to_bkey(t, inorder + 2, 0));
			prefetch(cacheline_to_bkey(t, inorder + 3, 0));
		} else if (n >= t->size)
			break;

		f = &t->tree[n];

		if (packed_search &&
		    likely(f->exponent < BFLOAT_FAILED))
			n = n * 2 + (f->mantissa <
				     bfloat_mantissa(packed_search, f));
		else
			n = n * 2 + (bkey_cmp_p_or_unp(b, tree_to_bkey(t, n),
						       packed_search,
						       search) < 0);
	} while (n < t->size);

	inorder = to_inorder(n >> 1, t);

	/*
	 * n would have been the node we recursed to - the low bit tells us if
	 * we recursed left or recursed right.
	 */
	if (n & 1) {
		return cacheline_to_bkey(t, inorder, f->m);
	} else {
		if (--inorder) {
			f = &t->tree[inorder_prev(n >> 1, t->size)];
			return cacheline_to_bkey(t, inorder, f->m);
		} else
			return t->data->start;
	}
}

/*
 * Returns the first key greater than or equal to @search
 */
__always_inline __flatten
static struct bkey_packed *bch_bset_search(struct btree_keys *b,
				struct bset_tree *t,
				struct bpos search,
				struct bkey_packed *packed_search,
				const struct bkey_packed *lossy_packed_search,
				bool strictly_greater)
{
	struct bkey_packed *m;

	/*
	 * First, we search for a cacheline, then lastly we do a linear search
	 * within that cacheline.
	 *
	 * To search for the cacheline, there's three different possibilities:
	 *  * The set is too small to have a search tree, so we just do a linear
	 *    search over the whole set.
	 *  * The set is the one we're currently inserting into; keeping a full
	 *    auxiliary search tree up to date would be too expensive, so we
	 *    use a much simpler lookup table to do a binary search -
	 *    bset_search_write_set().
	 *  * Or we use the auxiliary search tree we constructed earlier -
	 *    bset_search_tree()
	 */

	switch (bset_aux_tree_type(t)) {
	case BSET_NO_AUX_TREE:
		m = t->data->start;
		break;
	case BSET_RW_AUX_TREE:
		m = bset_search_write_set(b, t, search, lossy_packed_search);
		break;
	case BSET_RO_AUX_TREE:
		/*
		 * Each node in the auxiliary search tree covers a certain range
		 * of bits, and keys above and below the set it covers might
		 * differ outside those bits - so we have to special case the
		 * start and end - handle that here:
		 */

		if (unlikely(bkey_cmp_p_or_unp(b, &t->end,
					       packed_search, search) < 0))
			return bset_bkey_last(t->data);

		if (unlikely(bkey_cmp_p_or_unp(b, t->data->start,
					       packed_search, search) >= 0))
			m = t->data->start;
		else
			m = bset_search_tree(b, t, search, lossy_packed_search);
		break;
	}

	if (lossy_packed_search)
		while (m != bset_bkey_last(t->data) &&
		       !btree_iter_pos_cmp_p_or_unp(b, search, lossy_packed_search,
						    m, strictly_greater))
			m = bkey_next(m);

	if (!packed_search)
		while (m != bset_bkey_last(t->data) &&
		       !btree_iter_pos_cmp_packed(b, search, m, strictly_greater))
			m = bkey_next(m);

	if (IS_ENABLED(CONFIG_BCACHE_DEBUG)) {
		struct bkey_packed *prev = bkey_prev_all(t, m);

		BUG_ON(prev &&
		       btree_iter_pos_cmp_p_or_unp(b, search, packed_search,
						   prev, strictly_greater));
	}

	return m;
}

/* Btree node iterator */

void bch_btree_node_iter_push(struct btree_node_iter *iter,
			      struct btree_keys *b,
			      const struct bkey_packed *k,
			      const struct bkey_packed *end)
{
	if (k != end) {
		struct btree_node_iter_set *pos, n =
			((struct btree_node_iter_set) {
				 __btree_node_key_to_offset(b, k),
				 __btree_node_key_to_offset(b, end)
			 });

		btree_node_iter_for_each(iter, pos)
			if (btree_node_iter_cmp(iter, b, n, *pos) <= 0)
				break;

		memmove(pos + 1, pos,
			(void *) (iter->data + iter->used) - (void *) pos);
		iter->used++;
		*pos = n;
	}
}

noinline __flatten __attribute__((cold))
static void btree_node_iter_init_pack_failed(struct btree_node_iter *iter,
			      struct btree_keys *b, struct bpos search,
			      bool strictly_greater, bool is_extents)
{
	struct bset_tree *t;

	trace_bkey_pack_pos_fail(search);

	__bch_btree_node_iter_init(iter, is_extents);

	for_each_bset(b, t)
		__bch_btree_node_iter_push(iter, b,
			bch_bset_search(b, t, search, NULL, NULL,
					strictly_greater),
			bset_bkey_last(t->data));

	bch_btree_node_iter_sort(iter, b);
}

/**
 * bch_btree_node_iter_init - initialize a btree node iterator, starting from a
 * given position
 *
 * Main entry point to the lookup code for individual btree nodes:
 *
 * NOTE:
 *
 * When you don't filter out deleted keys, btree nodes _do_ contain duplicate
 * keys. This doesn't matter for most code, but it does matter for lookups.
 *
 * Some adjacent keys with a string of equal keys:
 *	i j k k k k l m
 *
 * If you search for k, the lookup code isn't guaranteed to return you any
 * specific k. The lookup code is conceptually doing a binary search and
 * iterating backwards is very expensive so if the pivot happens to land at the
 * last k that's what you'll get.
 *
 * This works out ok, but it's something to be aware of:
 *
 *  - For non extents, we guarantee that the live key comes last - see
 *    btree_node_iter_cmp(), keys_out_of_order(). So the duplicates you don't
 *    see will only be deleted keys you don't care about.
 *
 *  - For extents, deleted keys sort last (see the comment at the top of this
 *    file). But when you're searching for extents, you actually want the first
 *    key strictly greater than your search key - an extent that compares equal
 *    to the search key is going to have 0 sectors after the search key.
 *
 *    But this does mean that we can't just search for
 *    bkey_successor(start_of_range) to get the first extent that overlaps with
 *    the range we want - if we're unlucky and there's an extent that ends
 *    exactly where we searched, then there could be a deleted key at the same
 *    position and we'd get that when we search instead of the preceding extent
 *    we needed.
 *
 *    So we've got to search for start_of_range, then after the lookup iterate
 *    past any extents that compare equal to the position we searched for.
 */
void bch_btree_node_iter_init(struct btree_node_iter *iter,
			      struct btree_keys *b, struct bpos search,
			      bool strictly_greater, bool is_extents)
{
	struct bset_tree *t;
	struct bkey_packed p, *packed_search;

	BUG_ON(b->nsets > MAX_BSETS);

	switch (bkey_pack_pos_lossy(&p, search, b)) {
	case BKEY_PACK_POS_EXACT:
		packed_search = &p;
		break;
	case BKEY_PACK_POS_SMALLER:
		packed_search = NULL;
		break;
	case BKEY_PACK_POS_FAIL:
		btree_node_iter_init_pack_failed(iter, b, search,
					strictly_greater, is_extents);
		return;
	default:
		BUG();
	}

	__bch_btree_node_iter_init(iter, is_extents);

	for_each_bset(b, t)
		__bch_btree_node_iter_push(iter, b,
					   bch_bset_search(b, t, search,
							   packed_search, &p,
							   strictly_greater),
					   bset_bkey_last(t->data));

	bch_btree_node_iter_sort(iter, b);
}

void bch_btree_node_iter_init_from_start(struct btree_node_iter *iter,
					 struct btree_keys *b,
					 bool is_extents)
{
	struct bset_tree *t;

	__bch_btree_node_iter_init(iter, is_extents);

	for_each_bset(b, t)
		__bch_btree_node_iter_push(iter, b,
					   t->data->start,
					   bset_bkey_last(t->data));
	bch_btree_node_iter_sort(iter, b);
}

struct bkey_packed *bch_btree_node_iter_bset_pos(struct btree_node_iter *iter,
						 struct btree_keys *b,
						 struct bset *i)
{
	unsigned end = __btree_node_key_to_offset(b, bset_bkey_last(i));
	struct btree_node_iter_set *set;

	BUG_ON(iter->used > MAX_BSETS);

	btree_node_iter_for_each(iter, set)
		if (set->end == end)
			return __btree_node_offset_to_key(b, set->k);

	return bset_bkey_last(i);
}

static inline void btree_node_iter_sift(struct btree_node_iter *iter,
					struct btree_keys *b,
					unsigned start)
{
	unsigned i;

	EBUG_ON(iter->used > MAX_BSETS);

	for (i = start;
	     i + 1 < iter->used &&
	     btree_node_iter_cmp(iter, b, iter->data[i], iter->data[i + 1]) > 0;
	     i++)
		swap(iter->data[i], iter->data[i + 1]);
}

static inline void btree_node_iter_sort_two(struct btree_node_iter *iter,
					    struct btree_keys *b,
					    unsigned first)
{
	if (btree_node_iter_cmp(iter, b,
				iter->data[first],
				iter->data[first + 1]) > 0)
		swap(iter->data[first], iter->data[first + 1]);
}

void bch_btree_node_iter_sort(struct btree_node_iter *iter,
			      struct btree_keys *b)
{
	EBUG_ON(iter->used > 3);

	/* unrolled bubble sort: */

	if (iter->used > 2) {
		btree_node_iter_sort_two(iter, b, 0);
		btree_node_iter_sort_two(iter, b, 1);
	}

	if (iter->used > 1)
		btree_node_iter_sort_two(iter, b, 0);
}
EXPORT_SYMBOL(bch_btree_node_iter_sort);

/**
 * bch_btree_node_iter_advance - advance @iter by one key
 *
 * Doesn't do debugchecks - for cases where (insert_fixup_extent()) a bset might
 * momentarily have out of order extents.
 */
void bch_btree_node_iter_advance(struct btree_node_iter *iter,
				 struct btree_keys *b)
{
	struct bkey_packed *k = bch_btree_node_iter_peek_all(iter, b);

	iter->data->k += __bch_btree_node_iter_peek_all(iter, b)->u64s;

	BUG_ON(iter->data->k > iter->data->end);

	if (iter->data->k == iter->data->end) {
		BUG_ON(iter->used == 0);
		iter->data[0] = iter->data[--iter->used];
	}

	btree_node_iter_sift(iter, b, 0);

	bch_btree_node_iter_next_check(iter, b, k);
}

/*
 * Expensive:
 */
struct bkey_packed *bch_btree_node_iter_prev_all(struct btree_node_iter *iter,
						 struct btree_keys *b)
{
	struct bkey_packed *k, *prev = NULL;
	struct btree_node_iter_set *set;
	struct bset_tree *t;
	struct bset *prev_i;
	unsigned end;

	bch_btree_node_iter_verify(iter, b);

	for_each_bset(b, t) {
		k = bkey_prev_all(t,
			bch_btree_node_iter_bset_pos(iter, b, t->data));
		if (k &&
		    (!prev || __btree_node_iter_cmp(iter->is_extents, b,
						    k, prev) > 0)) {
			prev = k;
			prev_i = t->data;
		}
	}

	if (!prev)
		return NULL;

	/*
	 * We're manually memmoving instead of just calling sort() to ensure the
	 * prev we picked ends up in slot 0 - sort won't necessarily put it
	 * there because of duplicate deleted keys:
	 */
	end = __btree_node_key_to_offset(b, bset_bkey_last(prev_i));
	btree_node_iter_for_each(iter, set)
		if (set->end == end) {
			memmove(&iter->data[1],
				&iter->data[0],
				(void *) set - (void *) &iter->data[0]);
			goto out;
		}

	memmove(&iter->data[1],
		&iter->data[0],
		(void *) &iter->data[iter->used] - (void *) &iter->data[0]);
	iter->used++;
out:
	iter->data[0].k = __btree_node_key_to_offset(b, prev);
	iter->data[0].end = end;
	return prev;
}

struct bkey_packed *bch_btree_node_iter_prev(struct btree_node_iter *iter,
					     struct btree_keys *b)
{
	struct bkey_packed *k;

	do {
		k = bch_btree_node_iter_prev_all(iter, b);
	} while (k && bkey_deleted(k));

	return k;
}

struct bkey_s_c bch_btree_node_iter_peek_unpack(struct btree_node_iter *iter,
						struct btree_keys *b,
						struct bkey *u)
{
	struct bkey_packed *k = bch_btree_node_iter_peek(iter, b);

	return k ? bkey_disassemble(b, k, u) : bkey_s_c_null;
}
EXPORT_SYMBOL(bch_btree_node_iter_peek_unpack);

/* Mergesort */

void bch_btree_keys_stats(struct btree_keys *b, struct bset_stats *stats)
{
	struct bset_tree *t;

	for_each_bset(b, t) {
		enum bset_aux_tree_type type = bset_aux_tree_type(t);
		size_t j;

		stats->sets[type].nr++;
		stats->sets[type].bytes += le16_to_cpu(t->data->u64s) * sizeof(u64);

		if (bset_has_ro_aux_tree(t)) {
			stats->floats += t->size - 1;

			for (j = 1; j < t->size; j++)
				switch (t->tree[j].exponent) {
				case BFLOAT_FAILED_UNPACKED:
					stats->failed_unpacked++;
					break;
				case BFLOAT_FAILED_PREV:
					stats->failed_prev++;
					break;
				case BFLOAT_FAILED_OVERFLOW:
					stats->failed_overflow++;
					break;
				}
		}
	}
}

int bch_bkey_print_bfloat(struct btree_keys *b, struct bkey_packed *k,
			  char *buf, size_t size)
{
	struct bset_tree *t = bch_bkey_to_bset(b, k);
	struct bkey_packed *l, *r, *p;
	struct bkey uk, up;
	char buf1[200], buf2[200];
	unsigned j;

	if (!size)
		return 0;

	if (!bset_has_ro_aux_tree(t))
		goto out;

	j = inorder_to_tree(bkey_to_cacheline(t, k), t);
	if (j &&
	    j < t->size &&
	    k == tree_to_bkey(t, j))
		switch (t->tree[j].exponent) {
		case BFLOAT_FAILED_UNPACKED:
			uk = bkey_unpack_key(b, k);
			return scnprintf(buf, size,
					 "    failed unpacked at depth %u\n"
					 "\t%llu:%llu\n",
					 ilog2(j),
					 uk.p.inode, uk.p.offset);
		case BFLOAT_FAILED_PREV:
			p = tree_to_prev_bkey(t, j);
			l = is_power_of_2(j)
				? t->data->start
				: tree_to_prev_bkey(t, j >> ffs(j));
			r = is_power_of_2(j + 1)
				? bset_bkey_idx(t->data,
						le16_to_cpu(t->data->u64s) - t->end.u64s)
				: tree_to_bkey(t, j >> (ffz(j) + 1));

			up = bkey_unpack_key(b, p);
			uk = bkey_unpack_key(b, k);
			bch_to_binary(buf1, high_word(&b->format, p), b->nr_key_bits);
			bch_to_binary(buf2, high_word(&b->format, k), b->nr_key_bits);

			return scnprintf(buf, size,
					 "    failed prev at depth %u\n"
					 "\tkey starts at bit %u but first differing bit at %u\n"
					 "\t%llu:%llu\n"
					 "\t%llu:%llu\n"
					 "\t%s\n"
					 "\t%s\n",
					 ilog2(j),
					 bkey_greatest_differing_bit(b, l, r),
					 bkey_greatest_differing_bit(b, p, k),
					 uk.p.inode, uk.p.offset,
					 up.p.inode, up.p.offset,
					 buf1, buf2);
		case BFLOAT_FAILED_OVERFLOW:
			uk = bkey_unpack_key(b, k);
			return scnprintf(buf, size,
					 "    failed overflow at depth %u\n"
					 "\t%llu:%llu\n",
					 ilog2(j),
					 uk.p.inode, uk.p.offset);
		}
out:
	*buf = '\0';
	return 0;
}
