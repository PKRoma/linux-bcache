#ifndef _BCACHE_BSET_H
#define _BCACHE_BSET_H

#include <linux/bcache.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "bkey.h"
#include "bkey_methods.h"
#include "util.h" /* for time_stats */

/*
 * BKEYS:
 *
 * A bkey contains a key, a size field, a variable number of pointers, and some
 * ancillary flag bits.
 *
 * We use two different functions for validating bkeys, bkey_invalid and
 * bkey_deleted().
 *
 * The one exception to the rule that ptr_invalid() filters out invalid keys is
 * that it also filters out keys of size 0 - these are keys that have been
 * completely overwritten. It'd be safe to delete these in memory while leaving
 * them on disk, just unnecessary work - so we filter them out when resorting
 * instead.
 *
 * We can't filter out stale keys when we're resorting, because garbage
 * collection needs to find them to ensure bucket gens don't wrap around -
 * unless we're rewriting the btree node those stale keys still exist on disk.
 *
 * We also implement functions here for removing some number of sectors from the
 * front or the back of a bkey - this is mainly used for fixing overlapping
 * extents, by removing the overlapping sectors from the older key.
 *
 * BSETS:
 *
 * A bset is an array of bkeys laid out contiguously in memory in sorted order,
 * along with a header. A btree node is made up of a number of these, written at
 * different times.
 *
 * There could be many of them on disk, but we never allow there to be more than
 * 4 in memory - we lazily resort as needed.
 *
 * We implement code here for creating and maintaining auxiliary search trees
 * (described below) for searching an individial bset, and on top of that we
 * implement a btree iterator.
 *
 * BTREE ITERATOR:
 *
 * Most of the code in bcache doesn't care about an individual bset - it needs
 * to search entire btree nodes and iterate over them in sorted order.
 *
 * The btree iterator code serves both functions; it iterates through the keys
 * in a btree node in sorted order, starting from either keys after a specific
 * point (if you pass it a search key) or the start of the btree node.
 *
 * AUXILIARY SEARCH TREES:
 *
 * Since keys are variable length, we can't use a binary search on a bset - we
 * wouldn't be able to find the start of the next key. But binary searches are
 * slow anyways, due to terrible cache behaviour; bcache originally used binary
 * searches and that code topped out at under 50k lookups/second.
 *
 * So we need to construct some sort of lookup table. Since we only insert keys
 * into the last (unwritten) set, most of the keys within a given btree node are
 * usually in sets that are mostly constant. We use two different types of
 * lookup tables to take advantage of this.
 *
 * Both lookup tables share in common that they don't index every key in the
 * set; they index one key every BSET_CACHELINE bytes, and then a linear search
 * is used for the rest.
 *
 * For sets that have been written to disk and are no longer being inserted
 * into, we construct a binary search tree in an array - traversing a binary
 * search tree in an array gives excellent locality of reference and is very
 * fast, since both children of any node are adjacent to each other in memory
 * (and their grandchildren, and great grandchildren...) - this means
 * prefetching can be used to great effect.
 *
 * It's quite useful performance wise to keep these nodes small - not just
 * because they're more likely to be in L2, but also because we can prefetch
 * more nodes on a single cacheline and thus prefetch more iterations in advance
 * when traversing this tree.
 *
 * Nodes in the auxiliary search tree must contain both a key to compare against
 * (we don't want to fetch the key from the set, that would defeat the purpose),
 * and a pointer to the key. We use a few tricks to compress both of these.
 *
 * To compress the pointer, we take advantage of the fact that one node in the
 * search tree corresponds to precisely BSET_CACHELINE bytes in the set. We have
 * a function (to_inorder()) that takes the index of a node in a binary tree and
 * returns what its index would be in an inorder traversal, so we only have to
 * store the low bits of the offset.
 *
 * The key is 84 bits (KEY_DEV + key->key, the offset on the device). To
 * compress that,  we take advantage of the fact that when we're traversing the
 * search tree at every iteration we know that both our search key and the key
 * we're looking for lie within some range - bounded by our previous
 * comparisons. (We special case the start of a search so that this is true even
 * at the root of the tree).
 *
 * So we know the key we're looking for is between a and b, and a and b don't
 * differ higher than bit 50, we don't need to check anything higher than bit
 * 50.
 *
 * We don't usually need the rest of the bits, either; we only need enough bits
 * to partition the key range we're currently checking.  Consider key n - the
 * key our auxiliary search tree node corresponds to, and key p, the key
 * immediately preceding n.  The lowest bit we need to store in the auxiliary
 * search tree is the highest bit that differs between n and p.
 *
 * Note that this could be bit 0 - we might sometimes need all 80 bits to do the
 * comparison. But we'd really like our nodes in the auxiliary search tree to be
 * of fixed size.
 *
 * The solution is to make them fixed size, and when we're constructing a node
 * check if p and n differed in the bits we needed them to. If they don't we
 * flag that node, and when doing lookups we fallback to comparing against the
 * real key. As long as this doesn't happen to often (and it seems to reliably
 * happen a bit less than 1% of the time), we win - even on failures, that key
 * is then more likely to be in cache than if we were doing binary searches all
 * the way, since we're touching so much less memory.
 *
 * The keys in the auxiliary search tree are stored in (software) floating
 * point, with an exponent and a mantissa. The exponent needs to be big enough
 * to address all the bits in the original key, but the number of bits in the
 * mantissa is somewhat arbitrary; more bits just gets us fewer failures.
 *
 * We need 7 bits for the exponent and 3 bits for the key's offset (since keys
 * are 8 byte aligned); using 22 bits for the mantissa means a node is 4 bytes.
 * We need one node per 128 bytes in the btree node, which means the auxiliary
 * search trees take up 3% as much memory as the btree itself.
 *
 * Constructing these auxiliary search trees is moderately expensive, and we
 * don't want to be constantly rebuilding the search tree for the last set
 * whenever we insert another key into it. For the unwritten set, we use a much
 * simpler lookup table - it's just a flat array, so index i in the lookup table
 * corresponds to the i range of BSET_CACHELINE bytes in the set. Indexing
 * within each byte range works the same as with the auxiliary search trees.
 *
 * These are much easier to keep up to date when we insert a key - we do it
 * somewhat lazily; when we shift a key up we usually just increment the pointer
 * to it, only when it would overflow do we go to the trouble of finding the
 * first key in that range of bytes again.
 */

struct btree_node_iter;
struct btree_node_iter_set;

#define MAX_BSETS		3U

struct bset_tree {
	/*
	 * We construct a binary tree in an array as if the array
	 * started at 1, so that things line up on the same cachelines
	 * better: see comments in bset.c at cacheline_to_bkey() for
	 * details
	 */

	/* size of the binary tree and prev array */
	u16			size;

	/* function of size - precalculated for to_inorder() */
	u16			extra;

	u16			tree_offset;

	/*
	 * The nodes in the bset tree point to specific keys - this
	 * array holds the sizes of the previous key.
	 *
	 * Conceptually it's a member of struct bkey_float, but we want
	 * to keep bkey_float to 4 bytes and prev isn't used in the fast
	 * path.
	 */
	u16			prev_offset;

	/* copy of the last key in the set */
	struct bkey_packed	end;

	/* The actual btree node, with pointers to each sorted set */
	struct bset		*data;
};

enum bset_aux_tree_type {
	BSET_NO_AUX_TREE,
	BSET_RO_AUX_TREE,
	BSET_RW_AUX_TREE,
};

#define BSET_TREE_NR_TYPES	3

#define BSET_NO_AUX_TREE_VAL	(U16_MAX)
#define BSET_RW_AUX_TREE_VAL	(U16_MAX - 1)

static inline enum bset_aux_tree_type bset_aux_tree_type(struct bset_tree *t)
{
	switch (t->extra) {
	case BSET_NO_AUX_TREE_VAL:
		EBUG_ON(t->size);
		return BSET_NO_AUX_TREE;
	case BSET_RW_AUX_TREE_VAL:
		EBUG_ON(!t->size);
		return BSET_RW_AUX_TREE;
	default:
		EBUG_ON(!t->size);
		return BSET_RO_AUX_TREE;
	}
}

struct btree_nr_keys {

	/*
	 * Amount of live metadata (i.e. size of node after a compaction) in
	 * units of u64s
	 */
	u16			live_u64s;
	u16			bset_u64s[MAX_BSETS];

	/* live keys only: */
	u16			packed_keys;
	u16			unpacked_keys;
};

typedef void (*compiled_unpack_fn)(struct bkey *, const struct bkey_packed *);

struct btree_keys {
	u8			nsets;
	u8			page_order;
	u8			nr_key_bits;
	u8			unpack_fn_len;

	struct btree_nr_keys	nr;

	struct bkey_format	format;
	void			*aux_data;

	/*
	 * Sets of sorted keys - the real btree node - plus a binary search tree
	 *
	 * set[0] is special; set[0]->tree, set[0]->prev and set[0]->data point
	 * to the memory we have allocated for this btree node. Additionally,
	 * set[0]->data points to the entire btree node as it exists on disk.
	 */
	struct bset_tree	set[MAX_BSETS];
#ifdef CONFIG_BCACHE_DEBUG
	bool			*expensive_debug_checks;
#endif
};

static inline struct bkey
bkey_unpack_key_format_checked(const struct btree_keys *b,
			       const struct bkey_packed *src)
{
	struct bkey dst;

#ifdef HAVE_BCACHE_COMPILED_UNPACK
	{
		compiled_unpack_fn unpack_fn = b->aux_data;
		unpack_fn(&dst, src);

		if (IS_ENABLED(CONFIG_BCACHE_DEBUG)) {
			struct bkey dst2 = __bkey_unpack_key(&b->format, src);

			BUG_ON(memcmp(&dst, &dst2, sizeof(dst)));
		}
	}
#else
	dst = __bkey_unpack_key(&b->format, src);
#endif
	return dst;
}

/**
 * bkey_unpack_key -- unpack just the key, not the value
 */
static inline struct bkey bkey_unpack_key(const struct btree_keys *b,
					  const struct bkey_packed *src)
{
	return likely(bkey_packed(src))
		? bkey_unpack_key_format_checked(b, src)
		: *packed_to_bkey_c(src);
}

/* Disassembled bkeys */

static inline struct bkey_s_c bkey_disassemble(struct btree_keys *b,
					       const struct bkey_packed *k,
					       struct bkey *u)
{
	*u = bkey_unpack_key(b, k);

	return (struct bkey_s_c) { u, bkeyp_val(&b->format, k), };
}

/* non const version: */
static inline struct bkey_s __bkey_disassemble(struct btree_keys *b,
					       struct bkey_packed *k,
					       struct bkey *u)
{
	*u = bkey_unpack_key(b, k);

	return (struct bkey_s) { .k = u, .v = bkeyp_val(&b->format, k), };
}

#define for_each_bset(_b, _t)					\
	for (_t = (_b)->set; _t < (_b)->set + (_b)->nsets; _t++)

extern bool bch_expensive_debug_checks;

static inline bool btree_keys_expensive_checks(struct btree_keys *b)
{
#ifdef CONFIG_BCACHE_DEBUG
	return bch_expensive_debug_checks || *b->expensive_debug_checks;
#else
	return false;
#endif
}

static inline struct bset_tree *bset_tree_last(struct btree_keys *b)
{
	EBUG_ON(!b->nsets);
	return b->set + b->nsets - 1;
}

static inline bool bset_has_ro_aux_tree(struct bset_tree *t)
{
	return bset_aux_tree_type(t) == BSET_RO_AUX_TREE;
}

static inline bool bset_has_rw_aux_tree(struct bset_tree *t)
{
	return bset_aux_tree_type(t) == BSET_RW_AUX_TREE;
}

static inline void bch_bset_set_no_aux_tree(struct btree_keys *b,
					    struct bset_tree *t)
{
	BUG_ON(t < b->set);

	for (; t < b->set + ARRAY_SIZE(b->set); t++) {
		t->size = 0;
		t->extra = BSET_NO_AUX_TREE_VAL;
		t->tree_offset = U16_MAX;
		t->prev_offset = U16_MAX;
	}
}

static inline void btree_node_set_format(struct btree_keys *b,
					 struct bkey_format f)
{
	int len;

	b->format	= f;
	b->nr_key_bits	= bkey_format_key_bits(&f);

	len = bch_compile_bkey_format(&b->format, b->aux_data);
	BUG_ON(len < 0 || len > U8_MAX);

	b->unpack_fn_len = len;

	bch_bset_set_no_aux_tree(b, b->set);
}

#define __set_bytes(_i, _u64s)	(sizeof(*(_i)) + (_u64s) * sizeof(u64))
#define set_bytes(_i)		__set_bytes(_i, (_i)->u64s)

#define __set_blocks(_i, _u64s, _block_bytes)				\
	DIV_ROUND_UP((size_t) __set_bytes((_i), (_u64s)), (_block_bytes))

#define set_blocks(_i, _block_bytes)					\
	__set_blocks((_i), (_i)->u64s, (_block_bytes))

static inline struct bset *bset_next_set(struct btree_keys *b,
					 unsigned block_bytes)
{
	struct bset *i = bset_tree_last(b)->data;

	EBUG_ON(!is_power_of_2(block_bytes));

	return ((void *) i) + round_up(set_bytes(i), block_bytes);
}

void bch_btree_keys_free(struct btree_keys *);
int bch_btree_keys_alloc(struct btree_keys *, unsigned, gfp_t);
void bch_btree_keys_init(struct btree_keys *, bool *);

void bch_bset_init_first(struct btree_keys *, struct bset *);
void bch_bset_init_next(struct btree_keys *, struct bset *);
void bch_bset_build_aux_tree(struct btree_keys *, struct bset_tree *, bool);
void bch_bset_fix_invalidated_key(struct btree_keys *, struct bset_tree *,
				  struct bkey_packed *);

void bch_bset_insert(struct btree_keys *, struct btree_node_iter *,
		     struct bkey_packed *, struct bkey_i *, unsigned);
void bch_bset_delete(struct btree_keys *, struct bkey_packed *, unsigned);

/* Bkey utility code */

/* packed or unpacked */
static inline int bkey_cmp_p_or_unp(const struct btree_keys *b,
				    const struct bkey_packed *l,
				    const struct bkey_packed *r_packed,
				    struct bpos *r)
{
	EBUG_ON(r_packed && !bkey_packed(r_packed));

	if (unlikely(!bkey_packed(l)))
		return bkey_cmp(packed_to_bkey_c(l)->p, *r);

	if (likely(r_packed))
		return __bkey_cmp_packed_format_checked(l, r_packed, b);

	return __bkey_cmp_left_packed_format_checked(b, l, r);
}

/* Returns true if @k is after iterator position @pos */
static inline bool btree_iter_pos_cmp(struct bpos pos, const struct bkey *k,
				      bool strictly_greater)
{
	int cmp = bkey_cmp(k->p, pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

static inline bool btree_iter_pos_cmp_packed(const struct btree_keys *b,
					     struct bpos *pos,
					     const struct bkey_packed *k,
					     bool strictly_greater)
{
	int cmp = bkey_cmp_left_packed(b, k, pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

static inline bool btree_iter_pos_cmp_p_or_unp(const struct btree_keys *b,
					struct bpos pos,
					const struct bkey_packed *pos_packed,
					const struct bkey_packed *k,
					bool strictly_greater)
{
	int cmp = bkey_cmp_p_or_unp(b, k, pos_packed, &pos);

	return cmp > 0 ||
		(cmp == 0 && !strictly_greater && !bkey_deleted(k));
}

#define BKEY_PADDED(key)	__BKEY_PADDED(key, BKEY_EXTENT_VAL_U64s_MAX)

#define __bkey_idx(_set, _offset)				\
	((_set)->_data + (_offset))

#define bkey_idx(_set, _offset)					\
	((typeof(&(_set)->start[0])) __bkey_idx((_set), (_offset)))

#define __bset_bkey_last(_set)					\
	 __bkey_idx((_set), (_set)->u64s)

#define bset_bkey_last(_set)					\
	 bkey_idx((_set), le16_to_cpu((_set)->u64s))

static inline struct bkey_packed *bset_bkey_idx(struct bset *i, unsigned idx)
{
	return bkey_idx(i, idx);
}

struct bset_tree *bch_bkey_to_bset(struct btree_keys *, struct bkey_packed *);
struct bkey_packed *bkey_prev_all(struct btree_keys *, struct bset_tree *,
				  struct bkey_packed *);
struct bkey_packed *bkey_prev(struct btree_keys *, struct bset_tree *,
			      struct bkey_packed *);

enum bch_extent_overlap {
	BCH_EXTENT_OVERLAP_ALL		= 0,
	BCH_EXTENT_OVERLAP_BACK		= 1,
	BCH_EXTENT_OVERLAP_FRONT	= 2,
	BCH_EXTENT_OVERLAP_MIDDLE	= 3,
};

/* Returns how k overlaps with m */
static inline enum bch_extent_overlap bch_extent_overlap(const struct bkey *k,
							 const struct bkey *m)
{
	int cmp1 = bkey_cmp(k->p, m->p) < 0;
	int cmp2 = bkey_cmp(bkey_start_pos(k),
			    bkey_start_pos(m)) > 0;

	return (cmp1 << 1) + cmp2;
}

/* Btree key iteration */

struct btree_node_iter {
	u8		is_extents;
	u16		used;

	struct btree_node_iter_set {
		u16	k, end;
	} data[MAX_BSETS];
};

static inline void __bch_btree_node_iter_init(struct btree_node_iter *iter,
					      bool is_extents)
{
	iter->used = 0;
	iter->is_extents = is_extents;
}

void bch_btree_node_iter_push(struct btree_node_iter *, struct btree_keys *,
			      const struct bkey_packed *,
			      const struct bkey_packed *);
void bch_btree_node_iter_init(struct btree_node_iter *, struct btree_keys *,
			      struct bpos, bool, bool);
void bch_btree_node_iter_init_from_start(struct btree_node_iter *,
					 struct btree_keys *, bool);
struct bkey_packed *bch_btree_node_iter_bset_pos(struct btree_node_iter *,
						 struct btree_keys *,
						 struct bset *);

void bch_btree_node_iter_sort(struct btree_node_iter *, struct btree_keys *);
void bch_btree_node_iter_advance(struct btree_node_iter *, struct btree_keys *);

#define btree_node_iter_for_each(_iter, _set)			\
	for (_set = (_iter)->data;				\
	     _set < (_iter)->data + (_iter)->used;		\
	     _set++)

static inline bool bch_btree_node_iter_end(struct btree_node_iter *iter)
{
	return !iter->used;
}

static inline u16
__btree_node_key_to_offset(struct btree_keys *b, const struct bkey_packed *k)
{
	size_t ret = (u64 *) k - (u64 *) b->set->data;

	EBUG_ON(ret > U16_MAX);
	return ret;
}

static inline struct bkey_packed *
__btree_node_offset_to_key(struct btree_keys *b, u16 k)
{
	return (void *) ((u64 *) b->set->data + k);
}

static inline int __btree_node_iter_cmp(bool is_extents,
					struct btree_keys *b,
					struct bkey_packed *l,
					struct bkey_packed *r)
{
	/*
	 * For non extents, when keys compare equal the deleted keys have to
	 * come first - so that bch_btree_node_iter_next_check() can detect
	 * duplicate nondeleted keys (and possibly other reasons?)
	 *
	 * For extents, bkey_deleted() is used as a proxy for k->size == 0, so
	 * deleted keys have to sort last.
	 */
	return bkey_cmp_packed(b, l, r) ?: is_extents
		? (int) bkey_deleted(l) - (int) bkey_deleted(r)
		: (int) bkey_deleted(r) - (int) bkey_deleted(l);
}

static inline int btree_node_iter_cmp(struct btree_node_iter *iter,
				      struct btree_keys *b,
				      struct btree_node_iter_set l,
				      struct btree_node_iter_set r)
{
	return __btree_node_iter_cmp(iter->is_extents, b,
			__btree_node_offset_to_key(b, l.k),
			__btree_node_offset_to_key(b, r.k));
}

static inline void __bch_btree_node_iter_push(struct btree_node_iter *iter,
			      struct btree_keys *b,
			      const struct bkey_packed *k,
			      const struct bkey_packed *end)
{
	if (k != end)
		iter->data[iter->used++] = (struct btree_node_iter_set) {
			__btree_node_key_to_offset(b, k),
			__btree_node_key_to_offset(b, end)
		};
}

static inline struct bkey_packed *
__bch_btree_node_iter_peek_all(struct btree_node_iter *iter,
			       struct btree_keys *b)
{
	return __btree_node_offset_to_key(b, iter->data->k);
}

static inline struct bkey_packed *
bch_btree_node_iter_peek_all(struct btree_node_iter *iter,
			     struct btree_keys *b)
{
	return bch_btree_node_iter_end(iter)
		? NULL
		: __bch_btree_node_iter_peek_all(iter, b);
}

static inline struct bkey_packed *
bch_btree_node_iter_peek(struct btree_node_iter *iter, struct btree_keys *b)
{
	struct bkey_packed *ret;

	while ((ret = bch_btree_node_iter_peek_all(iter, b)) &&
	       bkey_deleted(ret))
		bch_btree_node_iter_advance(iter, b);

	return ret;
}

static inline struct bkey_packed *
bch_btree_node_iter_next_all(struct btree_node_iter *iter, struct btree_keys *b)
{
	struct bkey_packed *ret = bch_btree_node_iter_peek_all(iter, b);

	if (ret)
		bch_btree_node_iter_advance(iter, b);

	return ret;
}

struct bkey_packed *bch_btree_node_iter_prev_all(struct btree_node_iter *,
						 struct btree_keys *);
struct bkey_packed *bch_btree_node_iter_prev(struct btree_node_iter *,
					     struct btree_keys *);

/*
 * Iterates over all _live_ keys - skipping deleted (and potentially
 * overlapping) keys
 */
#define for_each_btree_node_key(b, k, iter, _is_extents)		\
	for (bch_btree_node_iter_init_from_start((iter), (b), (_is_extents));\
	     ((k) = bch_btree_node_iter_peek(iter, b));			\
	     bch_btree_node_iter_advance(iter, b))

struct bkey_s_c bch_btree_node_iter_peek_unpack(struct btree_node_iter *,
						struct btree_keys *,
						struct bkey *);

#define for_each_btree_node_key_unpack(b, k, iter, _is_extents, unpacked)\
	for (bch_btree_node_iter_init_from_start((iter), (b), (_is_extents));\
	     (k = bch_btree_node_iter_peek_unpack((iter), (b), (unpacked))).k;\
	     bch_btree_node_iter_advance(iter, b))

/* Accounting: */

static inline void btree_keys_account_key(struct btree_nr_keys *n,
					  unsigned bset,
					  struct bkey_packed *k,
					  int sign)
{
	n->live_u64s		+= k->u64s * sign;
	n->bset_u64s[bset]	+= k->u64s * sign;

	if (bkey_packed(k))
		n->packed_keys	+= sign;
	else
		n->unpacked_keys += sign;
}

#define btree_keys_account_key_add(_nr, _bset_idx, _k)		\
	btree_keys_account_key(_nr, _bset_idx, _k, 1)
#define btree_keys_account_key_drop(_nr, _bset_idx, _k)	\
	btree_keys_account_key(_nr, _bset_idx, _k, -1)

struct bset_stats {
	struct {
		size_t nr, bytes;
	} sets[BSET_TREE_NR_TYPES];

	size_t floats;
	size_t failed_unpacked;
	size_t failed_prev;
	size_t failed_overflow;
};

void bch_btree_keys_stats(struct btree_keys *, struct bset_stats *);
int bch_bkey_print_bfloat(struct btree_keys *, struct bkey_packed *,
			  char *, size_t);

/* Debug stuff */

void bch_dump_bset(struct btree_keys *, struct bset *, unsigned);
void bch_dump_btree_node(struct btree_keys *);
void bch_dump_btree_node_iter(struct btree_keys *, struct btree_node_iter *);

#ifdef CONFIG_BCACHE_DEBUG

void __bch_verify_btree_nr_keys(struct btree_keys *);
void bch_btree_node_iter_verify(struct btree_node_iter *, struct btree_keys *);
void bch_verify_key_order(struct btree_keys *, struct btree_node_iter *,
			  struct bkey_packed *);

#else

static inline void __bch_verify_btree_nr_keys(struct btree_keys *b) {}
static inline void bch_btree_node_iter_verify(struct btree_node_iter *iter,
					      struct btree_keys *b) {}
static inline void bch_verify_key_order(struct btree_keys *b,
					struct btree_node_iter *iter,
					struct bkey_packed *where) {}
#endif

static inline void bch_verify_btree_nr_keys(struct btree_keys *b)
{
	if (btree_keys_expensive_checks(b))
		__bch_verify_btree_nr_keys(b);
}

#endif
