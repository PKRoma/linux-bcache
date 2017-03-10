#ifndef _BCACHE_BTREE_CACHE_H
#define _BCACHE_BTREE_CACHE_H

#include "bcache.h"
#include "btree_types.h"

struct btree_iter;

extern const char * const bch_btree_ids[];

void bch_recalc_btree_reserve(struct bch_fs *);

void mca_hash_remove(struct bch_fs *, struct btree *);
int mca_hash_insert(struct bch_fs *, struct btree *,
		    unsigned, enum btree_id);

void mca_cannibalize_unlock(struct bch_fs *);
int mca_cannibalize_lock(struct bch_fs *, struct closure *);

struct btree *mca_alloc(struct bch_fs *);

struct btree *bch_btree_node_get(struct btree_iter *, const struct bkey_i *,
				 unsigned, enum six_lock_type);

void bch_fs_btree_exit(struct bch_fs *);
int bch_fs_btree_init(struct bch_fs *);

#define for_each_cached_btree(_b, _c, _tbl, _iter, _pos)		\
	for ((_tbl) = rht_dereference_rcu((_c)->btree_cache_table.tbl,	\
					  &(_c)->btree_cache_table),	\
	     _iter = 0;	_iter < (_tbl)->size; _iter++)			\
		rht_for_each_entry_rcu((_b), (_pos), _tbl, _iter, hash)

static inline size_t btree_bytes(struct bch_fs *c)
{
	return c->sb.btree_node_size << 9;
}

static inline size_t btree_max_u64s(struct bch_fs *c)
{
	return (btree_bytes(c) - sizeof(struct btree_node)) / sizeof(u64);
}

static inline size_t btree_pages(struct bch_fs *c)
{
	return c->sb.btree_node_size >> (PAGE_SHIFT - 9);
}

static inline size_t btree_page_order(struct bch_fs *c)
{
	return ilog2(btree_pages(c));
}

static inline unsigned btree_blocks(struct bch_fs *c)
{
	return c->sb.btree_node_size >> c->block_bits;
}

#define BTREE_SPLIT_THRESHOLD(c)		(btree_blocks(c) * 3 / 4)

#define BTREE_FOREGROUND_MERGE_THRESHOLD(c)	(btree_max_u64s(c) * 1 / 3)
#define BTREE_FOREGROUND_MERGE_HYSTERESIS(c)			\
	(BTREE_FOREGROUND_MERGE_THRESHOLD(c) +			\
	 (BTREE_FOREGROUND_MERGE_THRESHOLD(c) << 2))

#define btree_node_root(_c, _b)	((_c)->btree_roots[(_b)->btree_id].b)

int bch_print_btree_node(struct bch_fs *, struct btree *,
			 char *, size_t);

#endif /* _BCACHE_BTREE_CACHE_H */
