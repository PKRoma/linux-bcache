#ifndef _BCACHE_BTREE_TYPES_H
#define _BCACHE_BTREE_TYPES_H

#include <linux/bcache.h>
#include <linux/list.h>
#include <linux/rhashtable.h>
#include <linux/semaphore.h>
#include <linux/workqueue.h>

#include "bkey_methods.h"
#include "journal_types.h"
#include "six.h"

struct cache_set;
struct open_bucket;
struct btree_interior_update;

#define MAX_BSETS		3U

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

	u16			data_offset;
	u16			aux_data_offset;

	/* copy of the last key in the set */
	struct bkey_packed	end;
};

struct btree_write {
	struct journal_entry_pin	journal;
	struct closure_waitlist		wait;
};

struct btree {
	/* Hottest entries first */
	struct rhash_head	hash;

	/* Key/pointer for this btree node */
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);

	struct six_lock		lock;

	unsigned long		flags;
	u16			written;
	u8			level;
	u8			btree_id;
	u8			nsets;
	u8			nr_key_bits;

	struct bkey_format	format;

	struct btree_node	*data;
	void			*aux_data;

	/*
	 * Sets of sorted keys - the real btree node - plus a binary search tree
	 *
	 * set[0] is special; set[0]->tree, set[0]->prev and set[0]->data point
	 * to the memory we have allocated for this btree node. Additionally,
	 * set[0]->data points to the entire btree node as it exists on disk.
	 */
	struct bset_tree	set[MAX_BSETS];

	struct btree_nr_keys	nr;
	u16			sib_u64s[2];
	u16			whiteout_u64s;
	u16			uncompacted_whiteout_u64s;
	u8			page_order;
	u8			unpack_fn_len;

	/*
	 * XXX: add a delete sequence number, so when btree_node_relock() fails
	 * because the lock sequence number has changed - i.e. the contents were
	 * modified - we can still relock the node if it's still the one we
	 * want, without redoing the traversal
	 */

	/*
	 * For asynchronous splits/interior node updates:
	 * When we do a split, we allocate new child nodes and update the parent
	 * node to point to them: we update the parent in memory immediately,
	 * but then we must wait until the children have been written out before
	 * the update to the parent can be written - this is a list of the
	 * btree_interior_updates that are blocking this node from being
	 * written:
	 */
	struct list_head	write_blocked;

	struct open_bucket	*ob;

	/* lru list */
	struct list_head	list;

	struct btree_write	writes[2];

#ifdef CONFIG_BCACHE_DEBUG
	bool			*expensive_debug_checks;
#endif
};

#define BTREE_FLAG(flag)						\
static inline bool btree_node_ ## flag(struct btree *b)			\
{	return test_bit(BTREE_NODE_ ## flag, &b->flags); }		\
									\
static inline void set_btree_node_ ## flag(struct btree *b)		\
{	set_bit(BTREE_NODE_ ## flag, &b->flags); }			\
									\
static inline void clear_btree_node_ ## flag(struct btree *b)		\
{	clear_bit(BTREE_NODE_ ## flag, &b->flags); }

enum btree_flags {
	BTREE_NODE_read_error,
	BTREE_NODE_write_error,
	BTREE_NODE_dirty,
	BTREE_NODE_write_idx,
	BTREE_NODE_accessed,
	BTREE_NODE_write_in_flight,
	BTREE_NODE_just_written,
};

BTREE_FLAG(read_error);
BTREE_FLAG(write_error);
BTREE_FLAG(dirty);
BTREE_FLAG(write_idx);
BTREE_FLAG(accessed);
BTREE_FLAG(write_in_flight);
BTREE_FLAG(just_written);

static inline struct btree_write *btree_current_write(struct btree *b)
{
	return b->writes + btree_node_write_idx(b);
}

static inline struct btree_write *btree_prev_write(struct btree *b)
{
	return b->writes + (btree_node_write_idx(b) ^ 1);
}

static inline struct bset_tree *bset_tree_last(struct btree *b)
{
	EBUG_ON(!b->nsets);
	return b->set + b->nsets - 1;
}

static inline struct bset *bset(const struct btree *b,
				const struct bset_tree *t)
{
	return (void *) b->data + t->data_offset * sizeof(u64);
}

static inline void set_btree_bset(struct btree *b, struct bset_tree *t,
				  const struct bset *i)
{
	t->data_offset = (u64 *) i - (u64 *) b->data;

	EBUG_ON(bset(b, t) != i);
}

static inline struct bset *btree_bset_first(struct btree *b)
{
	return bset(b, b->set);
}

static inline struct bset *btree_bset_last(struct btree *b)
{
	return bset(b, bset_tree_last(b));
}

static inline unsigned bset_byte_offset(struct btree *b, void *i)
{
	return i - (void *) b->data;
}

/* Type of keys @b contains: */
static inline enum bkey_type btree_node_type(struct btree *b)
{
	return b->level ? BKEY_TYPE_BTREE : b->btree_id;
}

static inline const struct bkey_ops *btree_node_ops(struct btree *b)
{
	return bch_bkey_ops[btree_node_type(b)];
}

static inline bool btree_node_has_ptrs(struct btree *b)
{
	return btree_type_has_ptrs(btree_node_type(b));
}

static inline bool btree_node_is_extents(struct btree *b)
{
	return btree_node_type(b) == BKEY_TYPE_EXTENTS;
}

struct btree_root {
	struct btree		*b;

	struct btree_interior_update *as;

	/* On disk root - see async splits: */
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
	u8			level;
	u8			alive;
};

/*
 * Optional hook that will be called just prior to a btree node update, when
 * we're holding the write lock and we know what key is about to be overwritten:
 */

struct btree_iter;
struct bucket_stats_cache_set;
struct btree_node_iter;

enum extent_insert_hook_ret {
	BTREE_HOOK_DO_INSERT,
	BTREE_HOOK_NO_INSERT,
	BTREE_HOOK_RESTART_TRANS,
};

struct extent_insert_hook {
	enum extent_insert_hook_ret
	(*fn)(struct extent_insert_hook *, struct bpos, struct bpos,
	      struct bkey_s_c, const struct bkey_i *);
};

enum btree_insert_ret {
	BTREE_INSERT_OK,
	/* extent spanned multiple leaf nodes: have to traverse to next node: */
	BTREE_INSERT_NEED_TRAVERSE,
	/* write lock held for too long */
	BTREE_INSERT_NEED_RESCHED,
	/* leaf node needs to be split */
	BTREE_INSERT_BTREE_NODE_FULL,
	BTREE_INSERT_JOURNAL_RES_FULL,
	BTREE_INSERT_ENOSPC,
	BTREE_INSERT_NEED_GC_LOCK,
};

enum btree_gc_coalesce_fail_reason {
	BTREE_GC_COALESCE_FAIL_RESERVE_GET,
	BTREE_GC_COALESCE_FAIL_KEYLIST_REALLOC,
	BTREE_GC_COALESCE_FAIL_FORMAT_FITS,
};

typedef struct btree_nr_keys (*sort_fix_overlapping_fn)(struct bset *,
							struct btree *,
							struct btree_node_iter *);

#endif /* _BCACHE_BTREE_TYPES_H */
