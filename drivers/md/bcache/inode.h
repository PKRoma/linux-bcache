#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

extern const struct btree_keys_ops bch_inode_ops;
extern const struct bkey_ops bch_bkey_inode_ops;

ssize_t bch_inode_status(char *, size_t, const struct bkey *);

int bch_inode_create(struct cache_set *, struct bkey_i *, u64, u64, u64 *);
int bch_inode_truncate(struct cache_set *, u64, u64,
		       struct extent_insert_hook *, u64 *);
int bch_inode_rm(struct cache_set *, u64);

int bch_inode_update(struct cache_set *, struct bkey_i *, u64 *);

int bch_inode_find_by_inum(struct cache_set *, u64, struct bch_inode *);
int bch_cached_dev_inode_find_by_uuid(struct cache_set *, uuid_le *,
				      struct bkey_i_inode_blockdev *);

struct inode_opt_fields {
	const struct bch_inode_i_generation	*i_generation;
	const struct bch_inode_long_times	*long_times;
};

/*
 * This is just to provide a buffer that has enough space for an inode with all
 * optional fields - it is not to be used for accessing the optional fields:
 */
struct bkey_inode_buf {
	struct bkey_i			k_i;
	struct bch_inode		v;
	struct bch_inode_i_generation	__i_generation;
	struct bch_inode_long_times	__long_times;
};

struct inode_opt_fields bch_inode_opt_fields_get(const struct bch_inode *);

#endif
