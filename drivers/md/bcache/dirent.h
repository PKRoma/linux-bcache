#ifndef _BCACHE_DIRENT_H
#define _BCACHE_DIRENT_H

extern const struct bkey_ops bch_bkey_dirent_ops;

struct qstr;
struct file;
struct dir_context;
struct bch_fs;
struct bch_hash_info;

unsigned bch_dirent_name_bytes(struct bkey_s_c_dirent);
int bch_dirent_create(struct bch_fs *c, u64, const struct bch_hash_info *,
		      u8, const struct qstr *, u64, u64 *, int);
int bch_dirent_delete(struct bch_fs *, u64, const struct bch_hash_info *,
		      const struct qstr *, u64 *);

enum bch_rename_mode {
	BCH_RENAME,
	BCH_RENAME_OVERWRITE,
	BCH_RENAME_EXCHANGE,
};

int bch_dirent_rename(struct bch_fs *,
		      struct inode *, const struct qstr *,
		      struct inode *, const struct qstr *,
		      u64 *, enum bch_rename_mode);

u64 bch_dirent_lookup(struct bch_fs *, u64, const struct bch_hash_info *,
		      const struct qstr *);

int bch_empty_dir(struct bch_fs *, u64);
int bch_readdir(struct bch_fs *, struct file *, struct dir_context *);

#endif /* _BCACHE_DIRENT_H */

