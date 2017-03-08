
#include "bcache.h"
#include "btree_update.h"
#include "dirent.h"
#include "error.h"
#include "fs.h"
#include "fs-gc.h"
#include "inode.h"
#include "keylist.h"
#include "super.h"

#include <linux/generic-radix-tree.h>

#define QSTR(n) { { { .len = strlen(n) } }, .name = n }

static int remove_dirent(struct cache_set *c, struct btree_iter *iter,
			 struct bkey_s_c_dirent dirent)
{
	struct qstr name;
	struct bch_inode_unpacked dir_inode;
	struct bch_hash_info dir_hash_info;
	u64 dir_inum = dirent.k->p.inode;
	int ret;
	char *buf;

	name.len = bch_dirent_name_bytes(dirent);
	buf = kmalloc(name.len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, dirent.v->d_name, name.len);
	buf[name.len] = '\0';
	name.name = buf;

	/* Unlock iter so we don't deadlock, after copying name: */
	bch_btree_iter_unlock(iter);

	ret = bch_inode_find_by_inum(c, dir_inum, &dir_inode);
	if (ret)
		goto err;

	dir_hash_info = bch_hash_info_init(&dir_inode);

	ret = bch_dirent_delete(c, dir_inum, &dir_hash_info, &name, NULL);
err:
	kfree(buf);
	return ret;
}

static int reattach_inode(struct cache_set *c,
			  struct bch_inode_unpacked *lostfound_inode,
			  u64 inum)
{
	struct bch_hash_info lostfound_hash_info =
		bch_hash_info_init(lostfound_inode);
	struct bkey_inode_buf packed;
	char name_buf[20];
	struct qstr name;
	int ret;

	snprintf(name_buf, sizeof(name_buf), "%llu", inum);
	name = (struct qstr) QSTR(name_buf);

	lostfound_inode->i_nlink++;

	bch_inode_pack(&packed, lostfound_inode);

	ret = bch_btree_insert(c, BTREE_ID_INODES, &packed.inode.k_i,
			       NULL, NULL, NULL, 0);
	if (ret)
		return ret;

	return bch_dirent_create(c, lostfound_inode->inum,
				 &lostfound_hash_info,
				 DT_DIR, &name, inum, NULL, 0);
}

struct inode_walker {
	bool			first_this_inode;
	bool			have_inode;
	u64			cur_inum;
	struct bch_inode_unpacked inode;
};

static struct inode_walker inode_walker_init(void)
{
	return (struct inode_walker) {
		.cur_inum	= -1,
		.have_inode	= false,
	};
}

static int walk_inode(struct cache_set *c, struct inode_walker *w, u64 inum)
{
	w->first_this_inode	= inum != w->cur_inum;
	w->cur_inum		= inum;

	if (w->first_this_inode) {
		int ret = bch_inode_find_by_inum(c, inum, &w->inode);

		if (ret && ret != -ENOENT)
			return ret;

		w->have_inode = !ret;
	}

	return 0;
}

/*
 * Walk extents: verify that extents have a corresponding S_ISREG inode, and
 * that i_size an i_sectors are consistent
 */
noinline_for_stack
static int check_extents(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 i_sectors;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		if (k.k->type == KEY_TYPE_DISCARD)
			continue;

		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
			"extent type %u for missing inode %llu",
			k.k->type, k.k->p.inode);

		unfixable_fsck_err_on(w.first_this_inode && w.have_inode &&
			w.inode.i_sectors !=
			(i_sectors = bch_count_inode_sectors(c, w.cur_inum)),
			c, "i_sectors wrong: got %llu, should be %llu",
			w.inode.i_sectors, i_sectors);

		unfixable_fsck_err_on(w.have_inode &&
			!S_ISREG(w.inode.i_mode) && !S_ISLNK(w.inode.i_mode), c,
			"extent type %u for non regular file, inode %llu mode %o",
			k.k->type, k.k->p.inode, w.inode.i_mode);

		unfixable_fsck_err_on(k.k->type != BCH_RESERVATION &&
			k.k->p.offset > round_up(w.inode.i_size, PAGE_SIZE) >> 9, c,
			"extent type %u offset %llu past end of inode %llu, i_size %llu",
			k.k->type, k.k->p.offset, k.k->p.inode, w.inode.i_size);
	}
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/*
 * Walk dirents: verify that they all have a corresponding S_ISDIR inode,
 * validate d_type
 */
noinline_for_stack
static int check_dirents(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		struct bkey_s_c_dirent d;
		struct bch_inode_unpacked target;
		bool have_target;
		u64 d_inum;

		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
				      "dirent in nonexisting directory %llu",
				      k.k->p.inode);

		unfixable_fsck_err_on(!S_ISDIR(w.inode.i_mode), c,
				      "dirent in non directory inode %llu, type %u",
				      k.k->p.inode, mode_to_type(w.inode.i_mode));

		if (k.k->type != BCH_DIRENT)
			continue;

		d = bkey_s_c_to_dirent(k);
		d_inum = le64_to_cpu(d.v->d_inum);

		if (fsck_err_on(d_inum == d.k->p.inode, c,
				"dirent points to own directory")) {
			ret = remove_dirent(c, &iter, d);
			if (ret)
				goto err;
			continue;
		}

		ret = bch_inode_find_by_inum(c, d_inum, &target);
		if (ret && ret != -ENOENT)
			break;

		have_target = !ret;
		ret = 0;

		if (fsck_err_on(!have_target, c,
				"dirent points to missing inode %llu, type %u filename %s",
				d_inum, d.v->d_type, d.v->d_name)) {
			ret = remove_dirent(c, &iter, d);
			if (ret)
				goto err;
			continue;
		}

		if (fsck_err_on(have_target &&
				d.v->d_type !=
				mode_to_type(le16_to_cpu(target.i_mode)), c,
				"incorrect d_type: got %u should be %u, filename %s",
				d.v->d_type,
				mode_to_type(le16_to_cpu(target.i_mode)),
				d.v->d_name)) {
			struct bkey_i_dirent *n;

			n = kmalloc(bkey_bytes(d.k), GFP_KERNEL);
			if (!n) {
				ret = -ENOMEM;
				goto err;
			}

			bkey_reassemble(&n->k_i, d.s_c);
			n->v.d_type = mode_to_type(le16_to_cpu(target.i_mode));

			ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					BTREE_INSERT_NOFAIL,
					BTREE_INSERT_ENTRY(&iter, &n->k_i));
			kfree(n);
			if (ret)
				goto err;

		}
	}
err:
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/*
 * Walk xattrs: verify that they all have a corresponding inode
 */
noinline_for_stack
static int check_xattrs(struct cache_set *c)
{
	struct inode_walker w = inode_walker_init();
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = 0;

	for_each_btree_key(&iter, c, BTREE_ID_XATTRS,
			   POS(BCACHE_ROOT_INO, 0), k) {
		ret = walk_inode(c, &w, k.k->p.inode);
		if (ret)
			break;

		unfixable_fsck_err_on(!w.have_inode, c,
			"xattr for missing inode %llu",
			k.k->p.inode);
	}
fsck_err:
	return bch_btree_iter_unlock(&iter) ?: ret;
}

/* Get root directory, create if it doesn't exist: */
static int check_root(struct cache_set *c, struct bch_inode_unpacked *root_inode)
{
	struct bkey_inode_buf packed;
	int ret;

	ret = bch_inode_find_by_inum(c, BCACHE_ROOT_INO, root_inode);
	if (ret && ret != -ENOENT)
		return ret;

	if (fsck_err_on(ret, c, "root directory missing"))
		goto create_root;

	if (fsck_err_on(!S_ISDIR(root_inode->i_mode), c,
			"root inode not a directory"))
		goto create_root;

	return 0;
fsck_err:
	return ret;
create_root:
	bch_inode_init(c, root_inode, 0, 0, S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0);
	root_inode->inum = BCACHE_ROOT_INO;

	bch_inode_pack(&packed, root_inode);

	return bch_btree_insert(c, BTREE_ID_INODES, &packed.inode.k_i,
				NULL, NULL, NULL, 0);
}

/* Get lost+found, create if it doesn't exist: */
static int check_lostfound(struct cache_set *c,
			   struct bch_inode_unpacked *root_inode,
			   struct bch_inode_unpacked *lostfound_inode)
{
	struct qstr lostfound = QSTR("lost+found");
	struct bch_hash_info root_hash_info =
		bch_hash_info_init(root_inode);
	struct bkey_inode_buf packed;
	u64 inum;
	int ret;

	inum = bch_dirent_lookup(c, BCACHE_ROOT_INO, &root_hash_info,
				 &lostfound);
	if (!inum) {
		bch_notice(c, "creating lost+found");
		goto create_lostfound;
	}

	ret = bch_inode_find_by_inum(c, inum, lostfound_inode);
	if (ret && ret != -ENOENT)
		return ret;

	if (fsck_err_on(ret, c, "lost+found missing"))
		goto create_lostfound;

	if (fsck_err_on(!S_ISDIR(lostfound_inode->i_mode), c,
			"lost+found inode not a directory"))
		goto create_lostfound;

	return 0;
fsck_err:
	return ret;
create_lostfound:
	root_inode->i_nlink++;

	bch_inode_pack(&packed, root_inode);

	ret = bch_btree_insert(c, BTREE_ID_INODES, &packed.inode.k_i,
			       NULL, NULL, NULL, 0);
	if (ret)
		return ret;

	bch_inode_init(c, lostfound_inode, 0, 0, S_IFDIR|S_IRWXU|S_IRUGO|S_IXUGO, 0);
	bch_inode_pack(&packed, lostfound_inode);

	ret = bch_inode_create(c, &packed.inode.k_i, BLOCKDEV_INODE_MAX, 0,
			       &c->unused_inode_hint);
	if (ret)
		return ret;

	lostfound_inode->inum = packed.inode.k.p.inode;

	ret = bch_dirent_create(c, BCACHE_ROOT_INO, &root_hash_info, DT_DIR,
				&lostfound, lostfound_inode->inum, NULL, 0);
	if (ret)
		return ret;

	return 0;
}

struct inode_bitmap {
	unsigned long	*bits;
	size_t		size;
};

static inline bool inode_bitmap_test(struct inode_bitmap *b, size_t nr)
{
	return nr < b->size ? test_bit(nr, b->bits) : false;
}

static inline int inode_bitmap_set(struct inode_bitmap *b, size_t nr)
{
	if (nr >= b->size) {
		size_t new_size = max(max(PAGE_SIZE * 8,
					  b->size * 2),
					  nr + 1);
		void *n;

		new_size = roundup_pow_of_two(new_size);
		n = krealloc(b->bits, new_size / 8, GFP_KERNEL|__GFP_ZERO);
		if (!n)
			return -ENOMEM;

		b->bits = n;
		b->size = new_size;
	}

	__set_bit(nr, b->bits);
	return 0;
}

struct pathbuf {
	size_t		nr;
	size_t		size;

	struct pathbuf_entry {
		u64	inum;
		u64	offset;
	}		*entries;
};

static int path_down(struct pathbuf *p, u64 inum)
{
	if (p->nr == p->size) {
		size_t new_size = max(256UL, p->size * 2);
		void *n = krealloc(p->entries,
				   new_size * sizeof(p->entries[0]),
				   GFP_KERNEL);
		if (!n)
			return -ENOMEM;

		p->entries = n;
		p->size = new_size;
	};

	p->entries[p->nr++] = (struct pathbuf_entry) {
		.inum = inum,
		.offset = 0,
	};
	return 0;
}

noinline_for_stack
static int check_directory_structure(struct cache_set *c,
				     struct bch_inode_unpacked *lostfound_inode)
{
	struct inode_bitmap dirs_done = { NULL, 0 };
	struct pathbuf path = { 0, 0, NULL };
	struct pathbuf_entry *e;
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent dirent;
	bool had_unreachable;
	u64 d_inum;
	int ret = 0;

	/* DFS: */
restart_dfs:
	ret = inode_bitmap_set(&dirs_done, BCACHE_ROOT_INO);
	if (ret)
		goto err;

	ret = path_down(&path, BCACHE_ROOT_INO);
	if (ret)
		return ret;

	while (path.nr) {
next:
		e = &path.entries[path.nr - 1];

		if (e->offset == U64_MAX)
			goto up;

		for_each_btree_key(&iter, c, BTREE_ID_DIRENTS,
				   POS(e->inum, e->offset + 1), k) {
			if (k.k->p.inode != e->inum)
				break;

			e->offset = k.k->p.offset;

			if (k.k->type != BCH_DIRENT)
				continue;

			dirent = bkey_s_c_to_dirent(k);

			if (dirent.v->d_type != DT_DIR)
				continue;

			d_inum = le64_to_cpu(dirent.v->d_inum);

			if (fsck_err_on(inode_bitmap_test(&dirs_done, d_inum), c,
					"directory with multiple hardlinks")) {
				ret = remove_dirent(c, &iter, dirent);
				if (ret)
					goto err;
				continue;
			}

			ret = inode_bitmap_set(&dirs_done, d_inum);
			if (ret)
				goto err;

			ret = path_down(&path, d_inum);
			if (ret)
				goto err;

			bch_btree_iter_unlock(&iter);
			goto next;
		}
		ret = bch_btree_iter_unlock(&iter);
		if (ret)
			goto err;
up:
		path.nr--;
	}

	had_unreachable = false;

	for_each_btree_key(&iter, c, BTREE_ID_INODES, POS_MIN, k) {
		if (k.k->type != BCH_INODE_FS ||
		    !S_ISDIR(le16_to_cpu(bkey_s_c_to_inode(k).v->i_mode)))
			continue;

		if (fsck_err_on(!inode_bitmap_test(&dirs_done, k.k->p.inode), c,
				"unreachable directory found (inum %llu)",
				k.k->p.inode)) {
			bch_btree_iter_unlock(&iter);

			ret = reattach_inode(c, lostfound_inode, k.k->p.inode);
			if (ret)
				goto err;

			had_unreachable = true;
		}
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		goto err;

	if (had_unreachable) {
		bch_info(c, "reattached unreachable directories, restarting pass to check for loops");
		kfree(dirs_done.bits);
		kfree(path.entries);
		memset(&dirs_done, 0, sizeof(dirs_done));
		memset(&path, 0, sizeof(path));
		goto restart_dfs;
	}

out:
	kfree(dirs_done.bits);
	kfree(path.entries);
	return ret;
err:
fsck_err:
	ret = bch_btree_iter_unlock(&iter) ?: ret;
	goto out;
}

struct nlink {
	u32	count;
	u32	dir_count;
};

typedef GENRADIX(struct nlink) nlink_table;

static void inc_link(struct cache_set *c, nlink_table *links,
		     u64 range_start, u64 *range_end,
		     u64 inum, bool dir)
{
	struct nlink *link;

	if (inum < range_start || inum >= *range_end)
		return;

	link = genradix_ptr_alloc(links, inum - range_start, GFP_KERNEL);
	if (!link) {
		bch_verbose(c, "allocation failed during fs gc - will need another pass");
		*range_end = inum;
		return;
	}

	if (dir)
		link->dir_count++;
	else
		link->count++;
}

noinline_for_stack
static int bch_gc_walk_dirents(struct cache_set *c, nlink_table *links,
			       u64 range_start, u64 *range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bkey_s_c_dirent d;
	u64 d_inum;
	int ret;

	inc_link(c, links, range_start, range_end, BCACHE_ROOT_INO, false);

	for_each_btree_key(&iter, c, BTREE_ID_DIRENTS, POS_MIN, k) {
		switch (k.k->type) {
		case BCH_DIRENT:
			d = bkey_s_c_to_dirent(k);
			d_inum = le64_to_cpu(d.v->d_inum);

			if (d.v->d_type == DT_DIR)
				inc_link(c, links, range_start, range_end,
					 d.k->p.inode, true);

			inc_link(c, links, range_start, range_end,
				 d_inum, false);

			break;
		}

		bch_btree_iter_cond_resched(&iter);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		bch_err(c, "error in fs gc: btree error %i while walking dirents", ret);

	return ret;
}

s64 bch_count_inode_sectors(struct cache_set *c, u64 inum)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 sectors = 0;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS(inum, 0), k) {
		if (k.k->p.inode != inum)
			break;

		if (bkey_extent_is_allocation(k.k))
			sectors += k.k->size;
	}

	return bch_btree_iter_unlock(&iter) ?: sectors;
}

static int bch_gc_do_inode(struct cache_set *c,
			   struct bch_inode_unpacked *lostfound_inode,
			   struct btree_iter *iter,
			   struct bkey_s_c_inode inode, struct nlink link)
{
	struct bch_inode_unpacked u;
	int ret = 0;
	u32 i_nlink, real_i_nlink;
	bool do_update = false;

	ret = bch_inode_unpack(inode, &u);
	if (bch_fs_inconsistent_on(ret, c,
			 "error unpacking inode %llu in fs-gc",
			 inode.k->p.inode))
		return ret;

	i_nlink = u.i_nlink + nlink_bias(u.i_mode);

	fsck_err_on(i_nlink < link.count, c,
		    "inode %llu i_link too small (%u < %u, type %i)",
		    inode.k->p.inode, i_nlink,
		    link.count, mode_to_type(u.i_mode));

	/* These should have been caught/fixed by earlier passes: */
	if (S_ISDIR(u.i_mode)) {
		need_fsck_err_on(link.count > 1, c,
			"directory %llu with multiple hardlinks: %u",
			inode.k->p.inode, link.count);

		real_i_nlink = link.count * 2 + link.dir_count;
	} else {
		need_fsck_err_on(link.dir_count, c,
			"found dirents for non directory %llu",
			inode.k->p.inode);

		real_i_nlink = link.count + link.dir_count;
	}

	if (!link.count) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but found orphaned inode %llu",
			    inode.k->p.inode);

		if (fsck_err_on(S_ISDIR(u.i_mode) &&
				bch_empty_dir(c, inode.k->p.inode), c,
				"non empty directory with link count 0, "
				"inode nlink %u, dir links found %u",
				i_nlink, link.dir_count)) {
			ret = reattach_inode(c, lostfound_inode,
					     inode.k->p.inode);
			if (ret)
				return ret;
		}

		bch_verbose(c, "deleting inode %llu", inode.k->p.inode);

		ret = bch_inode_rm(c, inode.k->p.inode);
		if (ret)
			bch_err(c, "error in fs gc: error %i "
				"while deleting inode", ret);
		return ret;
	}

	if (u.i_flags & BCH_INODE_I_SIZE_DIRTY) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has i_size dirty",
			    inode.k->p.inode);

		bch_verbose(c, "truncating inode %llu", inode.k->p.inode);

		/*
		 * XXX: need to truncate partial blocks too here - or ideally
		 * just switch units to bytes and that issue goes away
		 */

		ret = bch_inode_truncate(c, inode.k->p.inode,
				round_up(u.i_size, PAGE_SIZE) >> 9,
				NULL, NULL);
		if (ret) {
			bch_err(c, "error in fs gc: error %i "
				"truncating inode", ret);
			return ret;
		}

		/*
		 * We truncated without our normal sector accounting hook, just
		 * make sure we recalculate it:
		 */
		u.i_flags |= BCH_INODE_I_SECTORS_DIRTY;

		u.i_flags &= ~BCH_INODE_I_SIZE_DIRTY;
		do_update = true;
	}

	if (u.i_flags & BCH_INODE_I_SECTORS_DIRTY) {
		s64 sectors;

		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has i_sectors dirty",
			    inode.k->p.inode);

		bch_verbose(c, "recounting sectors for inode %llu",
			    inode.k->p.inode);

		sectors = bch_count_inode_sectors(c, inode.k->p.inode);
		if (sectors < 0) {
			bch_err(c, "error in fs gc: error %i "
				"recounting inode sectors",
				(int) sectors);
			return sectors;
		}

		u.i_sectors = sectors;
		u.i_flags &= ~BCH_INODE_I_SECTORS_DIRTY;
		do_update = true;
	}

	if (i_nlink != real_i_nlink) {
		fsck_err_on(c->sb.clean, c,
			    "filesystem marked clean, "
			    "but inode %llu has wrong i_nlink "
			    "(type %u i_nlink %u, should be %u)",
			    inode.k->p.inode, mode_to_type(u.i_mode),
			    i_nlink, real_i_nlink);

		bch_verbose(c, "setting inode %llu nlinks from %u to %u",
			    inode.k->p.inode, i_nlink, real_i_nlink);
		u.i_nlink = real_i_nlink - nlink_bias(u.i_mode);;
		do_update = true;
	}

	if (do_update) {
		struct bkey_inode_buf p;

		bch_inode_pack(&p, &u);

		ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					  BTREE_INSERT_NOFAIL,
					  BTREE_INSERT_ENTRY(iter, &p.inode.k_i));
		if (ret && ret != -EINTR)
			bch_err(c, "error in fs gc: error %i "
				"updating inode", ret);
	}
fsck_err:
	return ret;
}

noinline_for_stack
static int bch_gc_walk_inodes(struct cache_set *c,
			      struct bch_inode_unpacked *lostfound_inode,
			      nlink_table *links,
			      u64 range_start, u64 range_end)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct nlink *link, zero_links = { 0, 0 };
	struct genradix_iter nlinks_iter;
	int ret = 0, ret2 = 0;
	u64 nlinks_pos;

	bch_btree_iter_init(&iter, c, BTREE_ID_INODES, POS(range_start, 0));
	genradix_iter_init(&nlinks_iter);

	while ((k = bch_btree_iter_peek(&iter)).k &&
	       !btree_iter_err(k)) {
peek_nlinks:	link = genradix_iter_peek(&nlinks_iter, links);

		if (!link && (!k.k || iter.pos.inode >= range_end))
			break;

		nlinks_pos = range_start + nlinks_iter.pos;
		if (iter.pos.inode > nlinks_pos) {
			/* Should have been caught by dirents pass: */
			need_fsck_err_on(link && link->count, c,
				"missing inode %llu (nlink %u)",
				nlinks_pos, link->count);
			genradix_iter_advance(&nlinks_iter, links);
			goto peek_nlinks;
		}

		if (iter.pos.inode < nlinks_pos || !link)
			link = &zero_links;

		if (k.k && k.k->type == BCH_INODE_FS) {
			/*
			 * Avoid potential deadlocks with iter for
			 * truncate/rm/etc.:
			 */
			bch_btree_iter_unlock(&iter);

			ret = bch_gc_do_inode(c, lostfound_inode, &iter,
					      bkey_s_c_to_inode(k), *link);
			if (ret == -EINTR)
				continue;
			if (ret)
				break;

			if (link->count)
				atomic_long_inc(&c->nr_inodes);
		} else {
			/* Should have been caught by dirents pass: */
			need_fsck_err_on(link->count, c,
				"missing inode %llu (nlink %u)",
				nlinks_pos, link->count);
		}

		if (nlinks_pos == iter.pos.inode)
			genradix_iter_advance(&nlinks_iter, links);

		bch_btree_iter_advance_pos(&iter);
		bch_btree_iter_cond_resched(&iter);
	}
fsck_err:
	ret2 = bch_btree_iter_unlock(&iter);
	if (ret2)
		bch_err(c, "error in fs gc: btree error %i while walking inodes", ret2);

	return ret ?: ret2;
}

noinline_for_stack
static int check_inode_nlinks(struct cache_set *c,
			      struct bch_inode_unpacked *lostfound_inode)
{
	nlink_table links;
	u64 this_iter_range_start, next_iter_range_start = 0;
	int ret = 0;

	genradix_init(&links);

	do {
		this_iter_range_start = next_iter_range_start;
		next_iter_range_start = U64_MAX;

		ret = bch_gc_walk_dirents(c, &links,
					  this_iter_range_start,
					  &next_iter_range_start);
		if (ret)
			break;

		ret = bch_gc_walk_inodes(c, lostfound_inode, &links,
					 this_iter_range_start,
					 next_iter_range_start);
		if (ret)
			break;

		genradix_free(&links);
	} while (next_iter_range_start != U64_MAX);

	genradix_free(&links);

	return ret;
}

/*
 * Checks for inconsistencies that shouldn't happen, unless we have a bug.
 * Doesn't fix them yet, mainly because they haven't yet been observed:
 */
int bch_fsck(struct cache_set *c, bool full_fsck)
{
	struct bch_inode_unpacked root_inode, lostfound_inode;
	int ret;

	ret = check_root(c, &root_inode);
	if (ret)
		return ret;

	ret = check_lostfound(c, &root_inode, &lostfound_inode);
	if (ret)
		return ret;

	if (!full_fsck)
		goto check_nlinks;

	ret = check_extents(c);
	if (ret)
		return ret;

	ret = check_dirents(c);
	if (ret)
		return ret;

	ret = check_xattrs(c);
	if (ret)
		return ret;

	ret = check_directory_structure(c, &lostfound_inode);
	if (ret)
		return ret;
check_nlinks:
	ret = check_inode_nlinks(c, &lostfound_inode);
	if (ret)
		return ret;

	return 0;
}
