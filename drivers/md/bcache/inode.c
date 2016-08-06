
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "inode.h"
#include "io.h"
#include "keylist.h"
#include "trans.h"

ssize_t bch_inode_status(char *buf, size_t len, const struct bkey *k)
{
	if (k->p.offset)
		return scnprintf(buf, len, "offset nonzero: %llu", k->p.offset);

	if (k->size)
		return scnprintf(buf, len, "size nonzero: %u", k->size);

	switch (k->type) {
	case KEY_TYPE_DELETED:
		return scnprintf(buf, len, "deleted");
	case KEY_TYPE_DISCARD:
		return scnprintf(buf, len, "discarded");
	case KEY_TYPE_ERROR:
		return scnprintf(buf, len, "error");
	case KEY_TYPE_COOKIE:
		return scnprintf(buf, len, "cookie");

	case BCH_INODE_FS:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode))
			return scnprintf(buf, len, "bad size: %zu",
					 bkey_val_bytes(k));

		if (k->p.inode < BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "fs inode in blockdev range: %llu",
					 k->p.inode);
		return 0;

	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k) != sizeof(struct bch_inode_blockdev))
			return scnprintf(buf, len, "bad size: %zu",
					 bkey_val_bytes(k));

		if (k->p.inode >= BLOCKDEV_INODE_MAX)
			return scnprintf(buf, len,
					 "blockdev inode in fs range: %llu",
					 k->p.inode);
		return 0;

	default:
		return scnprintf(buf, len, "unknown inode type: %u", k->type);
	}
}

static const char *bch_inode_invalid(const struct cache_set *c,
				     struct bkey_s_c k)
{
	if (k.k->p.offset)
		return "nonzero offset";

	switch (k.k->type) {
	case BCH_INODE_FS: {
		struct bkey_s_c_inode inode = bkey_s_c_to_inode(k);

		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode))
			return "incorrect value size";

		if (k.k->p.inode < BLOCKDEV_INODE_MAX)
			return "fs inode in blockdev range";

		if (INODE_STR_HASH_TYPE(inode.v) >= BCH_STR_HASH_NR)
			return "invalid str hash type";

		return NULL;
	}
	case BCH_INODE_BLOCKDEV:
		if (bkey_val_bytes(k.k) != sizeof(struct bch_inode_blockdev))
			return "incorrect value size";

		if (k.k->p.inode >= BLOCKDEV_INODE_MAX)
			return "blockdev inode in fs range";

		return NULL;
	default:
		return "invalid type";
	}
}

static void bch_inode_to_text(struct cache_set *c, char *buf,
			      size_t size, struct bkey_s_c k)
{
	struct bkey_s_c_inode inode;

	switch (k.k->type) {
	case BCH_INODE_FS:
		inode = bkey_s_c_to_inode(k);

		scnprintf(buf, size, "i_size %llu", inode.v->i_size);
		break;
	}
}

const struct btree_keys_ops bch_inode_ops = {
};

const struct bkey_ops bch_bkey_inode_ops = {
	.key_invalid	= bch_inode_invalid,
	.val_to_text	= bch_inode_to_text,
};

int bch_inode_find_slot(struct cache_set *c, struct btree_iter *iter, u64 max)
{
	struct bkey_s_c k;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode >= max)
			break;

		if (k.k->type < BCH_INODE_FS)
			return 0;

		/* slot used */
		bch_btree_iter_advance_pos(iter);
	}

	return -ENOSPC;
}

int bch_inode_create(struct cache_set *c, struct bkey_i_inode *inode)
{
	struct btree_iter iter;
	bool searched_from_start = false;
	struct bch_trans_inode_create *trans = &c->inode_create;
	u64 min = BCACHE_ROOT_INO;
	u64 max = c->opts.inodes_32bit ? U32_MAX : U64_MAX;
	u64 ino;
	int ret;

	mutex_lock(&c->inode_create_lock);

	if (!bch_transaction_active(&trans->t)) {
		bkey_trans_inode_create_val_init(&trans->k.k_i);
		trans->k.v.ino = cpu_to_le64(min);
		bch_transaction_start(c, &trans->t);
	}

	ino = clamp(le64_to_cpu(trans->k.v.ino), min, max);

	if (ino == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(ino, 0));

	do {
		struct bkey_i_trans_inode_create_val new_trans = trans->k;

		ret = bch_inode_find_slot(c, &iter, max);
		if (ret && !searched_from_start) {
			bch_btree_iter_unlock(&iter);
			ino = min;
			searched_from_start = true;
			goto again;
		}

		if (ret)
			break;

		inode->k.p = iter.pos;

		if (inode->k.p.inode < le64_to_cpu(trans->k.v.ino))
			le64_add_cpu(&new_trans.v.gen, 1);

		/* XXX set inode gen from trans_inode_create gen */

		new_trans.v.ino = le64_to_cpu(inode->k.p.inode + 1);

		pr_debug("inserting inode %llu (size %u)",
			 inode->k.p.inode, inode->k.u64s);

		ret = bch_btree_insert_at(c, NULL, NULL, NULL,
				BTREE_INSERT_ATOMIC,
				BTREE_INSERT_ENTRY(&iter, &inode->k_i),
				BTREE_TRANS_ENTRY(&trans->t, &new_trans.k_i));
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);

	mutex_unlock(&c->inode_create_lock);
	return ret;
}

int bch_blockdev_inode_create(struct cache_set *c, struct bkey_i *inode,
			      u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	bool searched_from_start = false;
	int ret;

	*hint = clamp(*hint, min, max);

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(*hint, 0));

	do {
		ret = bch_inode_find_slot(c, &iter, max);
		if (ret)
			break;

		inode->k.p = iter.pos;
		*hint = inode->k.p.inode + 1;

		pr_debug("inserting inode %llu (size %u)",
			 inode->k.p.inode, inode->k.u64s);

		ret = bch_btree_insert_at(c, NULL, NULL, NULL,
				BTREE_INSERT_ATOMIC,
				BTREE_INSERT_ENTRY(&iter, inode));
	} while (ret == -EINTR);

	bch_btree_iter_unlock(&iter);

	if (ret == -ENOSPC && !searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	return ret;
}

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size,
		       struct extent_insert_hook *hook, u64 *journal_seq)
{
	return bch_discard(c, POS(inode_nr, new_size), POS(inode_nr + 1, 0),
			   0, NULL, hook, journal_seq);
}

int bch_inode_rm(struct cache_set *c, u64 inode_nr)
{
	struct bkey_i delete;
	int ret;

	ret = bch_inode_truncate(c, inode_nr, 0, NULL, NULL);
	if (ret < 0)
		return ret;

	ret = bch_btree_delete_range(c, BTREE_ID_XATTRS,
				     POS(inode_nr, 0),
				     POS(inode_nr + 1, 0),
				     0, NULL, NULL, NULL);
	if (ret < 0)
		return ret;

	/*
	 * If this was a directory, there shouldn't be any real dirents left -
	 * but there could be whiteouts (from hash collisions) that we should
	 * delete:
	 *
	 * XXX: the dirent could ideally would delete whitouts when they're no
	 * longer needed
	 */
	ret = bch_btree_delete_range(c, BTREE_ID_DIRENTS,
				     POS(inode_nr, 0),
				     POS(inode_nr + 1, 0),
				     0, NULL, NULL, NULL);
	if (ret < 0)
		return ret;

	bkey_init(&delete.k);
	delete.k.p.inode = inode_nr;

	return bch_btree_insert(c, BTREE_ID_INODES, &delete, NULL,
				NULL, NULL, BTREE_INSERT_NOFAIL);
}

int bch_inode_update(struct cache_set *c, struct bkey_i *inode,
		     u64 *journal_seq)
{
	return bch_btree_update(c, BTREE_ID_INODES, inode, journal_seq);
}

int bch_inode_find_by_inum(struct cache_set *c, u64 inode_nr,
			   struct bch_inode *inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = -ENOENT;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_INODES,
				      POS(inode_nr, 0), k) {
		switch (k.k->type) {
		case BCH_INODE_FS:
			ret = 0;
			*inode = *bkey_s_c_to_inode(k).v;
			break;
		default:
			/* hole, not found */
			break;
		}

		break;

	}
	bch_btree_iter_unlock(&iter);

	return ret;
}

int bch_cached_dev_inode_find_by_uuid(struct cache_set *c, uuid_le *uuid,
				      struct bkey_i_inode_blockdev *ret)
{
	struct btree_iter iter;
	struct bkey_s_c k;

	for_each_btree_key(&iter, c, BTREE_ID_INODES, POS(0, 0), k) {
		if (k.k->p.inode >= BLOCKDEV_INODE_MAX)
			break;

		if (k.k->type == BCH_INODE_BLOCKDEV) {
			struct bkey_s_c_inode_blockdev inode =
				bkey_s_c_to_inode_blockdev(k);

			pr_debug("found inode %llu: %pU (u64s %u)",
				 inode.k->p.inode, inode.v->i_uuid.b,
				 inode.k->u64s);

			if (CACHED_DEV(inode.v) &&
			    !memcmp(uuid, &inode.v->i_uuid, 16)) {
				bkey_reassemble(&ret->k_i, k);
				bch_btree_iter_unlock(&iter);
				return 0;
			}
		}

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);
	return -ENOENT;
}

struct bkey_i_inode *bch_inode_assemble(const struct bch_inode *inode,
			const struct bch_inode_i_generation *i_generation,
			const struct bch_inode_long_times *long_times,
			gfp_t gfp)
{
	size_t bytes = sizeof(struct bkey_i_inode);
	struct bkey_i_inode *new_inode;
	void *p;
	unsigned i_flags;
	int ret;

#define count_field(_field)						\
	if (_field && !bch_is_zero((void *) _field, sizeof(*_field)))	\
		bytes += sizeof(*_field);				\
	else								\
		_field = NULL;

	count_field(i_generation);
	count_field(long_times);

	BUG_ON(bytes & 7);

	new_inode = kmalloc(bytes, gfp);
	if (!new_inode)
		return NULL;

	bkey_init(&new_inode->k);
	new_inode->k.u64s	= bytes / 8;
	new_inode->k.type	= BCH_INODE_FS;
	new_inode->k.p		= iter->pos;
	new_inode->v		= *inode;
	i_flags = le32_to_cpu(new_inode->v.i_flags);

	p = &(&new_inode->v)[1];

#define encode_field(_field)						\
	if (_field) {							\
		memcpy(p, _field, sizeof(*_field));			\
		p += sizeof(*_field);					\
		i_flags |=  (1 << __BCH_INODE_##_field);		\
	} else {							\
		i_flags &= ~(1 << __BCH_INODE_##_field);		\
	}

	encode_field(i_generation);
	encode_field(long_times);

	new_inode->v.i_flags = cpu_to_le32(i_flags);

	return new_inode;
}

struct inode_opt_fields bch_inode_opt_fields_get(const struct bch_inode *inode)
{
	size_t offset = sizeof(struct bch_inode);
	struct inode_opt_fields ret;

#define walk_field(_field, _field_size)					\
	do {								\
		if (le32_to_cpu(inode->i_flags) &			\
		    (1 << __BCH_INODE_##_field)) {			\
			struct bch_inode_##_field *field =		\
				(void *) inode + offset;		\
			size_t size = _field_size;			\
									\
			ret._field = field;				\
									\
			EBUG_ON(size & 7);				\
			offset += size;					\
		} else {						\
			ret._field = NULL;				\
		}							\
	} while (0)

#define walk_constant_size_field(_field)				\
		walk_field(_field, sizeof(*field))

	walk_constant_size_field(i_generation);
	walk_constant_size_field(long_times);
#undef walk_field
#undef walk_constant_size_field

	return ret;
}
