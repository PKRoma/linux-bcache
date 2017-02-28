
#include "bcache.h"
#include "bkey_methods.h"
#include "btree_update.h"
#include "extents.h"
#include "inode.h"
#include "io.h"
#include "keylist.h"

#include <linux/random.h>

#include <asm/unaligned.h>

#define FIELD_BYTES()						\

static const u8 byte_table[8] = { 1, 2, 3, 4, 6, 8, 10, 13 };
static const u8 bits_table[8] = {
	1  * 8 - 1,
	2  * 8 - 2,
	3  * 8 - 3,
	4  * 8 - 4,
	6  * 8 - 5,
	8  * 8 - 6,
	10 * 8 - 7,
	13 * 8 - 8,
};

static int inode_encode_field(u8 *out, u8 *end, const u64 in[2])
{
	unsigned bytes, bits, shift;

	if (likely(!in[1]))
		bits = fls64(in[0]);
	else
		bits = fls64(in[1]) + 64;

	for (shift = 1; shift <= 8; shift++)
		if (bits < bits_table[shift - 1])
			goto got_shift;

	BUG();
got_shift:
	bytes = byte_table[shift - 1];

	BUG_ON(out + bytes > end);

	if (likely(bytes <= 8)) {
		u64 b = cpu_to_be64(in[0]);

		memcpy(out, (void *) &b + 8 - bytes, bytes);
	} else {
		u64 b = cpu_to_be64(in[1]);

		memcpy(out, (void *) &b + 16 - bytes, bytes);
		put_unaligned_be64(in[0], out + bytes - 8);
	}

	*out |= (1 << 8) >> shift;

	return bytes;
}

static int inode_decode_field(const u8 *in, const u8 *end,
			      u64 out[2], unsigned *out_bits)
{
	unsigned bytes, bits, shift;

	if (in >= end)
		return -1;

	if (!*in)
		return -1;

	/*
	 * position of highest set bit indicates number of bytes:
	 * shift = number of bits to remove in high byte:
	 */
	shift	= 8 - __fls(*in); /* 1 <= shift <= 8 */
	bytes	= byte_table[shift - 1];
	bits	= bytes * 8 - shift;

	if (in + bytes > end)
		return -1;

	/*
	 * we're assuming it's safe to deref up to 7 bytes < in; this will work
	 * because keys always start quite a bit more than 7 bytes after the
	 * start of the btree node header:
	 */
	if (likely(bytes <= 8)) {
		out[0] = get_unaligned_be64(in + bytes - 8);
		out[0] <<= 64 - bits;
		out[0] >>= 64 - bits;
		out[1] = 0;
	} else {
		out[0] = get_unaligned_be64(in + bytes - 8);
		out[1] = get_unaligned_be64(in + bytes - 16);
		out[1] <<= 128 - bits;
		out[1] >>= 128 - bits;
	}

	*out_bits = out[1] ? 64 + fls64(out[1]) : fls64(out[0]);
	return bytes;
}

void bch_inode_pack(struct bkey_inode_buf *packed,
		    const struct bch_inode_unpacked *inode)
{
	u8 *out = packed->inode.v.fields;
	u8 *end = (void *) &packed[1];
	u8 *last_nonzero_field = out;
	u64 field[2];
	unsigned nr_fields = 0, last_nonzero_fieldnr = 0;

	bkey_inode_init(&packed->inode.k_i);
	packed->inode.k.p.inode		= inode->inum;
	packed->inode.v.i_hash_seed	= inode->i_hash_seed;
	packed->inode.v.i_flags		= cpu_to_le32(inode->i_flags);
	packed->inode.v.i_mode		= cpu_to_le16(inode->i_mode);

#define BCH_INODE_FIELD(_name, _bits)					\
	field[0] = inode->_name;					\
	field[1] = 0;							\
	out += inode_encode_field(out, end, field);			\
	nr_fields++;							\
									\
	if (field[0] | field[1]) {					\
		last_nonzero_field = out;				\
		last_nonzero_fieldnr = nr_fields;			\
	}

	BCH_INODE_FIELDS()
#undef  BCH_INODE_FIELD

	out = last_nonzero_field;
	nr_fields = last_nonzero_fieldnr;

	set_bkey_val_bytes(&packed->inode.k, out - (u8 *) &packed->inode.v);
	memset(out, 0,
	       (u8 *) &packed->inode.v +
	       bkey_val_bytes(&packed->inode.k) - out);

	SET_INODE_NR_FIELDS(&packed->inode.v, nr_fields);

	if (IS_ENABLED(CONFIG_BCACHE_DEBUG)) {
		struct bch_inode_unpacked unpacked;

		int ret = bch_inode_unpack(inode_i_to_s_c(&packed->inode),
					   &unpacked);
		BUG_ON(ret);
		BUG_ON(unpacked.inum		!= inode->inum);
		BUG_ON(unpacked.i_hash_seed	!= inode->i_hash_seed);
		BUG_ON(unpacked.i_mode		!= inode->i_mode);

#define BCH_INODE_FIELD(_name, _bits)	BUG_ON(unpacked._name != inode->_name);
		BCH_INODE_FIELDS()
#undef  BCH_INODE_FIELD
	}
}

int bch_inode_unpack(struct bkey_s_c_inode inode,
		     struct bch_inode_unpacked *unpacked)
{
	const u8 *in = inode.v->fields;
	const u8 *end = (void *) inode.v + bkey_val_bytes(inode.k);
	u64 field[2];
	unsigned fieldnr = 0, field_bits;
	int ret;

	unpacked->inum		= inode.k->p.inode;
	unpacked->i_hash_seed	= inode.v->i_hash_seed;
	unpacked->i_flags	= le32_to_cpu(inode.v->i_flags);
	unpacked->i_mode	= le16_to_cpu(inode.v->i_mode);

#define BCH_INODE_FIELD(_name, _bits)					\
	if (fieldnr++ == INODE_NR_FIELDS(inode.v)) {			\
		memset(&unpacked->_name, 0,				\
		       sizeof(*unpacked) -				\
		       offsetof(struct bch_inode_unpacked, _name));	\
		return 0;						\
	}								\
									\
	ret = inode_decode_field(in, end, field, &field_bits);		\
	if (ret < 0)							\
		return ret;						\
									\
	if (field_bits > sizeof(unpacked->_name) * 8)			\
		return -1;						\
									\
	unpacked->_name = field[0];					\
	in += ret;

	BCH_INODE_FIELDS()
#undef  BCH_INODE_FIELD

	/* XXX: signal if there were more fields than expected? */

	return 0;
}

static const char *bch_inode_invalid(const struct cache_set *c,
				     struct bkey_s_c k)
{
	if (k.k->p.offset)
		return "nonzero offset";

	switch (k.k->type) {
	case BCH_INODE_FS: {
		struct bkey_s_c_inode inode = bkey_s_c_to_inode(k);
		struct bch_inode_unpacked unpacked;

		if (bkey_val_bytes(k.k) < sizeof(struct bch_inode))
			return "incorrect value size";

		if (k.k->p.inode < BLOCKDEV_INODE_MAX)
			return "fs inode in blockdev range";

		if (INODE_STR_HASH(inode.v) >= BCH_STR_HASH_NR)
			return "invalid str hash type";

		if (bch_inode_unpack(inode, &unpacked))
			return "invalid variable length fields";

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
	struct bch_inode_unpacked unpacked;

	switch (k.k->type) {
	case BCH_INODE_FS:
		inode = bkey_s_c_to_inode(k);
		if (bch_inode_unpack(inode, &unpacked)) {
			scnprintf(buf, size, "(unpack error)");
			break;
		}

		scnprintf(buf, size, "i_size %llu", unpacked.i_size);
		break;
	}
}

const struct bkey_ops bch_bkey_inode_ops = {
	.key_invalid	= bch_inode_invalid,
	.val_to_text	= bch_inode_to_text,
};

void bch_inode_init(struct cache_set *c, struct bch_inode_unpacked *inode_u,
		    uid_t uid, gid_t gid, umode_t mode, dev_t rdev)
{
	s64 now = timespec_to_bch_time(c, CURRENT_TIME);

	memset(inode_u, 0, sizeof(*inode_u));

	/* ick */
	inode_u->i_flags |= c->sb.str_hash_type << INODE_STR_HASH_OFFSET;
	get_random_bytes(&inode_u->i_hash_seed, sizeof(inode_u->i_hash_seed));

	inode_u->i_mode		= mode;
	inode_u->i_uid		= uid;
	inode_u->i_gid		= gid;
	inode_u->i_dev		= rdev;
	inode_u->i_atime	= now;
	inode_u->i_mtime	= now;
	inode_u->i_ctime	= now;
	inode_u->i_otime	= now;
}

int bch_inode_create(struct cache_set *c, struct bkey_i *inode,
		     u64 min, u64 max, u64 *hint)
{
	struct btree_iter iter;
	bool searched_from_start = false;
	int ret;

	if (!max)
		max = ULLONG_MAX;

	if (c->opts.inodes_32bit)
		max = min_t(u64, max, U32_MAX);

	if (*hint >= max || *hint < min)
		*hint = min;

	if (*hint == min)
		searched_from_start = true;
again:
	bch_btree_iter_init_intent(&iter, c, BTREE_ID_INODES, POS(*hint, 0));

	while (1) {
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);

		ret = btree_iter_err(k);
		if (ret) {
			bch_btree_iter_unlock(&iter);
			return ret;
		}

		if (k.k->type < BCH_INODE_FS) {
			inode->k.p = k.k->p;

			pr_debug("inserting inode %llu (size %u)",
				 inode->k.p.inode, inode->k.u64s);

			ret = bch_btree_insert_at(c, NULL, NULL, NULL,
					BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&iter, inode));

			if (ret == -EINTR)
				continue;

			bch_btree_iter_unlock(&iter);
			if (!ret)
				*hint = k.k->p.inode + 1;

			return ret;
		} else {
			if (iter.pos.inode == max)
				break;
			/* slot used */
			bch_btree_iter_advance_pos(&iter);
		}
	}
	bch_btree_iter_unlock(&iter);

	if (!searched_from_start) {
		/* Retry from start */
		*hint = min;
		searched_from_start = true;
		goto again;
	}

	return -ENOSPC;
}

int bch_inode_truncate(struct cache_set *c, u64 inode_nr, u64 new_size,
		       struct extent_insert_hook *hook, u64 *journal_seq)
{
	return bch_discard(c, POS(inode_nr, new_size), POS(inode_nr + 1, 0),
			   ZERO_VERSION, NULL, hook, journal_seq);
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
				     ZERO_VERSION, NULL, NULL, NULL);
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
				     ZERO_VERSION, NULL, NULL, NULL);
	if (ret < 0)
		return ret;

	bkey_init(&delete.k);
	delete.k.p.inode = inode_nr;

	return bch_btree_insert(c, BTREE_ID_INODES, &delete, NULL,
				NULL, NULL, BTREE_INSERT_NOFAIL);
}

int bch_inode_find_by_inum(struct cache_set *c, u64 inode_nr,
			   struct bch_inode_unpacked *inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	int ret = -ENOENT;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_INODES,
				      POS(inode_nr, 0), k) {
		switch (k.k->type) {
		case BCH_INODE_FS:
			ret = bch_inode_unpack(bkey_s_c_to_inode(k), inode);
			break;
		default:
			/* hole, not found */
			break;
		}

		break;

	}

	return bch_btree_iter_unlock(&iter) ?: ret;
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
