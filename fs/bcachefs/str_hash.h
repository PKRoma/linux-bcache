#ifndef _BCACHE_STR_HASH_H
#define _BCACHE_STR_HASH_H

#include "btree_iter.h"
#include "checksum.h"
#include "siphash.h"

#include <crypto/sha1_base.h>
#include <linux/crc32c.h>

static const SIPHASH_KEY bch_siphash_key = {
	.k0 = cpu_to_le64(0x5a9585fd80087730ULL),
	.k1 = cpu_to_le64(0xc8de666d50b45664ULL ),
};

struct bch_str_hash_ctx {
	union {
		u32			crc32c;
		u64			crc64;
		SIPHASH_CTX		siphash;
		struct shash_desc	sha1;
	};
};

static inline void bch_str_hash_init(struct bch_str_hash_ctx *ctx,
				     enum bch_str_hash_type type)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = ~0;
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = ~0;
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Init(&ctx->siphash, &bch_siphash_key);
		break;
	case BCH_STR_HASH_SHA1:
		sha1_base_init(&ctx->sha1);
		break;
	default:
		BUG();
	}
}

static inline void bch_str_hash_update(struct bch_str_hash_ctx *ctx,
				enum bch_str_hash_type type,
				const void *data, size_t len)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		ctx->crc32c = crc32c(ctx->crc32c, data, len);
		break;
	case BCH_STR_HASH_CRC64:
		ctx->crc64 = bch_crc64_update(ctx->crc64, data, len);
		break;
	case BCH_STR_HASH_SIPHASH:
		SipHash24_Update(&ctx->siphash, data, len);
		break;
	case BCH_STR_HASH_SHA1:
		crypto_sha1_update(&ctx->sha1, data, len);
		break;
	default:
		BUG();
	}
}

static inline u64 bch_str_hash_end(struct bch_str_hash_ctx *ctx,
				   enum bch_str_hash_type type)
{
	switch (type) {
	case BCH_STR_HASH_CRC32C:
		return ctx->crc32c;
	case BCH_STR_HASH_CRC64:
		return ctx->crc64 >> 1;
	case BCH_STR_HASH_SIPHASH:
		return SipHash24_End(&ctx->siphash) >> 1;
	case BCH_STR_HASH_SHA1: {
		u8 out[SHA1_DIGEST_SIZE];
		u64 ret;

		crypto_sha1_finup(&ctx->sha1, NULL, 0, out);
		memcpy(&ret, &out, sizeof(ret));
		return ret >> 1;
	}
	default:
		BUG();
	}
}

struct bch_hash_info {
	u64		seed;
	u8		type;
};

struct bch_hash_desc {
	enum btree_id	btree_id;
	u8		key_type;
	u8		whiteout_type;

	u64		(*hash_key)(const struct bch_hash_info *, const void *);
	u64		(*hash_bkey)(const struct bch_hash_info *, struct bkey_s_c);
	bool		(*cmp_key)(struct bkey_s_c, const void *);
	bool		(*cmp_bkey)(struct bkey_s_c, struct bkey_s_c);
};

static inline struct bkey_s_c
bch_hash_lookup_at(const struct bch_hash_desc desc,
		   const struct bch_hash_info *info,
		   struct btree_iter *iter, const void *search)
{
	struct bkey_s_c k;
	u64 inode = iter->pos.inode;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode != inode)
			break;

		if (k.k->type == desc.key_type) {
			if (!desc.cmp_key(k, search))
				return k;
		} else if (k.k->type == desc.whiteout_type) {
			;
		} else {
			/* hole, not found */
			break;
		}

		bch_btree_iter_advance_pos(iter);
	}

	return bkey_s_c_err(-ENOENT);
}

static inline struct bkey_s_c
bch_hash_lookup_bkey_at(const struct bch_hash_desc desc,
			const struct bch_hash_info *info,
			struct btree_iter *iter, struct bkey_s_c search)
{
	struct bkey_s_c k;
	u64 inode = iter->pos.inode;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode != inode)
			break;

		if (k.k->type == desc.key_type) {
			if (!desc.cmp_bkey(k, search))
				return k;
		} else if (k.k->type == desc.whiteout_type) {
			;
		} else {
			/* hole, not found */
			break;
		}

		bch_btree_iter_advance_pos(iter);
	}

	return bkey_s_c_err(-ENOENT);
}

static inline struct bkey_s_c
bch_hash_lookup(const struct bch_hash_desc desc,
		const struct bch_hash_info *info,
		struct cache_set *c, u64 inode,
		struct btree_iter *iter, const void *key)
{
	bch_btree_iter_init(iter, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)));

	return bch_hash_lookup_at(desc, info, iter, key);
}

static inline struct bkey_s_c
bch_hash_lookup_intent(const struct bch_hash_desc desc,
		       const struct bch_hash_info *info,
		       struct cache_set *c, u64 inode,
		       struct btree_iter *iter, const void *key)
{
	bch_btree_iter_init_intent(iter, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)));

	return bch_hash_lookup_at(desc, info, iter, key);
}

static inline struct bkey_s_c
bch_hash_hole_at(const struct bch_hash_desc desc, struct btree_iter *iter)
{
	struct bkey_s_c k;
	u64 inode = iter->pos.inode;

	while ((k = bch_btree_iter_peek_with_holes(iter)).k) {
		if (k.k->p.inode != inode)
			break;

		if (k.k->type != desc.key_type)
			return k;

		/* hash collision, keep going */
		bch_btree_iter_advance_pos(iter);
	}

	return bkey_s_c_err(-ENOSPC);
}

static inline struct bkey_s_c bch_hash_hole(const struct bch_hash_desc desc,
					    const struct bch_hash_info *info,
					    struct cache_set *c, u64 inode,
					    struct btree_iter *iter,
					    const void *key)
{
	bch_btree_iter_init_intent(iter, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)));

	return bch_hash_hole_at(desc, iter);
}

static inline bool bch_hash_needs_whiteout(const struct bch_hash_desc desc,
					   const struct bch_hash_info *info,
					   struct btree_iter *iter,
					   struct btree_iter *start)
{
	struct bkey_s_c k;

	bch_btree_iter_init_copy(iter, start);

	while (1) {
		bch_btree_iter_advance_pos(iter);
		k = bch_btree_iter_peek_with_holes(iter);

		if (!k.k)
			return iter->error ? true : false;

		if (k.k->type != desc.key_type &&
		    k.k->type != desc.whiteout_type)
			return false;

		if (k.k->type == desc.key_type &&
		    desc.hash_bkey(info, k) <= start->pos.offset)
			return true;
	}
}

#define BCH_HASH_SET_MUST_CREATE	1
#define BCH_HASH_SET_MUST_REPLACE	2

static inline int bch_hash_set(const struct bch_hash_desc desc,
			       const struct bch_hash_info *info,
			       struct cache_set *c, u64 inode,
			       u64 *journal_seq,
			       struct bkey_i *insert, int flags)
{
	struct btree_iter iter, hashed_slot;
	struct bkey_s_c k;
	int ret;

	bch_btree_iter_init_intent(&hashed_slot, c, desc.btree_id,
		POS(inode, desc.hash_bkey(info, bkey_i_to_s_c(insert))));
	bch_btree_iter_init_intent(&iter, c, desc.btree_id, hashed_slot.pos);
	bch_btree_iter_link(&hashed_slot, &iter);

	do {
		ret = bch_btree_iter_traverse(&hashed_slot);
		if (ret)
			break;

		/*
		 * If there's a hash collision and we have to insert at a
		 * different slot, on -EINTR (insert had to drop locks) we have
		 * to recheck the slot we hashed to - it could have been deleted
		 * while we dropped locks:
		 */
		bch_btree_iter_copy(&iter, &hashed_slot);
		k = bch_hash_lookup_bkey_at(desc, info, &iter,
					    bkey_i_to_s_c(insert));
		if (IS_ERR(k.k)) {
			if (flags & BCH_HASH_SET_MUST_REPLACE) {
				ret = -ENOENT;
				goto err;
			}

			/*
			 * Not found, so we're now looking for any open
			 * slot - we might have skipped over a whiteout
			 * that we could have used, so restart from the
			 * slot we hashed to:
			 */
			bch_btree_iter_copy(&iter, &hashed_slot);
			k = bch_hash_hole_at(desc, &iter);
			if (IS_ERR(k.k)) {
				ret = PTR_ERR(k.k);
				goto err;
			}
		} else {
			if (flags & BCH_HASH_SET_MUST_CREATE) {
				ret = -EEXIST;
				goto err;
			}
		}

		insert->k.p = iter.pos;
		ret = bch_btree_insert_at(c, NULL, NULL, journal_seq,
					  BTREE_INSERT_ATOMIC,
					  BTREE_INSERT_ENTRY(&iter, insert));

		/* unlock before traversing hashed_slot: */
		bch_btree_iter_unlock(&iter);
	} while (ret == -EINTR);

	/*
	 * On successful insert, we don't want to clobber ret with error from
	 * iter:
	 */
	bch_btree_iter_unlock(&iter);
	bch_btree_iter_unlock(&hashed_slot);
	return ret;
err:
	ret = bch_btree_iter_unlock(&iter) ?: ret;
	ret = bch_btree_iter_unlock(&hashed_slot) ?: ret;
	return ret;
}

static inline int bch_hash_delete(const struct bch_hash_desc desc,
				  const struct bch_hash_info *info,
				  struct cache_set *c, u64 inode,
				  u64 *journal_seq, const void *key)
{
	struct btree_iter iter, hashed_slot, whiteout_iter;
	struct bkey_s_c k;
	struct bkey_i delete;
	bool needed_whiteout;
	int ret = -ENOENT;

	bch_btree_iter_init_intent(&hashed_slot, c, desc.btree_id,
			    POS(inode, desc.hash_key(info, key)));
	bch_btree_iter_init(&iter, c, 0, POS_MIN);
	bch_btree_iter_link(&hashed_slot, &iter);

	do {
		ret = bch_btree_iter_traverse(&hashed_slot);
		if (ret)
			break;

		bch_btree_iter_copy(&iter, &hashed_slot);
		k = bch_hash_lookup_at(desc, info, &iter, key);
		if (IS_ERR(k.k)) {
			ret = -ENOENT;
			goto err;
		}

		needed_whiteout = bch_hash_needs_whiteout(desc, info,
					&whiteout_iter, &iter);

		bkey_init(&delete.k);
		delete.k.p = k.k->p;
		delete.k.type = needed_whiteout
			? desc.whiteout_type
			: KEY_TYPE_DELETED;

		ret = bch_btree_insert_at(c, NULL, NULL, journal_seq,
					  BTREE_INSERT_NOFAIL|
					  BTREE_INSERT_ATOMIC,
					  BTREE_INSERT_ENTRY(&iter, &delete));
		/*
		 * Need to hold whiteout iter locked while we do the delete, if
		 * we're not leaving a whiteout:
		 */
		bch_btree_iter_unlink(&whiteout_iter);
		bch_btree_iter_unlock(&iter);
	} while (ret == -EINTR);

	if (!ret && !needed_whiteout) {
		struct bpos cleanup = iter.pos;

		cleanup.offset--;

		do {
			if (bkey_cmp(cleanup, hashed_slot.pos) <= 0)
				break;

			bch_btree_iter_copy(&iter, &hashed_slot);
			bch_btree_iter_set_pos(&iter, cleanup);

			k = bch_btree_iter_peek_with_holes(&iter);
			if (k.k->type != desc.whiteout_type)
				break;

			if (bch_hash_needs_whiteout(desc, info,
					&whiteout_iter, &iter))
				break;

			bkey_init(&delete.k);
			delete.k.p = k.k->p;
			delete.k.type = KEY_TYPE_DELETED;

			ret = bch_btree_insert_at(c, NULL, NULL, journal_seq,
					BTREE_INSERT_NOFAIL|BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&iter, &delete));
			bch_btree_iter_unlink(&whiteout_iter);
			bch_btree_iter_unlock(&iter);

			if (!ret)
				cleanup.offset--;
		} while (ret == -EINTR);

		/* don't clobber original success */
		ret = 0;
	}

	bch_btree_iter_unlink(&whiteout_iter);
	bch_btree_iter_unlock(&iter);
	bch_btree_iter_unlock(&hashed_slot);
	return ret;
err:
	ret = bch_btree_iter_unlock(&iter) ?: ret;
	ret = bch_btree_iter_unlock(&hashed_slot) ?: ret;
	return ret;
}

#endif /* _BCACHE_STR_HASH_H */
