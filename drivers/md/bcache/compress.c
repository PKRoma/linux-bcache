#include "bcache.h"
#include "compress.h"
#include "io.h"

#include <linux/lz4.h>
#include <linux/zlib.h>

enum bounced {
	BOUNCED_MAPPED,
	BOUNCED_KMALLOCED,
	BOUNCED_VMALLOCED,
	BOUNCED_MEMPOOLED,
};

static void *__bounce_alloc(struct cache_set *c, unsigned size,
			    unsigned *bounced, int direction)
{
	void *data;

	*bounced = BOUNCED_KMALLOCED;
	data = kmalloc(size, GFP_NOIO|__GFP_NOWARN);
	if (data)
		return data;

	*bounced = BOUNCED_MEMPOOLED;
	data = mempool_alloc(&c->compression_bounce[direction], GFP_NOWAIT);
	if (data)
		return page_address(data);

	*bounced = BOUNCED_VMALLOCED;
	data = vmalloc(size);
	if (data)
		return data;

	*bounced = BOUNCED_MEMPOOLED;
	data = mempool_alloc(&c->compression_bounce[direction], GFP_NOIO);
	return page_address(data);
}

static void *__bio_map_or_bounce(struct cache_set *c,
				 struct bio *bio, struct bvec_iter start,
				 unsigned *bounced, int direction)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned nr_pages = 0;
	struct page *stack_pages[16];
	struct page **pages = NULL;
	bool first = true;
	unsigned prev_end = PAGE_SIZE;
	void *data;

	BUG_ON(bvec_iter_sectors(start) > BCH_COMPRESSED_EXTENT_MAX);

	*bounced = BOUNCED_MAPPED;

	__bio_for_each_segment(bv, bio, iter, start) {
		if ((!first && bv.bv_offset) ||
		    prev_end != PAGE_SIZE)
			goto bounce;

		prev_end = bv.bv_offset + bv.bv_len;
		nr_pages++;
	}

	BUG_ON(DIV_ROUND_UP(start.bi_size, PAGE_SIZE) > nr_pages);

	pages = nr_pages > ARRAY_SIZE(stack_pages)
		? kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOIO)
		: stack_pages;
	if (!pages)
		goto bounce;

	nr_pages = 0;
	__bio_for_each_segment(bv, bio, iter, start)
		pages[nr_pages++] = bv.bv_page;

	data = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (pages != stack_pages)
		kfree(pages);

	return data + bio_iter_offset(bio, start);
bounce:
	data = __bounce_alloc(c, start.bi_size, bounced, direction);

	if (direction == READ)
		memcpy_from_bio(data, bio, start);

	return data;
}

static void *bio_map_or_bounce(struct cache_set *c, struct bio *bio,
			       unsigned *bounced, int direction)
{
	return __bio_map_or_bounce(c, bio, bio->bi_iter, bounced, direction);
}

static void bio_unmap_or_unbounce(struct cache_set *c, void *data,
				  unsigned bounced, int direction)
{
	if (!data)
		return;

	switch (bounced) {
	case BOUNCED_MAPPED:
		vunmap((void *) ((unsigned long) data & PAGE_MASK));
		return;
	case BOUNCED_KMALLOCED:
		kfree(data);
		return;
	case BOUNCED_VMALLOCED:
		vfree(data);
		return;
	case BOUNCED_MEMPOOLED:
		mempool_free(virt_to_page(data), &c->compression_bounce[direction]);
		return;
	}
}

static int __bio_uncompress(struct cache_set *c, struct bio *src,
			    void *dst_data, struct bch_extent_crc64 crc)
{
	void *src_data = NULL;
	unsigned src_bounced;
	size_t src_len = src->bi_iter.bi_size;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret;

	src_data = bio_map_or_bounce(c, src, &src_bounced, READ);

	switch (crc.compression_type) {
	case BCH_COMPRESSION_LZ4:
		ret = lz4_decompress(src_data, &src_len,
				     dst_data, dst_len);
		if (ret) {
			ret = -EIO;
			goto err;
		}
		break;
	case BCH_COMPRESSION_GZIP: {
		void *workspace;
		z_stream strm;

		workspace = kmalloc(zlib_inflate_workspacesize(),
				    GFP_NOIO|__GFP_NOWARN);
		if (!workspace) {
			mutex_lock(&c->zlib_workspace_lock);
			workspace = c->zlib_workspace;
		}

		strm.workspace	= workspace;
		strm.next_in	= src_data;
		strm.avail_in	= src_len;
		strm.next_out	= dst_data;
		strm.avail_out	= dst_len;
		zlib_inflateInit2(&strm, -MAX_WBITS);

		ret = zlib_inflate(&strm, Z_FINISH);

		if (workspace == c->zlib_workspace)
			mutex_unlock(&c->zlib_workspace_lock);
		else
			kfree(workspace);

		if (ret != Z_STREAM_END) {
			ret = -EIO;
			goto err;
		}
		break;
	}
	default:
		BUG();
	}
	ret = 0;
err:
	bio_unmap_or_unbounce(c, src_data, src_bounced, READ);
	return ret;
}

int bch_bio_uncompress_inplace(struct cache_set *c, struct bio *bio,
			       unsigned live_data_sectors,
			       struct bch_extent_crc64 crc)
{
	void *dst_data = NULL;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret = -ENOMEM;

	BUG_ON(DIV_ROUND_UP(live_data_sectors, PAGE_SECTORS) > bio->bi_max_vecs);

	/* XXX mempoolify */
	dst_data = kmalloc(dst_len, GFP_NOIO|__GFP_NOWARN);
	if (!dst_data) {
		dst_data = vmalloc(dst_len);
		if (!dst_data)
			goto err;
	}

	ret = __bio_uncompress(c, bio, dst_data, crc);
	if (ret)
		goto err;

	while (bio->bi_vcnt < DIV_ROUND_UP(live_data_sectors, PAGE_SECTORS)) {
		struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

		bv->bv_page = alloc_page(GFP_NOIO);
		if (!bv->bv_page)
			goto use_mempool;

		bv->bv_len = PAGE_SIZE;
		bv->bv_offset = 0;
		bio->bi_vcnt++;
	}

	bio->bi_iter.bi_size = live_data_sectors << 9;
copy_data:
	memcpy_to_bio(bio, bio->bi_iter, dst_data + (crc.offset << 9));
err:
	kvfree(dst_data);
	return ret;
use_mempool:
	/*
	 * We already allocated from mempool, we can't allocate from it again
	 * without freeing the pages we already allocated or else we could
	 * deadlock:
	 */

	bch_bio_free_pages_pool(c, bio);
	bch_bio_alloc_pages_pool(c, bio, live_data_sectors << 9);
	goto copy_data;
}

int bch_bio_uncompress(struct cache_set *c, struct bio *src,
		       struct bio *dst, struct bvec_iter dst_iter,
		       struct bch_extent_crc64 crc)
{
	void *dst_data = NULL;
	unsigned dst_bounced;
	size_t dst_len = crc.uncompressed_size << 9;
	int ret = -ENOMEM;

	dst_data = dst_len == dst_iter.bi_size
		? __bio_map_or_bounce(c, dst, dst_iter, &dst_bounced, WRITE)
		: __bounce_alloc(c, dst_len, &dst_bounced, WRITE);

	ret = __bio_uncompress(c, src, dst_data, crc);
	if (ret)
		goto err;

	if (dst_bounced)
		memcpy_to_bio(dst, dst_iter, dst_data + (crc.offset << 9));
err:
	bio_unmap_or_unbounce(c, dst_data, dst_bounced, WRITE);
	return ret;
}

static int __bio_compress(struct cache_set *c,
			  struct bio *dst, size_t *dst_len,
			  struct bio *src, size_t *src_len,
			  unsigned compression_type)
{
	void *src_data = NULL, *dst_data = NULL;
	unsigned src_bounced, dst_bounced, pad;
	int ret = -1;

	dst_data = bio_map_or_bounce(c, dst, &dst_bounced, WRITE);
	src_data = bio_map_or_bounce(c, src, &src_bounced, READ);

	switch (compression_type) {
	case BCH_COMPRESSION_LZ4: {
		void *workspace;

		*dst_len = dst->bi_iter.bi_size;
		*src_len = src->bi_iter.bi_size;

		workspace = mempool_alloc(&c->lz4_workspace_pool, GFP_NOIO);
retry_compress:
		ret = lz4_compress(src_data, *src_len,
				   dst_data, dst_len,
				   workspace);
		/*
		 * On error, the compressed data was bigger than dst_len, and
		 * -ret is the amount of data we were able to compress - round
		 * down to nearest block and try again:
		 */
		if (ret && round_down(-ret, block_bytes(c)) > *dst_len) {
			BUG_ON(ret > 0);

			/* not supposed to happen */
			if (WARN_ON(-ret >= *src_len))
				goto err;

			*src_len = round_down(-ret, block_bytes(c));
			if (!*src_len)
				goto err;

			goto retry_compress;
		}
		mempool_free(workspace, &c->lz4_workspace_pool);

		if (ret)
			goto err;
		break;
	}
	case BCH_COMPRESSION_GZIP: {
		void *workspace;
		z_stream strm;

		workspace = kmalloc(zlib_deflate_workspacesize(MAX_WBITS,
							       DEF_MEM_LEVEL),
				    GFP_NOIO|__GFP_NOWARN);
		if (!workspace) {
			mutex_lock(&c->zlib_workspace_lock);
			workspace = c->zlib_workspace;
		}

		strm.workspace	= workspace;
		strm.next_in	= src_data;
		strm.avail_in	= min(src->bi_iter.bi_size,
				      dst->bi_iter.bi_size);
		strm.next_out	= dst_data;
		strm.avail_out	= dst->bi_iter.bi_size;
		zlib_deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
				  Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL,
				  Z_DEFAULT_STRATEGY);

		ret = zlib_deflate(&strm, Z_FINISH);
		if (ret != Z_STREAM_END) {
			ret = -EIO;
			goto zlib_err;
		}

		ret = zlib_deflateEnd(&strm);
		if (ret != Z_OK) {
			ret = -EIO;
			goto zlib_err;
		}

		ret = 0;
zlib_err:
		if (workspace == c->zlib_workspace)
			mutex_unlock(&c->zlib_workspace_lock);
		else
			kfree(workspace);

		if (ret)
			goto err;

		*dst_len = strm.total_out;
		*src_len = strm.total_in;
		break;
	}
	default:
		BUG();
	}

	BUG_ON(!*dst_len);

	/* Didn't get smaller: */
	if (round_up(*dst_len, block_bytes(c)) >= *src_len) {
		ret = -1;
		goto err;
	}

	pad = round_up(*dst_len, block_bytes(c)) - *dst_len;

	memset(dst_data + *dst_len, 0, pad);
	*dst_len += pad;

	if (dst_bounced)
		memcpy_to_bio(dst, dst->bi_iter, dst_data);
err:
	bio_unmap_or_unbounce(c, src_data, src_bounced, READ);
	bio_unmap_or_unbounce(c, dst_data, dst_bounced, WRITE);
	return ret;
}

void bch_bio_compress(struct cache_set *c,
		      struct bio *dst, size_t *dst_len,
		      struct bio *src, size_t *src_len,
		      unsigned *compression_type)
{
	unsigned orig_dst = dst->bi_iter.bi_size;
	unsigned orig_src = src->bi_iter.bi_size;

	/* Don't consume more than BCH_COMPRESSED_EXTENT_MAX from @src: */
	src->bi_iter.bi_size =
		min(src->bi_iter.bi_size, BCH_COMPRESSED_EXTENT_MAX << 9);

	/* Don't generate a bigger output than input: */
	dst->bi_iter.bi_size =
		min(dst->bi_iter.bi_size, src->bi_iter.bi_size);

	/* If it's only one block, don't bother trying to compress: */
	if (*compression_type != BCH_COMPRESSION_NONE &&
	    bio_sectors(src) > c->sb.block_size &&
	    !__bio_compress(c, dst, dst_len, src, src_len, *compression_type))
		goto out;

	/* If compressing failed (didn't get smaller), just copy: */
	*compression_type = BCH_COMPRESSION_NONE;
	*dst_len = *src_len = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);
	bio_copy_data(dst, src);
out:
	dst->bi_iter.bi_size = orig_dst;
	src->bi_iter.bi_size = orig_src;
}

void bch_compress_free(struct cache_set *c)
{
	vfree(c->zlib_workspace);
	mempool_exit(&c->lz4_workspace_pool);
	mempool_exit(&c->compression_bounce[WRITE]);
	mempool_exit(&c->compression_bounce[READ]);
	free_percpu(c->bio_decompress_worker);
}

#define COMPRESSION_WORKSPACE_SIZE					\
	max_t(size_t, zlib_inflate_workspacesize(),			\
	      zlib_deflate_workspacesize(MAX_WBITS, DEF_MEM_LEVEL))

int bch_compress_init(struct cache_set *c)
{
	int ret, cpu;

	c->bio_decompress_worker = alloc_percpu(*c->bio_decompress_worker);
	if (!c->bio_decompress_worker)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct bio_decompress_worker *d =
			per_cpu_ptr(c->bio_decompress_worker, cpu);

		d->c = c;
		INIT_WORK(&d->work, bch_bio_decompress_work);
		init_llist_head(&d->bio_list);
	}

	ret = mempool_init_page_pool(&c->compression_bounce[READ], 1,
				     get_order(BCH_COMPRESSED_EXTENT_MAX << 9));
	if (ret)
		return ret;

	ret = mempool_init_page_pool(&c->compression_bounce[WRITE], 1,
				     get_order(BCH_COMPRESSED_EXTENT_MAX << 9));
	if (ret)
		return ret;

	ret = mempool_init_kmalloc_pool(&c->lz4_workspace_pool, 1,
					LZ4_MEM_COMPRESS);
	if (ret)
		return ret;

	c->zlib_workspace = vmalloc(COMPRESSION_WORKSPACE_SIZE);
	if (!c->zlib_workspace)
		return -ENOMEM;

	return 0;
}
