
#include "bcache.h"
#include "btree_update.h"
#include "buckets.h"
#include "clock.h"
#include "error.h"
#include "fs.h"
#include "fs-gc.h"
#include "fs-io.h"
#include "inode.h"
#include "journal.h"
#include "io.h"
#include "keylist.h"

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>

struct bio_set *bch_writepage_bioset;
struct bio_set *bch_dio_read_bioset;
struct bio_set *bch_dio_write_bioset;

/* i_size updates: */

/*
 * In memory i_size should never be < on disk i_size:
 */
static void bch_i_size_write(struct inode *inode, loff_t new_i_size)
{
	struct bch_inode_info *ei = to_bch_ei(inode);

	EBUG_ON(new_i_size < ei->i_size);
	i_size_write(inode, new_i_size);
}

static int inode_set_size(struct bch_inode_info *ei, struct bch_inode *bi,
			  void *p)
{
	loff_t *new_i_size = p;
	unsigned i_flags = le32_to_cpu(bi->i_flags);

	lockdep_assert_held(&ei->update_lock);

	bi->i_size = cpu_to_le64(*new_i_size);

	if (atomic_long_read(&ei->i_size_dirty_count))
		i_flags |= BCH_INODE_I_SIZE_DIRTY;
	else
		i_flags &= ~BCH_INODE_I_SIZE_DIRTY;

	bi->i_flags = cpu_to_le32(i_flags);

	return 0;
}

static int __must_check bch_write_inode_size(struct cache_set *c,
					     struct bch_inode_info *ei,
					     loff_t new_size)
{
	return __bch_write_inode(c, ei, inode_set_size, &new_size);
}

static int inode_set_dirty(struct bch_inode_info *ei,
			   struct bch_inode *bi, void *p)
{
	bi->i_flags = cpu_to_le32(le32_to_cpu(bi->i_flags)|
				  BCH_INODE_I_SIZE_DIRTY);
	return 0;
}

static int check_make_i_size_dirty(struct bch_inode_info *ei, loff_t offset)
{
	bool need_set_dirty;
	unsigned seq;
	int ret = 0;

	do {
		seq = read_seqcount_begin(&ei->shadow_i_size_lock);
		need_set_dirty = offset > round_up(ei->i_size, PAGE_SIZE) &&
			!(ei->i_flags & BCH_INODE_I_SIZE_DIRTY);
	} while (read_seqcount_retry(&ei->shadow_i_size_lock, seq));

	if (!need_set_dirty)
		return 0;

	mutex_lock(&ei->update_lock);

	/* recheck under lock.. */

	if (offset > round_up(ei->i_size, PAGE_SIZE) &&
	    !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY)) {
		struct cache_set *c = ei->vfs_inode.i_sb->s_fs_info;

		BUG_ON(!atomic_long_read(&ei->i_size_dirty_count));

		ret = __bch_write_inode(c, ei, inode_set_dirty, NULL);
	}

	mutex_unlock(&ei->update_lock);

	return ret;
}

static inline void i_size_dirty_put(struct bch_inode_info *ei)
{
	atomic_long_dec_bug(&ei->i_size_dirty_count);
}

static inline void i_size_dirty_get(struct bch_inode_info *ei)
{
	lockdep_assert_held(&ei->vfs_inode.i_rwsem);

	atomic_long_inc(&ei->i_size_dirty_count);
}

static void i_size_update_put(struct cache_set *c, struct bch_inode_info *ei,
			      unsigned idx, unsigned long count)
{
	struct i_size_update *u = &ei->i_size_updates.data[idx];
	loff_t new_i_size = -1;
	long r;

	if (!count)
		return;

	r = atomic_long_sub_return(count, &u->count);
	BUG_ON(r < 0);

	if (r)
		return;

	/*
	 * Flush i_size_updates entries in order - from the end of the fifo -
	 * if the entry at the end is finished (refcount has gone to 0):
	 */

	mutex_lock(&ei->update_lock);

	while (!fifo_empty(&ei->i_size_updates) &&
	       !atomic_long_read(&(u = &fifo_front(&ei->i_size_updates))->count)) {
		struct i_size_update t;

		i_size_dirty_put(ei);

		if (u->new_i_size != -1) {
			BUG_ON(u->new_i_size < ei->i_size);
			new_i_size = u->new_i_size;
		}

		fifo_pop(&ei->i_size_updates, t);
	}

	if (new_i_size != -1) {
		int ret = bch_write_inode_size(c, ei, new_i_size);

		ret = ret;
		/*
		 * XXX: need to pin the inode in memory if the inode update
		 * fails
		 */
	}

	mutex_unlock(&ei->update_lock);
}

static struct i_size_update *i_size_update_new(struct bch_inode_info *ei,
					       loff_t new_size)
{
	struct i_size_update *u;

	lockdep_assert_held(&ei->update_lock);

	if (fifo_empty(&ei->i_size_updates) ||
	    (test_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags) &&
	     !fifo_full(&ei->i_size_updates))) {
		clear_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
		fifo_push(&ei->i_size_updates,
			  (struct i_size_update) { 0 });

		u = &fifo_back(&ei->i_size_updates);
		atomic_long_set(&u->count, 0);
		i_size_dirty_get(ei);
	}

	u = &fifo_back(&ei->i_size_updates);
	u->new_i_size = new_size;

	return u;
}

/* i_sectors accounting: */

static void i_sectors_hook_fn(struct btree_insert_hook *hook,
			      struct btree_iter *iter,
			      struct bkey_s_c k,
			      struct bkey_i *insert,
			      struct journal_res *res)
{
	struct i_sectors_hook *h = container_of(hook,
				struct i_sectors_hook, hook);

	EBUG_ON(h->ei->vfs_inode.i_ino != insert->k.p.inode);
	EBUG_ON(!(h->ei->i_flags & BCH_INODE_I_SECTORS_DIRTY));
	EBUG_ON(!atomic_long_read(&h->ei->i_sectors_dirty_count));

	if (k.k) {
		if (!bkey_extent_is_allocation(k.k))
			return;

		switch (bch_extent_overlap(&insert->k, k.k)) {
		case BCH_EXTENT_OVERLAP_FRONT:
			h->sectors -= insert->k.p.offset - bkey_start_offset(k.k);
			break;

		case BCH_EXTENT_OVERLAP_BACK:
			h->sectors -= k.k->p.offset - bkey_start_offset(&insert->k);
			break;

		case BCH_EXTENT_OVERLAP_ALL:
			h->sectors -= k.k->size;
			break;

		case BCH_EXTENT_OVERLAP_MIDDLE:
			h->sectors -= insert->k.size;
			break;
		}
	} else {
		if (!bkey_extent_is_allocation(&insert->k))
			return;

#ifdef CONFIG_BCACHE_DEBUG
		if (!(insert->k.type == BCH_RESERVATION)) {
			struct bch_inode_info *ei = h->ei;
			unsigned seq;
			bool bad_write;

			do {
				seq = read_seqcount_begin(&ei->shadow_i_size_lock);
				bad_write = !(ei->i_flags & BCH_INODE_I_SIZE_DIRTY) &&
					insert->k.p.offset >
					(round_up(ei->i_size, PAGE_SIZE) >> 9);
			} while (read_seqcount_retry(&ei->shadow_i_size_lock, seq));

			BUG_ON(bad_write);
		}
#endif
		h->sectors += insert->k.size;
	}
}

static int inode_set_i_sectors_dirty(struct bch_inode_info *ei,
				    struct bch_inode *bi, void *p)
{
	BUG_ON(le32_to_cpu(bi->i_flags) & BCH_INODE_I_SECTORS_DIRTY);

	bi->i_flags = cpu_to_le32(le32_to_cpu(bi->i_flags)|
				  BCH_INODE_I_SECTORS_DIRTY);
	return 0;
}

static int inode_clear_i_sectors_dirty(struct bch_inode_info *ei,
				       struct bch_inode *bi, void *p)
{
	BUG_ON(!(le32_to_cpu(bi->i_flags) & BCH_INODE_I_SECTORS_DIRTY));

	bi->i_sectors	= cpu_to_le64(atomic64_read(&ei->i_sectors));
	bi->i_flags	= cpu_to_le32(le32_to_cpu(bi->i_flags) &
				      ~BCH_INODE_I_SECTORS_DIRTY);
	return 0;
}

static void __i_sectors_dirty_put(struct bch_inode_info *ei,
				  struct i_sectors_hook *h)
{
	if (h->sectors) {
		atomic64_add(h->sectors, &ei->i_sectors);

		EBUG_ON(atomic64_read(&ei->i_sectors) < 0);
	}

	EBUG_ON(atomic_long_read(&ei->i_sectors_dirty_count) <= 0);

	mutex_lock(&ei->update_lock);

	if (atomic_long_dec_and_test(&ei->i_sectors_dirty_count)) {
		struct cache_set *c = ei->vfs_inode.i_sb->s_fs_info;
		int ret = __bch_write_inode(c, ei, inode_clear_i_sectors_dirty, NULL);

		ret = ret;
	}

	mutex_unlock(&ei->update_lock);
}

static void i_sectors_dirty_put(struct bch_inode_info *ei,
				struct i_sectors_hook *h)
{
	struct inode *inode = &ei->vfs_inode;

	if (h->sectors) {
		spin_lock(&inode->i_lock);
		inode->i_blocks += h->sectors;
		spin_unlock(&inode->i_lock);
	}

	__i_sectors_dirty_put(ei, h);
}

static int __must_check i_sectors_dirty_get(struct bch_inode_info *ei,
					    struct i_sectors_hook *h)
{
	int ret = 0;

	h->hook.fn	= i_sectors_hook_fn;
	h->sectors	= 0;
#ifdef CONFIG_BCACHE_DEBUG
	h->ei		= ei;
#endif

	if (atomic_long_inc_not_zero(&ei->i_sectors_dirty_count))
		return 0;

	mutex_lock(&ei->update_lock);

	if (!(ei->i_flags & BCH_INODE_I_SECTORS_DIRTY)) {
		struct cache_set *c = ei->vfs_inode.i_sb->s_fs_info;

		ret = __bch_write_inode(c, ei, inode_set_i_sectors_dirty, NULL);
	}

	if (!ret)
		atomic_long_inc(&ei->i_sectors_dirty_count);

	mutex_unlock(&ei->update_lock);

	return ret;
}

/* page state: */

/* stored in page->private: */

/*
 * bch_page_state has to (unfortunately) be manipulated with cmpxchg - we could
 * almost protected it with the page lock, except that bch_writepage_io_done has
 * to update the sector counts (and from interrupt/bottom half context).
 */
struct bch_page_state {
union { struct {
	/*
	 * BCH_PAGE_ALLOCATED: page is _fully_ written on disk, and not
	 * compressed - which means to write this page we don't have to reserve
	 * space (the new write will never take up more space on disk than what
	 * it's overwriting)
	 *
	 * BCH_PAGE_UNALLOCATED: page is not fully written on disk, or is
	 * compressed - before writing we have to reserve space with
	 * bch_reserve_sectors()
	 *
	 * BCH_PAGE_RESERVED: page has space reserved on disk (reservation will
	 * be consumed when the page is written).
	 */
	enum {
		BCH_PAGE_UNALLOCATED	= 0,
		BCH_PAGE_ALLOCATED,
		BCH_PAGE_RESERVED,
	}			alloc_state:2;

	/*
	 * append: if true, when we wrote to this page we extended i_size; thus,
	 * the update of the on disk i_size needs to know when this page is
	 * written (because we can't extend i_size on disk until the
	 * corresponding data writes have completed)
	 *
	 * append_idx points to the corresponding i_size_update, in
	 * bch_inode_info
	 */
	unsigned		append:1;
	unsigned		append_idx:I_SIZE_UPDATE_ENTRIES_BITS;

	/*
	 * Number of sectors on disk - for i_blocks
	 * Uncompressed size, not compressed size:
	 */
	u8			sectors;
	u8			dirty_sectors;
};
	/* for cmpxchg: */
	unsigned long		v;
};
};

#define page_state_cmpxchg(_ptr, _new, _expr)				\
({									\
	unsigned long _v = READ_ONCE((_ptr)->v);			\
	struct bch_page_state _old;					\
									\
	do {								\
		_old.v = _new.v = _v;					\
		_expr;							\
									\
		EBUG_ON(_new.sectors + _new.dirty_sectors > PAGE_SECTORS);\
	} while (_old.v != _new.v &&					\
		 (_v = cmpxchg(&(_ptr)->v, _old.v, _new.v)) != _old.v);	\
									\
	_old;								\
})

static inline struct bch_page_state *page_state(struct page *page)
{
	struct bch_page_state *s = (void *) &page->private;

	BUILD_BUG_ON(sizeof(*s) > sizeof(page->private));

	if (!PagePrivate(page))
		SetPagePrivate(page);

	return s;
}

static void bch_put_page_reservation(struct cache_set *c, struct page *page)
{
	struct bch_page_state s;

	s = page_state_cmpxchg(page_state(page), s, {
		if (s.alloc_state == BCH_PAGE_RESERVED)
			s.alloc_state = BCH_PAGE_UNALLOCATED;
	});

	if (s.alloc_state == BCH_PAGE_RESERVED)
		atomic64_sub_bug(PAGE_SECTORS, &c->sectors_reserved);
}

static int bch_get_page_reservation(struct cache_set *c, struct page *page)
{
	struct bch_page_state *s = page_state(page), old, new;
	int ret = 0;

	if (s->alloc_state != BCH_PAGE_UNALLOCATED)
		return 0;

	ret = bch_reserve_sectors(c, PAGE_SECTORS);
	if (ret)
		return ret;

	old = page_state_cmpxchg(s, new, new.alloc_state = BCH_PAGE_RESERVED);

	BUG_ON(old.alloc_state != BCH_PAGE_UNALLOCATED);

	return ret;
}

static void bch_clear_page_bits(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_page_state s;

	if (!PagePrivate(page))
		return;

	s = xchg(page_state(page), (struct bch_page_state) { .v = 0 });
	ClearPagePrivate(page);

	if (s.dirty_sectors) {
		spin_lock(&inode->i_lock);
		inode->i_blocks -= s.dirty_sectors;
		spin_unlock(&inode->i_lock);
	}

	if (s.alloc_state == BCH_PAGE_RESERVED)
		atomic64_sub_bug(PAGE_SECTORS, &c->sectors_reserved);

	if (s.append)
		i_size_update_put(c, ei, s.append_idx, 1);
}

int bch_set_page_dirty(struct page *page)
{
	struct bch_page_state old, new;

#ifdef CONFIG_BCACHE_DEBUG
	{
		struct bch_inode_info *ei = to_bch_ei(page->mapping->host);
		unsigned seq, i_flags;
		u64 i_size;

		do {
			seq = read_seqcount_begin(&ei->shadow_i_size_lock);
			i_size = ei->i_size;
			i_flags = ei->i_flags;
		} while (read_seqcount_retry(&ei->shadow_i_size_lock, seq));

		BUG_ON(((page_offset(page) + PAGE_SIZE) >
			round_up(i_size, PAGE_SIZE)) &&
		       !(i_flags & BCH_INODE_I_SIZE_DIRTY) &&
		       !atomic_long_read(&ei->i_size_dirty_count));
	}
#endif

	old = page_state_cmpxchg(page_state(page), new,
		new.dirty_sectors = PAGE_SECTORS - new.sectors;
	);

	if (old.dirty_sectors != new.dirty_sectors) {
		struct inode *inode = page->mapping->host;

		spin_lock(&inode->i_lock);
		inode->i_blocks += new.dirty_sectors - old.dirty_sectors;
		spin_unlock(&inode->i_lock);
	}

	return __set_page_dirty_nobuffers(page);
}

/* readpages/writepages: */

static int bch_bio_add_page(struct bio *bio, struct page *page)
{
	sector_t offset = (sector_t) page->index << (PAGE_SHIFT - 9);

	BUG_ON(!bio->bi_max_vecs);

	if (!bio->bi_vcnt)
		bio->bi_iter.bi_sector = offset;
	else if (bio_end_sector(bio) != offset ||
		 bio->bi_vcnt == bio->bi_max_vecs)
		return -1;

	bio->bi_io_vec[bio->bi_vcnt++] = (struct bio_vec) {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};

	bio->bi_iter.bi_size += PAGE_SIZE;

	return 0;
}

static void bch_readpages_end_io(struct bio *bio)
{
	struct bio_vec *bv;
	int i;

	bio_for_each_segment_all(bv, bio, i) {
		struct page *page = bv->bv_page;

		if (!bio->bi_error) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	}

	bio_put(bio);
}

static inline struct page *__readpage_next_page(struct address_space *mapping,
						struct list_head *pages,
						unsigned *nr_pages)
{
	struct page *page;
	int ret;

	while (*nr_pages) {
		page = list_entry(pages->prev, struct page, lru);
		prefetchw(&page->flags);
		list_del(&page->lru);

		ret = add_to_page_cache_lru(page, mapping, page->index, GFP_NOFS);

		/* if add_to_page_cache_lru() succeeded, page is locked: */
		put_page(page);

		if (!ret)
			return page;

		(*nr_pages)--;
	}

	return NULL;
}

#define for_each_readpage_page(_mapping, _pages, _nr_pages, _page)	\
	for (;								\
	     ((_page) = __readpage_next_page(_mapping, _pages, &(_nr_pages)));\
	     (_nr_pages)--)

static void bch_mark_pages_unalloc(struct bio *bio)
{
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter)
		page_state(bv.bv_page)->alloc_state = BCH_PAGE_UNALLOCATED;
}

static void bch_add_page_sectors(struct bio *bio, const struct bkey *k)
{
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter) {
		struct bch_page_state *s = page_state(bv.bv_page);

		/* sectors in @k from the start of this page: */
		unsigned k_sectors = k->size - (iter.bi_sector - k->p.offset);

		unsigned page_sectors = min(bv.bv_len >> 9, k_sectors);

		BUG_ON(s->sectors + page_sectors > PAGE_SECTORS);

		s->sectors += page_sectors;
	}
}

static void bchfs_read(struct cache_set *c, struct bio *bio, u64 inode)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct bio_vec *bv;
	unsigned i;

	bch_increment_clock(c, bio_sectors(bio), READ);

	/*
	 * Initialize page state:
	 * If a page is partly allocated and partly a hole, we want it to be
	 * marked BCH_PAGE_UNALLOCATED - so we initially mark all pages
	 * allocated and then mark them unallocated as we find holes:
	 *
	 * Note that the bio hasn't been split yet - it's the only bio that
	 * points to these pages. As we walk extents and split @bio, that
	 * necessarily be true, the splits won't necessarily be on page
	 * boundaries:
	 */
	bio_for_each_segment_all(bv, bio, i) {
		struct bch_page_state *s = page_state(bv->bv_page);

		EBUG_ON(s->alloc_state == BCH_PAGE_RESERVED);

		s->alloc_state = BCH_PAGE_ALLOCATED;
		s->sectors = 0;
	}

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bio->bi_iter.bi_sector), k) {
		struct extent_pick_ptr pick;
		unsigned bytes, sectors;
		bool is_last;

		bch_extent_pick_ptr(c, k, &pick);
		bch_btree_iter_unlock(&iter);

		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bio_endio(bio);
			return;
		}

		sectors = min_t(u64, k.k->p.offset,
				bio_end_sector(bio)) -
			bio->bi_iter.bi_sector;
		bytes = sectors << 9;
		is_last = bytes == bio->bi_iter.bi_size;
		swap(bio->bi_iter.bi_size, bytes);

		if (!(k.k->type == BCH_RESERVATION ||
		      (pick.ca &&
		       pick.crc.compression_type == BCH_COMPRESSION_NONE)))
			bch_mark_pages_unalloc(bio);

		if (bkey_extent_is_allocation(k.k))
			bch_add_page_sectors(bio, k.k);

		if (pick.ca) {
			PTR_BUCKET(pick.ca, &pick.ptr)->read_prio =
				c->prio_clock[READ].hand;

			bch_read_extent(c, bio, k, &pick,
					bio->bi_iter.bi_sector -
					bkey_start_offset(k.k),
					BCH_READ_FORCE_BOUNCE|
					BCH_READ_RETRY_IF_STALE|
					BCH_READ_PROMOTE|
					(is_last ? BCH_READ_IS_LAST : 0));
		} else {
			zero_fill_bio_iter(bio, bio->bi_iter);

			if (is_last)
				bio_endio(bio);
		}

		if (is_last)
			return;

		swap(bio->bi_iter.bi_size, bytes);
		bio_advance(bio, bytes);
	}

	/*
	 * If we get here, it better have been because there was an error
	 * reading a btree node
	 */
	BUG_ON(!bch_btree_iter_unlock(&iter));
	bcache_io_error(c, bio, "btree IO error");
	bio_endio(bio);
}

int bch_readpages(struct file *file, struct address_space *mapping,
		  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = NULL;
	struct page *page;

	pr_debug("reading %u pages", nr_pages);

	for_each_readpage_page(mapping, pages, nr_pages, page) {
again:
		if (!bio) {
			bio = bio_alloc(GFP_NOFS,
					min_t(unsigned, nr_pages,
					      BIO_MAX_PAGES));

			bio->bi_end_io = bch_readpages_end_io;
		}

		if (bch_bio_add_page(bio, page)) {
			bchfs_read(c, bio, inode->i_ino);
			bio = NULL;
			goto again;
		}
	}

	if (bio)
		bchfs_read(c, bio, inode->i_ino);

	pr_debug("success");
	return 0;
}

int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_rw = READ_SYNC;
	bio->bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(bio, page);
	bchfs_read(c, bio, inode->i_ino);

	return 0;
}

struct bch_writepage {
	struct cache_set	*c;
	u64			inum;
	struct bch_writepage_io	*io;
};

static void bch_writepage_io_free(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct bio *bio = &io->bio.bio.bio;

	bio_put(bio);
}

static void bch_writepage_io_done(struct closure *cl)
{
	struct bch_writepage_io *io = container_of(cl,
					struct bch_writepage_io, cl);
	struct cache_set *c = io->op.c;
	struct bio *bio = &io->bio.bio.bio;
	struct bch_inode_info *ei = io->ei;
	struct bio_vec *bvec;
	unsigned i;

	atomic64_sub_bug(io->sectors_reserved, &c->sectors_reserved);

	for (i = 0; i < ARRAY_SIZE(io->i_size_update_count); i++)
		i_size_update_put(c, ei, i, io->i_size_update_count[i]);

	__i_sectors_dirty_put(ei, &io->i_sectors_hook);

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (io->op.error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		} else {
			struct bch_page_state old, new;

			old = page_state_cmpxchg(page_state(page), new, {
				new.sectors += new.dirty_sectors;
				new.dirty_sectors = 0;
			});

			io->i_sectors_hook.sectors -= old.dirty_sectors;
		}
	}

	/*
	 * PageWriteback is effectively our ref on the inode - fixup i_blocks
	 * before calling end_page_writeback:
	 */
	if (!io->op.error && io->i_sectors_hook.sectors) {
		struct inode *inode = &io->ei->vfs_inode;

		spin_lock(&inode->i_lock);
		inode->i_blocks += io->i_sectors_hook.sectors;
		spin_unlock(&inode->i_lock);
	}

	bio_for_each_segment_all(bvec, bio, i)
		end_page_writeback(bvec->bv_page);

	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	pr_debug("writing %u sectors to %llu:%llu",
		 bio_sectors(&io->bio.bio.bio),
		 io->op.insert_key.k.p.inode,
		 (u64) io->bio.bio.bio.bi_iter.bi_sector);

	closure_call(&io->op.cl, bch_write, NULL, &io->cl);
	continue_at(&io->cl, bch_writepage_io_done, io->op.c->wq);
}

/*
 * Get a bch_writepage_io and add @page to it - appending to an existing one if
 * possible, else allocating a new one:
 */
static void bch_writepage_io_alloc(struct bch_writepage *w,
				   struct bch_inode_info *ei,
				   struct page *page)
{
alloc_io:
	if (!w->io) {
		struct bio *bio = bio_alloc_bioset(GFP_NOFS, BIO_MAX_PAGES,
						   bch_writepage_bioset);
		int ret;

		w->io = container_of(bio, struct bch_writepage_io, bio.bio.bio);

		closure_init(&w->io->cl, NULL);
		w->io->ei		= ei;
		memset(w->io->i_size_update_count, 0,
		       sizeof(w->io->i_size_update_count));
		w->io->sectors_reserved	= 0;

		ret = i_sectors_dirty_get(ei, &w->io->i_sectors_hook);
		/*
		 * i_sectors_dirty_get() will only return an error if it failed
		 * to set the I_SECTORS_DIRTY flag - however, we're already
		 * holding a ref (in bch_writepage() or bch_writepages()) so
		 * the flag must already be set:
		 */
		BUG_ON(ret);

		bch_write_op_init(&w->io->op, w->c, &w->io->bio, NULL,
				  bkey_to_s_c(&KEY(w->inum, 0, 0)),
				  &w->io->i_sectors_hook.hook,
				  &ei->journal_seq, 0);
	}

	if (bch_bio_add_page(&w->io->bio.bio.bio, page)) {
		bch_writepage_do_io(w->io);
		w->io = NULL;
		goto alloc_io;
	}

	/*
	 * We shouldn't ever be handed pages for multiple inodes in a single
	 * pass - right?
	 */
	BUG_ON(ei != w->io->ei);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_writepage *w = data;
	struct bch_page_state old, new;
	unsigned offset;
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_SHIFT;

	EBUG_ON(!PageUptodate(page));

	/* Is the page fully inside i_size? */
	if (page->index < end_index)
		goto do_io;

	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_SIZE - 1);
	if (page->index > end_index || !offset) {
		unlock_page(page);
		return 0;
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, offset, PAGE_SIZE);
do_io:
	if (check_make_i_size_dirty(ei, page_offset(page) + PAGE_SIZE)) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	bch_writepage_io_alloc(w, ei, page);

	if (wbc->sync_mode == WB_SYNC_ALL)
		w->io->bio.bio.bio.bi_rw |= WRITE_SYNC;

	/*
	 * Before unlocking the page, transfer refcounts to w->io:
	 */
	old = page_state_cmpxchg(page_state(page), new, {
		new.append = 0;
		new.alloc_state = w->io->op.compression_type == BCH_COMPRESSION_NONE
			? BCH_PAGE_ALLOCATED
			: BCH_PAGE_UNALLOCATED;
	});

	if (old.append) {
		/*
		 * i_size won't get updated and this write's data made visible
		 * until the i_size_update this page points to completes - so
		 * tell the write path to start a new one:
		 */
		if (&ei->i_size_updates.data[old.append_idx] ==
		    &fifo_back(&ei->i_size_updates))
			set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);

		w->io->i_size_update_count[old.append_idx]++;
	}

	BUG_ON(old.alloc_state == BCH_PAGE_UNALLOCATED);

	if (old.alloc_state == BCH_PAGE_RESERVED)
		w->io->sectors_reserved += PAGE_SECTORS;

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

int bch_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct bch_inode_info *ei = to_bch_ei(mapping->host);
	struct i_sectors_hook i_sectors_hook;
	struct bch_writepage w = {
		.c	= mapping->host->i_sb->s_fs_info,
		.inum	= mapping->host->i_ino,
		.io	= NULL,
	};
	int ret;

	ret = i_sectors_dirty_get(ei, &i_sectors_hook);
	if (ret)
		return ret;

	ret = write_cache_pages(mapping, wbc, __bch_writepage, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

	i_sectors_dirty_put(ei, &i_sectors_hook);

	return ret;
}

int bch_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct i_sectors_hook i_sectors_hook;
	struct bch_writepage w = {
		.c = inode->i_sb->s_fs_info,
		.inum = inode->i_ino,
		.io = NULL,
	};
	int ret;

	ret = i_sectors_dirty_get(ei, &i_sectors_hook);
	if (ret)
		return ret;

	ret = __bch_writepage(page, wbc, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

	i_sectors_dirty_put(ei, &i_sectors_hook);

	return ret;
}

static void bch_read_single_page_end_io(struct bio *bio)
{
	complete(bio->bi_private);
}

static int bch_read_single_page(struct page *page,
				struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio;
	int ret = 0;
	DECLARE_COMPLETION_ONSTACK(done);

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_rw = READ_SYNC;
	bio->bi_private = &done;
	bio->bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(bio, page);

	bchfs_read(c, bio, inode->i_ino);
	wait_for_completion(&done);

	if (!ret)
		ret = bio->bi_error;
	bio_put(bio);

	if (ret < 0)
		return ret;

	SetPageUptodate(page);

	return 0;
}

int bch_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_SHIFT;
	unsigned offset = pos & (PAGE_SIZE - 1);
	struct page *page;
	int ret = 0;

	BUG_ON(inode_unhashed(mapping->host));

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	if (PageUptodate(page))
		goto out;

	/* If we're writing entire page, don't need to read it in first: */
	if (len == PAGE_SIZE)
		goto out;

	if (!offset && pos + len >= inode->i_size) {
		zero_user_segment(page, len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}

	if (index > inode->i_size >> PAGE_SHIFT) {
		zero_user_segments(page, 0, offset, offset + len, PAGE_SIZE);
		flush_dcache_page(page);
		goto out;
	}
readpage:
	ret = bch_read_single_page(page, mapping);
	if (ret)
		goto err;
out:
	ret = bch_get_page_reservation(c, page);
	if (ret) {
		if (!PageUptodate(page)) {
			/*
			 * If the page hasn't been read in, we won't know if we actually
			 * need a reservation - we don't actually need to read here, we
			 * just need to check if the page is fully backed by
			 * uncompressed data:
			 */
			goto readpage;
		}

		goto err;
	}

	*pagep = page;
	return ret;
err:
	unlock_page(page);
	put_page(page);
	*pagep = NULL;
	return ret;
}

int bch_write_end(struct file *filp, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_page_state *s = page_state(page);

	lockdep_assert_held(&inode->i_rwsem);
	BUG_ON(s->alloc_state == BCH_PAGE_UNALLOCATED);

	if (unlikely(copied < len && !PageUptodate(page))) {
		/*
		 * The page needs to be read in, but that would destroy
		 * our partial write - simplest thing is to just force
		 * userspace to redo the write:
		 *
		 * userspace doesn't _have_ to redo the write, so clear
		 * PageAllocated:
		 */
		copied = 0;
		zero_user(page, 0, PAGE_SIZE);
		flush_dcache_page(page);
		bch_put_page_reservation(c, page);
		goto out;
	}

	if (pos + copied > inode->i_size) {
		struct bch_page_state old, new;
		struct i_size_update *u;

		/*
		 * if page already has a ref on a i_size_update, even if it's an
		 * older one, leave it - they have to be flushed in order so
		 * that's just as good as taking a ref on a newer one, if we're
		 * adding a newer one now
		 *
		 * - if there's no current i_size_update, or if we want to
		 *   create a new one and there's room for a new one, create it
		 *
		 * - set current i_size_update's i_size to new i_size
		 *
		 * - if !PageAppend, take a ref on the current i_size_update
		 */

		/* XXX: locking */
		mutex_lock(&ei->update_lock);
		u = i_size_update_new(ei, pos + copied);

		old = page_state_cmpxchg(s, new,
			if (!new.append) {
				new.append	= 1;
				new.append_idx	= u - ei->i_size_updates.data;
			}
		);

		if (!old.append)
			atomic_long_inc(&u->count);

		bch_i_size_write(inode, pos + copied);
		mutex_unlock(&ei->update_lock);
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (!PageDirty(page))
		set_page_dirty(page);
out:
	unlock_page(page);
	put_page(page);

	return copied;
}

/* O_DIRECT */

static void bch_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret, 0);
	bio_put(&dio->bio);
}

static void bch_direct_IO_read_endio(struct bio *bio)
{
	struct dio_read *dio = bio->bi_private;

	if (bio->bi_error)
		dio->ret = bio->bi_error;

	closure_put(&dio->cl);
	bio_check_pages_dirty(bio);	/* transfers ownership */
}

static int bch_direct_IO_read(struct cache_set *c, struct kiocb *req,
			      struct file *file, struct inode *inode,
			      struct iov_iter *iter, loff_t offset)
{
	struct dio_read *dio;
	struct bio *bio;
	unsigned long inum = inode->i_ino;
	ssize_t ret = 0;
	size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);
	bool sync = is_sync_kiocb(req);
	loff_t i_size;

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_read_bioset);
	bio_get(bio);

	dio = container_of(bio, struct dio_read, bio);
	closure_init(&dio->cl, NULL);

	/*
	 * this is a _really_ horrible hack just to avoid an atomic sub at the
	 * end:
	 */
	if (!sync) {
		set_closure_fn(&dio->cl, bch_dio_read_complete, NULL);
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER -
			   CLOSURE_RUNNING +
			   CLOSURE_DESTRUCTOR);
	} else {
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER + 1);
	}

	dio->req	= req;
	dio->ret	= iter->count;

	i_size = i_size_read(inode);
	if (offset + dio->ret > i_size) {
		dio->ret = max_t(loff_t, 0, i_size - offset);
		iter->count = round_up(dio->ret, PAGE_SIZE);
	}

	if (!dio->ret) {
		closure_put(&dio->cl);
		goto out;
	}

	goto start;
	while (iter->count) {
		pages = iov_iter_npages(iter, BIO_MAX_PAGES);
		bio = bio_alloc(GFP_KERNEL, pages);
start:
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_end_io		= bch_direct_IO_read_endio;
		bio->bi_private		= dio;

		ret = bio_get_user_pages(bio, iter, 1);
		if (ret < 0) {
			/* XXX: fault inject this path */
			bio->bi_error = ret;
			bio_endio(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;
		bio_set_pages_dirty(bio);

		if (iter->count)
			closure_get(&dio->cl);

		bch_read(c, bio, inum);
	}
out:
	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_put(&dio->bio);
		return ret;
	} else {
		return -EIOCBQUEUED;
	}
}

static void __bch_dio_write_complete(struct dio_write *dio)
{
	struct inode *inode = dio->req->ki_filp->f_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;

	atomic64_sub_bug(dio->nr_sectors, &c->sectors_reserved);

	i_sectors_dirty_put(ei, &dio->i_sectors_hook);

	inode_dio_end(dio->req->ki_filp->f_inode);

	if (dio->iovec && dio->iovec != dio->inline_vecs)
		kfree(dio->iovec);

	bio_put(&dio->bio.bio.bio);
}

static void bch_dio_write_complete(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);
	struct kiocb *req = dio->req;
	long ret = dio->written ?: dio->error;

	__bch_dio_write_complete(dio);
	req->ki_complete(req, ret, 0);
}

static void bch_dio_write_done(struct dio_write *dio)
{
	struct bio_vec *bv;
	int i;

	dio->written += dio->iop.written << 9;

	if (dio->iop.error)
		dio->error = dio->iop.error;

	bio_for_each_segment_all(bv, &dio->bio.bio.bio, i)
		put_page(bv->bv_page);

	if (dio->iter.count)
		bio_reset(&dio->bio.bio.bio);
}

static void bch_do_direct_IO_write(struct dio_write *dio, bool sync)
{
	struct file *file = dio->req->ki_filp;
	struct inode *inode = file->f_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bio *bio = &dio->bio.bio.bio;
	unsigned flags = 0;
	int ret;

	if (file->f_flags & O_DSYNC || IS_SYNC(file->f_mapping->host))
		flags |= BCH_WRITE_FLUSH;

	while (dio->iter.count) {
		bio->bi_iter.bi_sector = (dio->offset + dio->written) >> 9;

		ret = bio_get_user_pages(bio, &dio->iter, 0);
		if (ret < 0) {
			dio->error = ret;
			break;
		}

		bch_write_op_init(&dio->iop, c, &dio->bio, NULL,
				  bkey_to_s_c(&KEY(inode->i_ino,
						   bio_end_sector(bio),
						   bio_sectors(bio))),
				  &dio->i_sectors_hook.hook,
				  &ei->journal_seq, flags);

		task_io_account_write(bio->bi_iter.bi_size);

		closure_call(&dio->iop.cl, bch_write, NULL, &dio->cl);

		if (!sync)
			break;

		closure_sync(&dio->cl);
		bch_dio_write_done(dio);
	}
}

static void bch_dio_write_loop_async(struct closure *cl)
{
	struct dio_write *dio =
		container_of(cl, struct dio_write, cl);

	bch_dio_write_done(dio);

	if (dio->iter.count && !dio->error) {
		use_mm(dio->mm);
		bch_do_direct_IO_write(dio, false);
		unuse_mm(dio->mm);

		continue_at(&dio->cl,
			    bch_dio_write_loop_async,
			    dio->iter.count ? system_wq : NULL);
	} else {
#if 0
		closure_return_with_destructor(cl, bch_dio_write_complete);
#else
		closure_debug_destroy(cl);
		bch_dio_write_complete(cl);
#endif
	}
}

static int bch_direct_IO_write(struct cache_set *c, struct kiocb *req,
			       struct file *file, struct inode *inode,
			       struct iov_iter *iter, loff_t offset)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct dio_write *dio;
	struct bio *bio;
	size_t pages = iov_iter_npages(iter, BIO_MAX_PAGES);
	ssize_t ret;
	bool sync;

	lockdep_assert_held(&inode->i_rwsem);

	bio = bio_alloc_bioset(GFP_KERNEL, pages, bch_dio_write_bioset);

	dio = container_of(bio, struct dio_write, bio.bio.bio);
	dio->req	= req;
	dio->written	= 0;
	dio->error	= 0;
	dio->offset	= offset;
	dio->nr_sectors	= iter->count >> 9;
	dio->append	= false;
	dio->iovec	= NULL;
	dio->iter	= *iter;
	dio->mm		= current->mm;

	if (offset + iter->count > inode->i_size) {
		/*
		 * XXX: try and convert this to i_size_update_new(), and maybe
		 * make async O_DIRECT appends work
		 */

		dio->append = true;
		i_size_dirty_get(ei);
	}

	ret = check_make_i_size_dirty(ei, offset + iter->count);
	if (ret)
		goto err;

	ret = i_sectors_dirty_get(ei, &dio->i_sectors_hook);
	if (ret)
		goto err;

	/*
	 * XXX: we shouldn't return -ENOSPC if we're overwriting existing data -
	 * if getting a reservation fails we should check if we are doing an
	 * overwrite.
	 *
	 * Have to then guard against racing with truncate (deleting data that
	 * we would have been overwriting)
	 */
	ret = bch_reserve_sectors(c, dio->nr_sectors);
	if (ret)
		goto err_put_sectors_dirty;

	closure_init(&dio->cl, NULL);

	inode_dio_begin(inode);

	/*
	 * appends are sync in order to do the i_size update under
	 * i_rwsem, after we know the write has completed successfully
	 */
	sync = is_sync_kiocb(req) || dio->append;

	bch_do_direct_IO_write(dio, sync);

	if (sync) {
		closure_debug_destroy(&dio->cl);
		ret = dio->written ?: dio->error;

		if (dio->append) {
			loff_t new_i_size = offset + dio->written;
			int ret2 = 0;

			if (dio->written &&
			    new_i_size > inode->i_size) {
				struct i_size_update *u;
				unsigned idx;

				mutex_lock(&ei->update_lock);

				bch_i_size_write(inode, new_i_size);

				fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx) {
					if (u->new_i_size < new_i_size)
						u->new_i_size = -1;
					else
						BUG();
				}

				i_size_dirty_put(ei);
				ret2 = bch_write_inode_size(c, ei, new_i_size);

				mutex_unlock(&ei->update_lock);
			} else {
				i_size_dirty_put(ei);
			}
		}

		__bch_dio_write_complete(dio);
		return ret;
	} else {
		if (dio->iter.count) {
			if (dio->iter.nr_segs > ARRAY_SIZE(dio->inline_vecs)) {
				dio->iovec = kmalloc(dio->iter.nr_segs *
						     sizeof(struct iovec),
						     GFP_KERNEL);
				if (!dio->iovec)
					dio->error = -ENOMEM;
			} else {
				dio->iovec = dio->inline_vecs;
			}

			memcpy(dio->iovec,
			       dio->iter.iov,
			       dio->iter.nr_segs * sizeof(struct iovec));
			dio->iter.iov = dio->iovec;
		}

		continue_at_noreturn(&dio->cl,
				     bch_dio_write_loop_async,
				     dio->iter.count ? system_wq : NULL);
		return -EIOCBQUEUED;
	}
err_put_sectors_dirty:
	i_sectors_dirty_put(ei, &dio->i_sectors_hook);
err:
	if (dio->append)
		i_size_dirty_put(ei);
	bio_put(bio);
	return ret;
}

ssize_t bch_direct_IO(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct inode *inode = file->f_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;

	if ((req->ki_pos|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	return ((iov_iter_rw(iter) == WRITE)
		? bch_direct_IO_write
		: bch_direct_IO_read)(c, req, file, inode, iter, req->ki_pos);
}

static ssize_t
bch_direct_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	loff_t		pos = iocb->ki_pos;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;

	write_len = iov_iter_count(from);
	end = (pos + write_len - 1) >> PAGE_SHIFT;

	written = filemap_write_and_wait_range(mapping, pos, pos + write_len - 1);
	if (written)
		goto out;

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	if (mapping->nrpages) {
		written = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_SHIFT, end);
		/*
		 * If a page can not be invalidated, return 0 to fall back
		 * to buffered write.
		 */
		if (written) {
			if (written == -EBUSY)
				return 0;
			goto out;
		}
	}

	written = mapping->a_ops->direct_IO(iocb, from);

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * cached by non-direct readahead, or faulted in by get_user_pages()
	 * if the source of the write was an mmap'ed region of the file
	 * we're writing.  Either one is a pretty crazy thing to do,
	 * so we don't support it 100%.  If this invalidation
	 * fails, tough, the write still worked...
	 *
	 * Augh: this makes no sense for async writes - the second invalidate
	 * has to come after the new data is visible. But, we can't just move it
	 * to the end of the dio write path - for async writes we don't have
	 * i_mutex held anymore, 
	 */
	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_SHIFT, end);
	}
out:
	return written;
}

static ssize_t __bch_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t	ret;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = file_remove_privs(file);
	if (ret)
		goto out;

	ret = file_update_time(file);
	if (ret)
		goto out;

	ret = iocb->ki_flags & IOCB_DIRECT
		? bch_direct_write(iocb, from)
		: generic_perform_write(file, from, iocb->ki_pos);

	if (likely(ret > 0))
		iocb->ki_pos += ret;
out:
	current->backing_dev_info = NULL;
	return ret;
}

ssize_t bch_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __bch_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

int bch_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct address_space *mapping = inode->i_mapping;
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);

	/*
	 * i_mutex is required for synchronizing with fcollapse(), O_DIRECT
	 * writes
	 */
	inode_lock(inode);

	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(inode)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (bch_get_page_reservation(c, page)) {
		unlock_page(page);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	if (!PageDirty(page))
		set_page_dirty(page);
	wait_for_stable_page(page);
out:
	inode_unlock(inode);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

void bch_invalidatepage(struct page *page, unsigned int offset,
			unsigned int length)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	if (offset || length < PAGE_SIZE)
		return;

	bch_clear_page_bits(page);
}

int bch_releasepage(struct page *page, gfp_t gfp_mask)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));
	BUG_ON(PageDirty(page));

	bch_clear_page_bits(page);

	return 1;
}

#ifdef CONFIG_MIGRATION
int bch_migrate_page(struct address_space *mapping, struct page *newpage,
		     struct page *page, enum migrate_mode mode)
{
	int ret;

	ret = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);
	if (ret != MIGRATEPAGE_SUCCESS)
		return ret;

	if (PagePrivate(page)) {
		*page_state(newpage) = *page_state(page);
		ClearPagePrivate(page);
	}

	migrate_page_copy(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
#endif

int bch_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	int ret;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	inode_lock(inode);
	if (datasync && end <= ei->i_size)
		goto out;

	/*
	 * If there's still outstanding appends, we may have not yet written an
	 * i_size that exposes the data we just fsynced - however, we can
	 * advance the i_size on disk up to the end of what we just explicitly
	 * wrote:
	 */

	mutex_lock(&ei->update_lock);

	if (end > ei->i_size &&
	    ei->i_size < inode->i_size) {
		struct i_size_update *u;
		unsigned idx;
		loff_t new_i_size = min_t(u64, inode->i_size,
					  roundup(end, PAGE_SIZE));

		BUG_ON(fifo_empty(&ei->i_size_updates));
		BUG_ON(new_i_size < ei->i_size);

		/*
		 * There can still be a pending i_size update < the size we're
		 * writing, because it may have been shared with pages > the
		 * size we fsynced to:
		 */
		fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
			if (u->new_i_size < new_i_size)
				u->new_i_size = -1;

		ret = bch_write_inode_size(c, ei, new_i_size);
	}

	mutex_unlock(&ei->update_lock);
out:
	inode_unlock(inode);

	if (ret)
		return ret;

	if (c->opts.journal_flush_disabled)
		return 0;

	return bch_journal_flush_seq(&c->journal, ei->journal_seq);
}

static int __bch_truncate_page(struct address_space *mapping,
			       pgoff_t index, loff_t start, loff_t end)
{
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	unsigned start_offset = start & (PAGE_SIZE - 1);
	unsigned end_offset = ((end - 1) & (PAGE_SIZE - 1)) + 1;
	struct bch_page_state new;
	struct page *page;
	int ret = 0;

	/* Page boundary? Nothing to do */
	if (!((index == start >> PAGE_SHIFT && start_offset) ||
	      (index == end >> PAGE_SHIFT && end_offset != PAGE_SIZE)))
		return 0;

	/* Above i_size? */
	if (index << PAGE_SHIFT >= inode->i_size)
		return 0;

	page = find_lock_page(mapping, index);
	if (!page) {
		struct btree_iter iter;
		struct bkey_s_c k = bkey_s_c_null;

		/*
		 * XXX: we're doing two index lookups when we end up reading the
		 * page
		 */
		for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino,
				       index << (PAGE_SHIFT - 9)), k) {
			if (bkey_cmp(bkey_start_pos(k.k),
				     POS(inode->i_ino,
					 (index + 1) << (PAGE_SHIFT - 9))) >= 0)
				break;

			if (k.k->type != KEY_TYPE_DISCARD &&
			    k.k->type != BCH_RESERVATION) {
				bch_btree_iter_unlock(&iter);
				goto create;
			}
		}
		bch_btree_iter_unlock(&iter);
		return 0;
create:
		page = find_or_create_page(mapping, index, GFP_KERNEL);
		if (unlikely(!page)) {
			ret = -ENOMEM;
			goto out;
		}
	}

	if (!PageUptodate(page)) {
		ret = bch_read_single_page(page, mapping);
		if (ret)
			goto unlock;
	}

#if 0
	/*
	 * XXX: this is a hack, because we don't want truncate to fail due to
	 * -ENOSPC
	 *
	 *  Note that because we aren't currently tracking whether the page has
	 *  actual data in it (vs. just 0s, or only partially written) this is
	 *  also wrong. ick.
	 */
#endif
	page_state_cmpxchg(page_state(page), new, {
		if (new.alloc_state == BCH_PAGE_UNALLOCATED)
			new.alloc_state = BCH_PAGE_ALLOCATED;
	});

	if (index == start >> PAGE_SHIFT &&
	    index == end >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, end_offset);
	else if (index == start >> PAGE_SHIFT)
		zero_user_segment(page, start_offset, PAGE_SIZE);
	else if (index == end >> PAGE_SHIFT)
		zero_user_segment(page, 0, end_offset);

	if (!PageDirty(page))
		set_page_dirty(page);
unlock:
	unlock_page(page);
	put_page(page);
out:
	return ret;
}

static int bch_truncate_page(struct address_space *mapping, loff_t from)
{
	return __bch_truncate_page(mapping, from >> PAGE_SHIFT,
				   from, from + PAGE_SIZE);
}

int bch_truncate(struct inode *inode, struct iattr *iattr)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct i_size_update *u;
	bool shrink = iattr->ia_size <= inode->i_size;
	unsigned idx;
	int ret = 0;

	inode_dio_wait(inode);

	mutex_lock(&ei->update_lock);

	/*
	 * The new i_size could be bigger or smaller than the current on
	 * disk size (ei->i_size):
	 *
	 * If it's smaller (i.e. we actually are truncating), then in
	 * order to make the truncate appear atomic we have to write out
	 * the new i_size before discarding the data to be truncated.
	 *
	 * However, if the new i_size is bigger than the on disk i_size,
	 * then we _don't_ want to write the new i_size here - because
	 * if there are appends in flight, that would cause us to expose
	 * the range between the old and the new i_size before those
	 * appends have completed.
	 */

	/*
	 * First, cancel i_size_updates that extend past the new
	 * i_size, so the i_size we write here doesn't get
	 * stomped on:
	 */
	fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
		if (u->new_i_size > iattr->ia_size)
			u->new_i_size = -1;

	set_bit(BCH_INODE_WANT_NEW_APPEND, &ei->flags);
	u = i_size_update_new(ei, iattr->ia_size);

	atomic_long_inc(&u->count);
	idx = u - ei->i_size_updates.data;

	if (iattr->ia_size < ei->i_size)
		ret = bch_write_inode_size(c, ei, iattr->ia_size);

	mutex_unlock(&ei->update_lock);

	/*
	 * XXX: if we error, we leak i_size_dirty count - and we can't
	 * just put it, because it actually is still dirty
	 */
	if (unlikely(ret))
		return ret;

	/*
	 * truncate_setsize() does the i_size_write(), can't use
	 * bch_i_size_write()
	 */
	EBUG_ON(iattr->ia_size < ei->i_size);
	truncate_setsize(inode, iattr->ia_size);

	/*
	 * There might be persistent reservations (from fallocate())
	 * above i_size, which bch_inode_truncate() will discard - we're
	 * only supposed to discard them if we're doing a real truncate
	 * here (new i_size < current i_size):
	 */
	if (shrink) {
		struct i_sectors_hook i_sectors_hook;
		int ret;

		ret = i_sectors_dirty_get(ei, &i_sectors_hook);
		if (unlikely(ret))
			return ret;

		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (unlikely(ret)) {
			i_sectors_dirty_put(ei, &i_sectors_hook);
			return ret;
		}

		ret = bch_inode_truncate(c, inode->i_ino,
					 round_up(iattr->ia_size, PAGE_SIZE) >> 9,
					 &i_sectors_hook.hook,
					 &ei->journal_seq);

		i_sectors_dirty_put(ei, &i_sectors_hook);

		if (unlikely(ret))
			return ret;
	}

	setattr_copy(inode, iattr);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	i_size_update_put(c, ei, idx, 1);
	return 0;
}

static long bch_fpunch(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	u64 ino = inode->i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(inode);
	ret = __bch_truncate_page(inode->i_mapping,
				  offset >> PAGE_SHIFT,
				  offset, offset + len);
	if (unlikely(ret))
		goto out;

	if (offset >> PAGE_SHIFT !=
	    (offset + len) >> PAGE_SHIFT) {
		ret = __bch_truncate_page(inode->i_mapping,
					  (offset + len) >> PAGE_SHIFT,
					  offset, offset + len);
		if (unlikely(ret))
			goto out;
	}

	truncate_pagecache_range(inode, offset, offset + len - 1);

	if (discard_start < discard_end) {
		struct i_sectors_hook i_sectors_hook;
		int ret;

		ret = i_sectors_dirty_get(ei, &i_sectors_hook);
		if (unlikely(ret))
			goto out;

		ret = bch_discard(c,
				  POS(ino, discard_start),
				  POS(ino, discard_end),
				  0,
				  &i_sectors_hook.hook,
				  &ei->journal_seq);

		i_sectors_dirty_put(ei, &i_sectors_hook);
	}
out:
	inode_unlock(inode);

	return ret;
}

static long bch_fcollapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter src;
	struct btree_iter dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_size_update *u;
	struct i_sectors_hook i_sectors_hook;
	loff_t new_size;
	unsigned idx;
	int ret;

	if ((offset | len) & (PAGE_SIZE - 1))
		return -EINVAL;

	bch_btree_iter_init_intent(&dst, c, BTREE_ID_EXTENTS,
				   POS(inode->i_ino, offset >> 9));
	/* position will be set from dst iter's position: */
	bch_btree_iter_init(&src, c, BTREE_ID_EXTENTS, POS_MIN);
	bch_btree_iter_link(&src, &dst);

	/*
	 * We need i_mutex to keep the page cache consistent with the extents
	 * btree, and the btree consistent with i_size - we don't need outside
	 * locking for the extents btree itself, because we're using linked
	 * iterators
	 *
	 * XXX: hmm, need to prevent reads adding things to the pagecache until
	 * we're done?
	 */
	inode_lock(inode);

	ret = -EINVAL;
	if (offset + len >= inode->i_size)
		goto err;

	if (inode->i_size < len)
		goto err;

	new_size = inode->i_size - len;

	inode_dio_wait(inode);

	do {
		ret = filemap_write_and_wait_range(inode->i_mapping,
						   offset, LLONG_MAX);
		if (ret)
			goto err;

		ret = invalidate_inode_pages2_range(inode->i_mapping,
					offset >> PAGE_SHIFT,
					ULONG_MAX);
	} while (ret == -EBUSY);

	if (ret)
		goto err;

	ret = i_sectors_dirty_get(ei, &i_sectors_hook);
	if (ret)
		goto err;

	while (bkey_cmp(dst.pos,
			POS(inode->i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		bch_btree_iter_set_pos(&src,
			POS(dst.pos.inode, dst.pos.offset + (len >> 9)));

		/* Have to take intent locks before read locks: */
		ret = bch_btree_iter_traverse(&dst);
		if (ret)
			goto err_unwind;

		k = bch_btree_iter_peek_with_holes(&src);
		if (!k.k) {
			ret = -EIO;
			goto err_unwind;
		}

		bkey_reassemble(&copy.k, k);

		if (bkey_deleted(&copy.k.k))
			copy.k.k.type = KEY_TYPE_DISCARD;

		bch_cut_front(src.pos, &copy.k);
		copy.k.k.p.offset -= len >> 9;

		BUG_ON(bkey_cmp(dst.pos, bkey_start_pos(&copy.k.k)));

		ret = bch_btree_insert_at(&dst,
					  &keylist_single(&copy.k),
					  &i_sectors_hook.hook,
					  &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
		if (ret < 0 && ret != -EINTR)
			goto err_unwind;

		bch_btree_iter_unlock(&src);
	}

	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);

	ret = bch_inode_truncate(c, inode->i_ino,
				 round_up(new_size, PAGE_SIZE) >> 9,
				 &i_sectors_hook.hook,
				 &ei->journal_seq);
	if (ret)
		goto err_unwind;

	i_sectors_dirty_put(ei, &i_sectors_hook);

	mutex_lock(&ei->update_lock);

	/*
	 * Cancel i_size updates > new_size:
	 *
	 * Note: we're also cancelling i_size updates for appends < new_size, and
	 * writing the new i_size before they finish - would be better to use an
	 * i_size_update here like truncate, so we can sequence our i_size
	 * updates with outstanding appends and not have to cancel them:
	 */
	fifo_for_each_entry_ptr(u, &ei->i_size_updates, idx)
		u->new_i_size = -1;

	ret = bch_write_inode_size(c, ei, new_size);
	bch_i_size_write(inode, new_size);

	truncate_pagecache(inode, offset);

	mutex_unlock(&ei->update_lock);

	inode_unlock(inode);

	return ret;
err_unwind:
	i_sectors_dirty_put(ei, &i_sectors_hook);
	BUG();
err:
	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);
	inode_unlock(inode);
	return ret;
}

static long bch_fallocate(struct inode *inode, int mode,
				    loff_t offset, loff_t len)
{
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct i_sectors_hook i_sectors_hook;
	struct btree_iter iter;
	struct bkey_i reservation;
	struct bkey_s_c k;
	struct bpos end;
	loff_t block_start, block_end;
	loff_t new_size = offset + len;
	unsigned sectors;
	int ret;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

	inode_lock(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto err;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
		/* just for __bch_truncate_page(): */
		inode_dio_wait(inode);

		ret = __bch_truncate_page(inode->i_mapping,
					  offset >> PAGE_SHIFT,
					  offset, offset + len);

		if (!ret &&
		    offset >> PAGE_SHIFT !=
		    (offset + len) >> PAGE_SHIFT)
			ret = __bch_truncate_page(inode->i_mapping,
						  (offset + len) >> PAGE_SHIFT,
						  offset, offset + len);

		if (unlikely(ret))
			goto err;

		truncate_pagecache_range(inode, offset, offset + len - 1);

		block_start	= round_up(offset, PAGE_SIZE);
		block_end	= round_down(offset + len, PAGE_SIZE);
	} else {
		block_start	= round_down(offset, PAGE_SIZE);
		block_end	= round_up(offset + len, PAGE_SIZE);
	}

	bch_btree_iter_set_pos(&iter, POS(inode->i_ino, block_start >> 9));
	end = POS(inode->i_ino, block_end >> 9);

	ret = i_sectors_dirty_get(ei, &i_sectors_hook);
	if (unlikely(ret))
		goto err;

	while (bkey_cmp(iter.pos, end) < 0) {
		unsigned flags = 0;

		k = bch_btree_iter_peek_with_holes(&iter);
		if (!k.k) {
			ret = bch_btree_iter_unlock(&iter) ?: -EIO;
			goto err_put_sectors_dirty;
		}

		/* already reserved */
		if (k.k->type == BCH_RESERVATION) {
			bch_btree_iter_advance_pos(&iter);
			continue;
		}

		if (bkey_extent_is_data(k.k)) {
			if (!(mode & FALLOC_FL_ZERO_RANGE)) {
				bch_btree_iter_advance_pos(&iter);
				continue;
			}

			/* don't check for -ENOSPC if we're deleting data: */
			flags |= BTREE_INSERT_NOFAIL;
		}

		bkey_init(&reservation.k);
		reservation.k.type	= BCH_RESERVATION;
		reservation.k.p		= k.k->p;
		reservation.k.size	= k.k->size;

		bch_cut_front(iter.pos, &reservation);
		bch_cut_back(end, &reservation.k);

		sectors = reservation.k.size;

		ret = bch_reserve_sectors(c, sectors);
		if (ret)
			goto err_put_sectors_dirty;

		ret = bch_btree_insert_at(&iter,
					  &keylist_single(&reservation),
					  &i_sectors_hook.hook,
					  &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|flags);

		atomic64_sub_bug(sectors, &c->sectors_reserved);

		if (ret < 0 && ret != -EINTR)
			goto err_put_sectors_dirty;

	}
	bch_btree_iter_unlock(&iter);

	i_sectors_dirty_put(ei, &i_sectors_hook);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		struct i_size_update *u;
		unsigned idx;

		mutex_lock(&ei->update_lock);
		bch_i_size_write(inode, new_size);

		u = i_size_update_new(ei, new_size);
		idx = u - ei->i_size_updates.data;
		atomic_long_inc(&u->count);
		mutex_unlock(&ei->update_lock);

		i_size_update_put(c, ei, idx, 1);
	}

	inode_unlock(inode);

	return 0;
err_put_sectors_dirty:
	i_sectors_dirty_put(ei, &i_sectors_hook);
err:
	bch_btree_iter_unlock(&iter);
	inode_unlock(inode);
	return ret;
}

long bch_fallocate_dispatch(struct file *file, int mode,
			    loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);

	if (!(mode & ~(FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE)))
		return bch_fallocate(inode, mode, offset, len);

	if (mode == (FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE))
		return bch_fpunch(inode, offset, len);

	if (mode == FALLOC_FL_COLLAPSE_RANGE)
		return bch_fcollapse(inode, offset, len);

	return -EOPNOTSUPP;
}

static bool page_is_data(struct page *page)
{
	return PagePrivate(page) &&
		page_state(page)->alloc_state != BCH_PAGE_UNALLOCATED;
}

static loff_t bch_next_pagecache_data(struct inode *inode,
				      loff_t start_offset,
				      loff_t end_offset)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	pgoff_t index;

	for (index = start_offset >> PAGE_CACHE_SHIFT;
	     index < end_offset >> PAGE_CACHE_SHIFT;
	     index++) {
		if (find_get_pages(mapping, index, 1, &page)) {
			lock_page(page);
			index = page->index;

			if (page_is_data(page))
				end_offset =
					min(end_offset,
					max(start_offset,
					    ((loff_t) index) << PAGE_CACHE_SHIFT));
			unlock_page(page);
			put_page(page);
		} else {
			break;
		}
	}

	return end_offset;
}

static loff_t bch_seek_data(struct file *file, u64 offset)
{
	struct inode *inode = file->f_mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 isize, next_data = MAX_LFS_FILESIZE;
	int ret;

	isize = i_size_read(inode);
	if (offset >= isize)
		return -ENXIO;

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS,
			   POS(inode->i_ino, offset >> 9), k) {
		if (k.k->p.inode != inode->i_ino) {
			break;
		} else if (bkey_extent_is_data(k.k)) {
			next_data = max(offset, bkey_start_offset(k.k) << 9);
			break;
		} else if (k.k->p.offset >> 9 > isize)
			break;
	}

	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	if (next_data > offset)
		next_data = bch_next_pagecache_data(inode, offset, next_data);

	if (next_data > isize)
		return -ENXIO;

	return vfs_setpos(file, next_data, MAX_LFS_FILESIZE);
}

static bool page_slot_is_data(struct address_space *mapping, pgoff_t index)
{
	struct page *page;
	bool ret;

	page = find_lock_entry(mapping, index);
	if (!page)
		return false;

	ret = page_is_data(page);
	unlock_page(page);

	return ret;
}

static loff_t bch_next_pagecache_hole(struct inode *inode,
				      loff_t start_offset,
				      loff_t end_offset)
{
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;

	for (index = start_offset >> PAGE_CACHE_SHIFT;
	     index < end_offset >> PAGE_CACHE_SHIFT;
	     index++)
		if (!page_slot_is_data(mapping, index))
			end_offset = max(start_offset,
					 ((loff_t) index) << PAGE_CACHE_SHIFT);

	return end_offset;
}

static loff_t bch_seek_hole(struct file *file, u64 offset)
{
	struct inode *inode = file->f_mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter iter;
	struct bkey_s_c k;
	u64 isize, next_hole = MAX_LFS_FILESIZE;
	int ret;

	isize = i_size_read(inode);
	if (offset >= isize)
		return -ENXIO;

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode->i_ino, offset >> 9), k) {
		if (k.k->p.inode != inode->i_ino) {
			next_hole = bch_next_pagecache_hole(inode,
					offset, MAX_LFS_FILESIZE);
			break;
		} else if (!bkey_extent_is_data(k.k)) {
			next_hole = bch_next_pagecache_hole(inode,
					max(offset, bkey_start_offset(k.k) << 9),
					k.k->p.offset << 9);

			if (next_hole < k.k->p.offset << 9)
				break;
		} else {
			offset = max(offset, bkey_start_offset(k.k) << 9);
		}
	}

	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	if (next_hole > isize)
		next_hole = isize;

	return vfs_setpos(file, next_hole, MAX_LFS_FILESIZE);
}

loff_t bch_llseek(struct file *file, loff_t offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek(file, offset, whence);
	case SEEK_DATA:
		return bch_seek_data(file, offset);
	case SEEK_HOLE:
		return bch_seek_hole(file, offset);
	}

	return -EINVAL;
}
