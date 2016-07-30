
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

/* pagecache_block must be held */
static int write_invalidate_inode_pages_range(struct address_space *mapping,
					      loff_t start, loff_t end)
{
	int ret;

	/*
	 * XXX: the way this is currently implemented, we can spin if a process
	 * is continually redirtying a specific page
	 */
	do {
		if (!mapping->nrpages &&
		    !mapping->nrexceptional)
			return 0;

		ret = filemap_write_and_wait_range(mapping, start, end);
		if (ret)
			break;

		if (!mapping->nrpages)
			return 0;

		ret = invalidate_inode_pages2_range(mapping,
				start >> PAGE_SHIFT,
				end >> PAGE_SHIFT);
	} while (ret == -EBUSY);

	return ret;
}

/* i_size updates: */

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

static inline void i_size_dirty_put(struct bch_inode_info *ei)
{
	atomic_long_dec_bug(&ei->i_size_dirty_count);
}

static inline void i_size_dirty_get(struct bch_inode_info *ei)
{
	lockdep_assert_held(&ei->vfs_inode.i_rwsem);

	atomic_long_inc(&ei->i_size_dirty_count);
}

/* i_sectors accounting: */

static enum extent_insert_hook_ret
i_sectors_hook_fn(struct extent_insert_hook *hook,
		  struct bpos committed_pos,
		  struct bpos next_pos,
		  struct bkey_s_c k,
		  const struct bkey_i *insert)
{
	struct i_sectors_hook *h = container_of(hook,
				struct i_sectors_hook, hook);
	s64 sectors = next_pos.offset - committed_pos.offset;
	int sign = bkey_extent_is_allocation(&insert->k) -
		(k.k && bkey_extent_is_allocation(k.k));

	EBUG_ON(!(h->ei->i_flags & BCH_INODE_I_SECTORS_DIRTY));
	EBUG_ON(!atomic_long_read(&h->ei->i_sectors_dirty_count));

	h->sectors += sectors * sign;

	return BTREE_HOOK_DO_INSERT;
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

static void i_sectors_dirty_put(struct bch_inode_info *ei,
				struct i_sectors_hook *h)
{
	struct inode *inode = &ei->vfs_inode;

	if (h->sectors) {
		spin_lock(&inode->i_lock);
		inode->i_blocks += h->sectors;
		spin_unlock(&inode->i_lock);

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

struct bchfs_extent_trans_hook {
	struct bchfs_write_op		*op;
	struct extent_insert_hook	hook;
	struct bkey_i_inode		new_inode;
	bool				need_inode_update;
};

static enum extent_insert_hook_ret
bchfs_extent_update_hook(struct extent_insert_hook *hook,
			 struct bpos committed_pos,
			 struct bpos next_pos,
			 struct bkey_s_c k,
			 const struct bkey_i *insert)
{
	struct bchfs_extent_trans_hook *h = container_of(hook,
				struct bchfs_extent_trans_hook, hook);
	struct bch_inode_info *ei = h->op->ei;
	struct inode *inode = &ei->vfs_inode;
	int sign = bkey_extent_is_allocation(&insert->k) -
		(k.k && bkey_extent_is_allocation(k.k));
	s64 sectors = (s64) (next_pos.offset - committed_pos.offset) * sign;
	u64 offset = min(next_pos.offset << 9, h->op->new_i_size);

	BUG_ON((next_pos.offset << 9) > round_up(offset, PAGE_SIZE));

	/* XXX: ei->i_size locking */
	if (offset > ei->i_size) {
		BUG_ON(ei->i_flags & BCH_INODE_I_SIZE_DIRTY);

		if (!h->need_inode_update) {
			h->need_inode_update = true;
			return BTREE_HOOK_RESTART_TRANS;
		}

		h->new_inode.v.i_size = cpu_to_le64(offset);
		ei->i_size = offset;

		if (h->op->is_dio)
			i_size_write(inode, offset);
	}

	if (sectors) {
		if (!h->need_inode_update) {
			h->need_inode_update = true;
			return BTREE_HOOK_RESTART_TRANS;
		}

		le64_add_cpu(&h->new_inode.v.i_sectors, sectors);
		atomic64_add(sectors, &ei->i_sectors);

		h->op->sectors_added += sectors;

		if (h->op->is_dio) {
			spin_lock(&inode->i_lock);
			inode->i_blocks += sectors;
			spin_unlock(&inode->i_lock);
		}
	}

	return BTREE_HOOK_DO_INSERT;
}

static int bchfs_write_index_update(struct bch_write_op *wop)
{
	struct bchfs_write_op *op = container_of(wop,
				struct bchfs_write_op, op);
	struct keylist *keys = &op->op.insert_keys;
	struct btree_iter extent_iter, inode_iter;
	struct bchfs_extent_trans_hook hook;
	int ret;

	BUG_ON(bch_keylist_front(keys)->k.p.inode != op->ei->vfs_inode.i_ino);

	bch_btree_iter_init_intent(&extent_iter, wop->c, BTREE_ID_EXTENTS,
				   bkey_start_pos(&bch_keylist_front(keys)->k));
	bch_btree_iter_init_intent(&inode_iter, wop->c,	BTREE_ID_INODES,
				   POS(extent_iter.pos.inode, 0));
	bch_btree_iter_link(&extent_iter, &inode_iter);

	hook.op			= op;
	hook.hook.fn		= bchfs_extent_update_hook;
	hook.need_inode_update	= false;

	do {
		struct bkey_i *k = bch_keylist_front(keys);

		/* lock ordering... */
		bch_btree_iter_unlock(&inode_iter);

		ret = bch_btree_iter_traverse(&extent_iter);
		if (ret)
			break;

		/* XXX: ei->i_size locking */
		if (min(k->k.p.offset << 9, op->new_i_size) > op->ei->i_size)
			hook.need_inode_update = true;

		if (hook.need_inode_update) {
			struct btree_insert_trans trans = {
				.nr = 2,
				.entries = (struct btree_trans_entry[]) {
					{ .iter = &extent_iter, .k = k },
					{ .iter = &inode_iter,  .k = &hook.new_inode.k_i },
				},
			};
			struct bkey_s_c inode;

			ret = bch_btree_iter_traverse(&inode_iter);
			if (ret)
				break;

			inode = bch_btree_iter_peek_with_holes(&inode_iter);

			if (WARN_ONCE(!inode.k ||
				      inode.k->type != BCH_INODE_FS,
				      "inode %llu not found when updating",
				      extent_iter.pos.inode)) {
				ret = -ENOENT;
				break;
			}

			bkey_reassemble(&hook.new_inode.k_i, inode);

			ret = bch_btree_insert_trans(&trans, &wop->res,
						     &hook.hook,
						     op_journal_seq(wop),
						     BTREE_INSERT_NOFAIL|
						     BTREE_INSERT_ATOMIC);
		} else {
			ret = bch_btree_insert_at(&extent_iter, k,
						  &wop->res, &hook.hook,
						  op_journal_seq(wop),
						  BTREE_INSERT_NOFAIL|
						  BTREE_INSERT_ATOMIC);
		}

		if (ret == -EINTR)
			continue;
		if (ret)
			break;

		bch_keylist_dequeue(keys);
	} while (!bch_keylist_empty(keys));

	bch_btree_iter_unlock(&extent_iter);
	bch_btree_iter_unlock(&inode_iter);

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
	}			alloc_state:2;

	/* Owns PAGE_SECTORS sized reservation: */
	unsigned		reserved:1;

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
	struct disk_reservation res = { .sectors = PAGE_SECTORS };
	struct bch_page_state s;

	s = page_state_cmpxchg(page_state(page), s, {
		if (!s.reserved)
			return;
		s.reserved = 0;
	});

	bch_disk_reservation_put(c, &res);
}

static int bch_get_page_reservation(struct cache_set *c, struct page *page,
				    bool check_enospc)
{
	struct bch_page_state *s = page_state(page), new;
	struct disk_reservation res;
	int ret = 0;

	BUG_ON(s->alloc_state == BCH_PAGE_ALLOCATED &&
	       s->sectors != PAGE_SECTORS);

	if (s->reserved ||
	    s->alloc_state == BCH_PAGE_ALLOCATED)
		return 0;

	ret = bch_disk_reservation_get(c, &res, PAGE_SECTORS, !check_enospc
				       ? BCH_DISK_RESERVATION_NOFAIL : 0);
	if (ret)
		return ret;

	page_state_cmpxchg(s, new, {
		if (new.reserved) {
			bch_disk_reservation_put(c, &res);
			return 0;
		}
		new.reserved = 1;
	});

	return 0;
}

static void bch_clear_page_bits(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct disk_reservation res = { .sectors = PAGE_SECTORS };
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

	if (s.reserved)
		bch_disk_reservation_put(c, &res);
}

int bch_set_page_dirty(struct page *page)
{
	struct bch_page_state old, new;

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

static void bchfs_read(struct cache_set *c, struct bch_read_bio *rbio, u64 inode)
{
	struct bio *bio = &rbio->bio;
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

		EBUG_ON(s->reserved);

		s->alloc_state = BCH_PAGE_ALLOCATED;
		s->sectors = 0;
	}

	for_each_btree_key_with_holes(&iter, c, BTREE_ID_EXTENTS,
				      POS(inode, bio->bi_iter.bi_sector), k) {
		BKEY_PADDED(k) tmp;
		struct extent_pick_ptr pick;
		unsigned bytes, sectors;
		bool is_last;

		bkey_reassemble(&tmp.k, k);
		bch_btree_iter_unlock(&iter);
		k = bkey_i_to_s_c(&tmp.k);

		if (!bkey_extent_is_allocation(k.k) ||
		    bkey_extent_is_compressed(c, k))
			bch_mark_pages_unalloc(bio);

		bch_extent_pick_ptr(c, k, &pick);
		if (IS_ERR(pick.ca)) {
			bcache_io_error(c, bio, "no device to read from");
			bio_endio(bio);
			return;
		}

		sectors = min_t(u64, k.k->p.offset, bio_end_sector(bio)) -
			bio->bi_iter.bi_sector;
		bytes = sectors << 9;
		is_last = bytes == bio->bi_iter.bi_size;
		swap(bio->bi_iter.bi_size, bytes);

		if (bkey_extent_is_allocation(k.k))
			bch_add_page_sectors(bio, k.k);

		if (pick.ca) {
			PTR_BUCKET(pick.ca, &pick.ptr)->read_prio =
				c->prio_clock[READ].hand;

			bch_read_extent(c, rbio, k, &pick,
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
	struct bch_read_bio *rbio = NULL;
	struct page *page;

	pr_debug("reading %u pages", nr_pages);

	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_get(&mapping->add_lock);

	for_each_readpage_page(mapping, pages, nr_pages, page) {
again:
		if (!rbio) {
			rbio = container_of(bio_alloc_bioset(GFP_NOFS,
						min_t(unsigned, nr_pages,
						      BIO_MAX_PAGES),
						&c->bio_read),
					   struct bch_read_bio, bio);

			rbio->bio.bi_end_io = bch_readpages_end_io;
		}

		if (bch_bio_add_page(&rbio->bio, page)) {
			bchfs_read(c, rbio, inode->i_ino);
			rbio = NULL;
			goto again;
		}
	}

	if (rbio)
		bchfs_read(c, rbio, inode->i_ino);

	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_put(&mapping->add_lock);

	pr_debug("success");
	return 0;
}

int bch_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct bch_read_bio *rbio;

	rbio = container_of(bio_alloc_bioset(GFP_NOFS, 1,
					    &c->bio_read),
			   struct bch_read_bio, bio);
	rbio->bio.bi_rw = READ_SYNC;
	rbio->bio.bi_end_io = bch_readpages_end_io;

	bch_bio_add_page(&rbio->bio, page);
	bchfs_read(c, rbio, inode->i_ino);

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
	struct bio *bio = &io->bio.bio.bio;
	struct bio_vec *bvec;
	unsigned i;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		if (io->op.op.error) {
			SetPageError(page);
			if (page->mapping)
				set_bit(AS_EIO, &page->mapping->flags);
		}

		if (io->op.op.written >= PAGE_SECTORS) {
			struct bch_page_state old, new;

			old = page_state_cmpxchg(page_state(page), new, {
				new.sectors = PAGE_SECTORS;
				new.dirty_sectors = 0;
			});

			io->op.sectors_added -= old.dirty_sectors;
			io->op.op.written -= PAGE_SECTORS;
		}
	}

	/*
	 * racing with fallocate can cause us to add fewer sectors than
	 * expected - but we shouldn't add more sectors than expected:
	 *
	 * (error (due to going RO) halfway through a page can screw that up
	 * slightly)
	 */
	BUG_ON(io->op.sectors_added >= (s64) PAGE_SECTORS);

	/*
	 * PageWriteback is effectively our ref on the inode - fixup i_blocks
	 * before calling end_page_writeback:
	 */
	if (io->op.sectors_added) {
		struct inode *inode = &io->op.ei->vfs_inode;

		spin_lock(&inode->i_lock);
		inode->i_blocks += io->op.sectors_added;
		spin_unlock(&inode->i_lock);
	}

	bio_for_each_segment_all(bvec, bio, i)
		end_page_writeback(bvec->bv_page);

	closure_return_with_destructor(&io->cl, bch_writepage_io_free);
}

static void bch_writepage_do_io(struct bch_writepage_io *io)
{
	io->op.op.insert_key.k.p.offset = bio_end_sector(&io->bio.bio.bio);
	io->op.op.insert_key.k.size	= bio_sectors(&io->bio.bio.bio);

	closure_call(&io->op.op.cl, bch_write, NULL, &io->cl);
	continue_at(&io->cl, bch_writepage_io_done, NULL);
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

		w->io = container_of(bio, struct bch_writepage_io, bio.bio.bio);

		closure_init(&w->io->cl, NULL);
		w->io->op.ei		= ei;
		w->io->op.sectors_added	= 0;
		w->io->op.is_dio	= false;
		bch_write_op_init(&w->io->op.op, w->c, &w->io->bio,
				  (struct disk_reservation) { 0 }, NULL,
				  bkey_to_s_c(&KEY(w->inum, 0, 0)),
				  NULL, &ei->journal_seq, 0);
		w->io->op.op.index_update_fn = bchfs_write_index_update;
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
	BUG_ON(ei != w->io->op.ei);
}

static int __bch_writepage(struct page *page, struct writeback_control *wbc,
			   void *data)
{
	struct inode *inode = page->mapping->host;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bch_writepage *w = data;
	struct bch_page_state new, old;
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
	bch_writepage_io_alloc(w, ei, page);

	/* while page is locked: */
	w->io->op.new_i_size = i_size;

	if (wbc->sync_mode == WB_SYNC_ALL)
		w->io->bio.bio.bio.bi_rw |= WRITE_SYNC;

	/* Before unlocking the page, transfer reservation to w->io: */
	old = page_state_cmpxchg(page_state(page), new, {
		BUG_ON(!new.reserved &&
		       (new.sectors != PAGE_SECTORS ||
			new.alloc_state != BCH_PAGE_ALLOCATED));

		if (new.alloc_state == BCH_PAGE_ALLOCATED &&
		    w->io->op.op.compression_type != BCH_COMPRESSION_NONE)
			new.alloc_state = BCH_PAGE_UNALLOCATED;
		else if (!new.reserved)
			goto out;
		new.reserved = 0;
	});

	w->io->op.op.res.sectors += PAGE_SECTORS * (old.reserved - new.reserved);
out:
	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);

	return 0;
}

int bch_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct bch_writepage w = {
		.c	= mapping->host->i_sb->s_fs_info,
		.inum	= mapping->host->i_ino,
		.io	= NULL,
	};
	int ret;

	ret = write_cache_pages(mapping, wbc, __bch_writepage, &w);
	if (w.io)
		bch_writepage_do_io(w.io);

	return ret;
}

int bch_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct bch_writepage w = {
		.c = inode->i_sb->s_fs_info,
		.inum = inode->i_ino,
		.io = NULL,
	};
	int ret;

	ret = __bch_writepage(page, wbc, &w);

	if (w.io)
		bch_writepage_do_io(w.io);

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
	struct bch_read_bio *rbio;
	int ret;
	DECLARE_COMPLETION_ONSTACK(done);

	rbio = container_of(bio_alloc_bioset(GFP_NOFS, 1,
					     &c->bio_read),
			    struct bch_read_bio, bio);
	rbio->bio.bi_rw = READ_SYNC;
	rbio->bio.bi_private = &done;
	rbio->bio.bi_end_io = bch_read_single_page_end_io;
	bch_bio_add_page(&rbio->bio, page);

	bchfs_read(c, rbio, inode->i_ino);
	wait_for_completion(&done);

	ret = rbio->bio.bi_error;
	bio_put(&rbio->bio);

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
	int ret = -ENOMEM;

	BUG_ON(inode_unhashed(mapping->host));

	/* Not strictly necessary - same reason as mkwrite(): */
	pagecache_add_get(&mapping->add_lock);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		goto err_unlock;

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
	ret = bch_get_page_reservation(c, page, true);
	if (ret) {
		if (!PageUptodate(page)) {
			/*
			 * If the page hasn't been read in, we won't know if we
			 * actually need a reservation - we don't actually need
			 * to read here, we just need to check if the page is
			 * fully backed by uncompressed data:
			 */
			goto readpage;
		}

		goto err;
	}

	*pagep = page;
	return 0;
err:
	unlock_page(page);
	put_page(page);
	*pagep = NULL;
err_unlock:
	pagecache_add_put(&mapping->add_lock);
	return ret;
}

int bch_write_end(struct file *filp, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct cache_set *c = inode->i_sb->s_fs_info;

	lockdep_assert_held(&inode->i_rwsem);

	if (unlikely(copied < len && !PageUptodate(page))) {
		/*
		 * The page needs to be read in, but that would destroy
		 * our partial write - simplest thing is to just force
		 * userspace to redo the write:
		 */
		zero_user(page, 0, PAGE_SIZE);
		flush_dcache_page(page);
		copied = 0;
	}

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);

	if (copied) {
		if (!PageUptodate(page))
			SetPageUptodate(page);
		if (!PageDirty(page))
			set_page_dirty(page);
	} else {
		bch_put_page_reservation(c, page);
	}

	unlock_page(page);
	put_page(page);
	pagecache_add_put(&mapping->add_lock);

	return copied;
}

/* O_DIRECT */

static void bch_dio_read_complete(struct closure *cl)
{
	struct dio_read *dio = container_of(cl, struct dio_read, cl);

	dio->req->ki_complete(dio->req, dio->ret, 0);
	bio_check_pages_dirty(&dio->rbio.bio);	/* transfers ownership */
}

static void bch_direct_IO_read_endio(struct bio *bio)
{
	struct dio_read *dio = bio->bi_private;

	if (bio->bi_error)
		dio->ret = bio->bi_error;

	closure_put(&dio->cl);
}

static void bch_direct_IO_read_split_endio(struct bio *bio)
{
	bch_direct_IO_read_endio(bio);
	bio_check_pages_dirty(bio);	/* transfers ownership */
}

static int bch_direct_IO_read(struct cache_set *c, struct kiocb *req,
			      struct file *file, struct inode *inode,
			      struct iov_iter *iter, loff_t offset)
{
	struct dio_read *dio;
	struct bio *bio;
	bool sync = is_sync_kiocb(req);
	ssize_t ret;

	if ((offset|iter->count) & (block_bytes(c) - 1))
		return -EINVAL;

	ret = min_t(loff_t, iter->count,
		    max_t(loff_t, 0, i_size_read(inode) - offset));
	iov_iter_truncate(iter, round_up(ret, block_bytes(c)));

	if (!ret)
		return ret;

	bio = bio_alloc_bioset(GFP_KERNEL,
			       iov_iter_npages(iter, BIO_MAX_PAGES),
			       bch_dio_read_bioset);

	bio->bi_end_io = bch_direct_IO_read_endio;

	dio = container_of(bio, struct dio_read, rbio.bio);
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
	dio->ret	= ret;

	goto start;
	while (iter->count) {
		bio = bio_alloc_bioset(GFP_KERNEL,
				       iov_iter_npages(iter, BIO_MAX_PAGES),
				       &c->bio_read);
		bio->bi_end_io		= bch_direct_IO_read_split_endio;
start:
		bio->bi_rw		= READ_SYNC;
		bio->bi_iter.bi_sector	= offset >> 9;
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

		bch_read(c, container_of(bio,
				struct bch_read_bio, bio),
			 inode->i_ino);
	}

	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_check_pages_dirty(&dio->rbio.bio); /* transfers ownership */
		return ret;
	} else {
		return -EIOCBQUEUED;
	}
}

static long __bch_dio_write_complete(struct dio_write *dio)
{
	struct file *file = dio->req->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file->f_inode;
	long ret = dio->error ?: dio->written;

	bch_disk_reservation_put(dio->c, &dio->res);

	__pagecache_block_put(&mapping->add_lock);
	inode_dio_end(inode);

	if (dio->iovec && dio->iovec != dio->inline_vecs)
		kfree(dio->iovec);

	bio_put(&dio->bio.bio.bio);
	return ret;
}

static void bch_dio_write_complete(struct closure *cl)
{
	struct dio_write *dio = container_of(cl, struct dio_write, cl);
	struct kiocb *req = dio->req;

	req->ki_complete(req, __bch_dio_write_complete(dio), 0);
}

static void bch_dio_write_done(struct dio_write *dio)
{
	struct bio_vec *bv;
	int i;

	dio->written += dio->iop.op.written << 9;

	if (dio->iop.op.error)
		dio->error = dio->iop.op.error;

	bio_for_each_segment_all(bv, &dio->bio.bio.bio, i)
		put_page(bv->bv_page);

	if (dio->iter.count)
		bio_reset(&dio->bio.bio.bio);
}

static void bch_do_direct_IO_write(struct dio_write *dio)
{
	struct file *file = dio->req->ki_filp;
	struct inode *inode = file->f_inode;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct bio *bio = &dio->bio.bio.bio;
	unsigned flags = 0;
	int ret;

	if (((file->f_flags & O_DSYNC) || IS_SYNC(file->f_mapping->host)) &&
	    !dio->c->opts.journal_flush_disabled)
		flags |= BCH_WRITE_FLUSH;

	bio->bi_iter.bi_sector = (dio->offset + dio->written) >> 9;

	ret = bio_get_user_pages(bio, &dio->iter, 0);
	if (ret < 0) {
		/*
		 * these didn't get initialized, but bch_dio_write_done() will
		 * look at them:
		 */
		dio->iop.op.error = 0;
		dio->iop.op.written = 0;
		dio->error = ret;
		return;
	}

	dio->iop.ei		= ei;
	dio->iop.sectors_added	= 0;
	dio->iop.is_dio		= true;
	dio->iop.new_i_size	= U64_MAX;
	bch_write_op_init(&dio->iop.op, dio->c, &dio->bio,
			  (struct disk_reservation) {
			  .sectors = bio_sectors(bio),
			  .gen = dio->res.gen
			  }, NULL,
			  bkey_to_s_c(&KEY(inode->i_ino,
					   bio_end_sector(bio),
					   bio_sectors(bio))),
			  NULL, &ei->journal_seq, flags);
	dio->iop.op.index_update_fn = bchfs_write_index_update;

	dio->res.sectors -= bio_sectors(bio);

	task_io_account_write(bio->bi_iter.bi_size);

	closure_call(&dio->iop.op.cl, bch_write, NULL, &dio->cl);
}

static void bch_dio_write_loop_async(struct closure *cl)
{
	struct dio_write *dio =
		container_of(cl, struct dio_write, cl);
	struct address_space *mapping = dio->req->ki_filp->f_mapping;

	bch_dio_write_done(dio);

	if (dio->iter.count && !dio->error) {
		use_mm(dio->mm);
		pagecache_block_get(&mapping->add_lock);

		bch_do_direct_IO_write(dio);

		pagecache_block_put(&mapping->add_lock);
		unuse_mm(dio->mm);

		continue_at(&dio->cl, bch_dio_write_loop_async, NULL);
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
	struct address_space *mapping = file->f_mapping;
	struct dio_write *dio;
	struct bio *bio;
	ssize_t ret;
	bool sync = is_sync_kiocb(req);

	lockdep_assert_held(&inode->i_rwsem);

	if (unlikely(!iter->count))
		return 0;

	if (unlikely((offset|iter->count) & (block_bytes(c) - 1)))
		return -EINVAL;

	bio = bio_alloc_bioset(GFP_KERNEL,
			       iov_iter_npages(iter, BIO_MAX_PAGES),
			       bch_dio_write_bioset);
	dio = container_of(bio, struct dio_write, bio.bio.bio);
	dio->req	= req;
	dio->c		= c;
	dio->written	= 0;
	dio->error	= 0;
	dio->offset	= offset;
	dio->iovec	= NULL;
	dio->iter	= *iter;
	dio->mm		= current->mm;
	closure_init(&dio->cl, NULL);

	if (offset + iter->count > inode->i_size)
		sync = true;

	/*
	 * XXX: we shouldn't return -ENOSPC if we're overwriting existing data -
	 * if getting a reservation fails we should check if we are doing an
	 * overwrite.
	 *
	 * Have to then guard against racing with truncate (deleting data that
	 * we would have been overwriting)
	 */
	ret = bch_disk_reservation_get(c, &dio->res, iter->count >> 9, 0);
	if (unlikely(ret)) {
		closure_debug_destroy(&dio->cl);
		bio_put(bio);
		return ret;
	}

	inode_dio_begin(inode);
	__pagecache_block_get(&mapping->add_lock);

	if (sync) {
		do {
			bch_do_direct_IO_write(dio);

			closure_sync(&dio->cl);
			bch_dio_write_done(dio);
		} while (dio->iter.count && !dio->error);

		closure_debug_destroy(&dio->cl);
		return __bch_dio_write_complete(dio);
	} else {
		bch_do_direct_IO_write(dio);

		if (dio->iter.count && !dio->error) {
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

		continue_at_noreturn(&dio->cl, bch_dio_write_loop_async, NULL);
		return -EIOCBQUEUED;
	}
}

ssize_t bch_direct_IO(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct inode *inode = file->f_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;

	return ((iov_iter_rw(iter) == WRITE)
		? bch_direct_IO_write
		: bch_direct_IO_read)(c, req, file, inode, iter, req->ki_pos);
}

static ssize_t
bch_direct_write(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_inode;
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct address_space *mapping = file->f_mapping;
	loff_t pos = iocb->ki_pos;
	ssize_t	ret;

	pagecache_block_get(&mapping->add_lock);

	/* Write and invalidate pagecache range that we're writing to: */
	ret = write_invalidate_inode_pages_range(file->f_mapping, pos,
					pos + iov_iter_count(iter) - 1);
	if (unlikely(ret))
		goto err;

	ret = bch_direct_IO_write(c, iocb, file, inode, iter, pos);
err:
	pagecache_block_put(&mapping->add_lock);

	return ret;
}

static ssize_t __bch_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
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
	bool direct = iocb->ki_flags & IOCB_DIRECT;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __bch_write_iter(iocb, from);
	inode_unlock(inode);

	if (ret > 0 && !direct)
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
	 * Not strictly necessary, but helps avoid dio writes livelocking in
	 * write_invalidate_inode_pages_range() - can drop this if/when we get
	 * a write_invalidate_inode_pages_range() that works without dropping
	 * page lock before invalidating page
	 */
	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_get(&mapping->add_lock);

	lock_page(page);
	if (page->mapping != mapping ||
	    page_offset(page) > i_size_read(inode)) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	if (bch_get_page_reservation(c, page, true)) {
		unlock_page(page);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	if (!PageDirty(page))
		set_page_dirty(page);
	wait_for_stable_page(page);
out:
	if (current->pagecache_lock != &mapping->add_lock)
		pagecache_add_put(&mapping->add_lock);
	sb_end_pagefault(inode->i_sb);
	return ret;
}

void bch_invalidatepage(struct page *page, unsigned int offset,
			unsigned int length)
{
	EBUG_ON(!PageLocked(page));
	EBUG_ON(PageWriteback(page));

	if (offset || length < PAGE_SIZE)
		return;

	bch_clear_page_bits(page);
}

int bch_releasepage(struct page *page, gfp_t gfp_mask)
{
	EBUG_ON(!PageLocked(page));
	EBUG_ON(PageWriteback(page));

	if (PageDirty(page))
		return 0;

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

	/*
	 * Bit of a hack - we don't want truncate to fail due to -ENOSPC.
	 *
	 * XXX: because we aren't currently tracking whether the page has actual
	 * data in it (vs. just 0s, or only partially written) this wrong. ick.
	 */
	ret = bch_get_page_reservation(c, page, false);
	BUG_ON(ret);

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
	struct address_space *mapping = inode->i_mapping;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	bool shrink = iattr->ia_size <= inode->i_size;
	int ret = 0;

	inode_dio_wait(inode);
	pagecache_block_get(&mapping->add_lock);

	truncate_setsize(inode, iattr->ia_size);

	/* sync appends.. */
	/* XXX what protects ei->i_size? */
	if (iattr->ia_size > ei->i_size)
		ret = filemap_write_and_wait_range(mapping, ei->i_size, S64_MAX);
	if (ret)
		goto err_put_pagecache;

	mutex_lock(&ei->update_lock);
	i_size_dirty_get(ei);
	ret = bch_write_inode_size(c, ei, inode->i_size);
	mutex_unlock(&ei->update_lock);

	if (unlikely(ret))
		goto err;

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
			goto err;

		ret = bch_truncate_page(inode->i_mapping, iattr->ia_size);
		if (unlikely(ret)) {
			i_sectors_dirty_put(ei, &i_sectors_hook);
			goto err;
		}

		ret = bch_inode_truncate(c, inode->i_ino,
					 round_up(iattr->ia_size, PAGE_SIZE) >> 9,
					 &i_sectors_hook.hook,
					 &ei->journal_seq);

		i_sectors_dirty_put(ei, &i_sectors_hook);

		if (unlikely(ret))
			goto err;
	}

	mutex_lock(&ei->update_lock);
	setattr_copy(inode, iattr);
	inode->i_mtime = inode->i_ctime = CURRENT_TIME;

	/* clear I_SIZE_DIRTY: */
	i_size_dirty_put(ei);
	ret = bch_write_inode_size(c, ei, inode->i_size);
	mutex_unlock(&ei->update_lock);

	pagecache_block_put(&mapping->add_lock);

	return 0;
err:
	i_size_dirty_put(ei);
err_put_pagecache:
	pagecache_block_put(&mapping->add_lock);
	return ret;
}

static long bch_fpunch(struct inode *inode, loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->i_mapping;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	u64 ino = inode->i_ino;
	u64 discard_start = round_up(offset, PAGE_SIZE) >> 9;
	u64 discard_end = round_down(offset + len, PAGE_SIZE) >> 9;
	int ret = 0;

	inode_lock(inode);
	inode_dio_wait(inode);
	pagecache_block_get(&mapping->add_lock);

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
		struct disk_reservation disk_res;
		struct i_sectors_hook i_sectors_hook;
		int ret;

		BUG_ON(bch_disk_reservation_get(c, &disk_res, 0, 0));

		ret = i_sectors_dirty_get(ei, &i_sectors_hook);
		if (unlikely(ret))
			goto out;

		ret = bch_discard(c,
				  POS(ino, discard_start),
				  POS(ino, discard_end),
				  0,
				  &disk_res,
				  &i_sectors_hook.hook,
				  &ei->journal_seq);

		i_sectors_dirty_put(ei, &i_sectors_hook);
		bch_disk_reservation_put(c, &disk_res);
	}
out:
	pagecache_block_put(&mapping->add_lock);
	inode_unlock(inode);

	return ret;
}

static long bch_fcollapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->i_mapping;
	struct bch_inode_info *ei = to_bch_ei(inode);
	struct cache_set *c = inode->i_sb->s_fs_info;
	struct btree_iter src;
	struct btree_iter dst;
	BKEY_PADDED(k) copy;
	struct bkey_s_c k;
	struct i_sectors_hook i_sectors_hook;
	loff_t new_size;
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
	 */
	inode_lock(inode);
	inode_dio_wait(inode);
	pagecache_block_get(&mapping->add_lock);

	ret = -EINVAL;
	if (offset + len >= inode->i_size)
		goto err;

	if (inode->i_size < len)
		goto err;

	new_size = inode->i_size - len;

	ret = write_invalidate_inode_pages_range(inode->i_mapping,
						 offset, LLONG_MAX);
	if (ret)
		goto err;

	ret = i_sectors_dirty_get(ei, &i_sectors_hook);
	if (ret)
		goto err;

	while (bkey_cmp(dst.pos,
			POS(inode->i_ino,
			    round_up(new_size, PAGE_SIZE) >> 9)) < 0) {
		struct disk_reservation disk_res;

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

		ret = bch_disk_reservation_get(c, &disk_res, copy.k.k.size,
					       BCH_DISK_RESERVATION_NOFAIL);
		BUG_ON(ret);

		ret = bch_btree_insert_at(&dst, &copy.k, &disk_res,
					  &i_sectors_hook.hook,
					  &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
		bch_disk_reservation_put(c, &disk_res);

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
	i_size_write(inode, new_size);
	ret = bch_write_inode_size(c, ei, inode->i_size);
	mutex_unlock(&ei->update_lock);

	pagecache_block_put(&mapping->add_lock);
	inode_unlock(inode);

	return ret;
err_unwind:
	/*
	 * XXX: we've left data with multiple pointers... which isn't a _super_
	 * serious problem...
	 */
	i_sectors_dirty_put(ei, &i_sectors_hook);
err:
	bch_btree_iter_unlock(&src);
	bch_btree_iter_unlock(&dst);
	pagecache_block_put(&mapping->add_lock);
	inode_unlock(inode);
	return ret;
}

static long bch_fallocate(struct inode *inode, int mode,
			  loff_t offset, loff_t len)
{
	struct address_space *mapping = inode->i_mapping;
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
	inode_dio_wait(inode);
	pagecache_block_get(&mapping->add_lock);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto err;
	}

	if (mode & FALLOC_FL_ZERO_RANGE) {
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
		struct disk_reservation disk_res = { 0 };

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
		}

		bkey_init(&reservation.k);
		reservation.k.type	= BCH_RESERVATION;
		reservation.k.p		= k.k->p;
		reservation.k.size	= k.k->size;

		bch_cut_front(iter.pos, &reservation);
		bch_cut_back(end, &reservation.k);

		sectors = reservation.k.size;

		if (!bkey_extent_is_allocation(k.k) ||
		    bkey_extent_is_compressed(c, k)) {
			ret = bch_disk_reservation_get(c, &disk_res,
						       sectors, 0);
			if (ret)
				goto err_put_sectors_dirty;
		}

		ret = bch_btree_insert_at(&iter, &reservation, &disk_res,
					  &i_sectors_hook.hook,
					  &ei->journal_seq,
					  BTREE_INSERT_ATOMIC|
					  BTREE_INSERT_NOFAIL);
		bch_disk_reservation_put(c, &disk_res);

		if (ret < 0 && ret != -EINTR)
			goto err_put_sectors_dirty;

	}
	bch_btree_iter_unlock(&iter);

	i_sectors_dirty_put(ei, &i_sectors_hook);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    new_size > inode->i_size) {
		i_size_write(inode, new_size);

		mutex_lock(&ei->update_lock);
		ret = bch_write_inode_size(c, ei, inode->i_size);
		mutex_unlock(&ei->update_lock);
	}

	/* blech */
	if ((mode & FALLOC_FL_KEEP_SIZE) &&
	    (mode & FALLOC_FL_ZERO_RANGE) &&
	    ei->i_size != inode->i_size) {
		/* sync appends.. */
		ret = filemap_write_and_wait_range(mapping, ei->i_size, S64_MAX);
		if (ret)
			goto err;

		if (ei->i_size != inode->i_size) {
			mutex_lock(&ei->update_lock);
			ret = bch_write_inode_size(c, ei, inode->i_size);
			mutex_unlock(&ei->update_lock);
		}
	}

	pagecache_block_put(&mapping->add_lock);
	inode_unlock(inode);

	return 0;
err_put_sectors_dirty:
	i_sectors_dirty_put(ei, &i_sectors_hook);
err:
	bch_btree_iter_unlock(&iter);
	pagecache_block_put(&mapping->add_lock);
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
	/* XXX: should only have to check PageDirty */
	return PagePrivate(page) &&
		(page_state(page)->sectors ||
		 page_state(page)->dirty_sectors);
}

static loff_t bch_next_pagecache_data(struct inode *inode,
				      loff_t start_offset,
				      loff_t end_offset)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	pgoff_t index;

	for (index = start_offset >> PAGE_SHIFT;
	     index < end_offset >> PAGE_SHIFT;
	     index++) {
		if (find_get_pages(mapping, index, 1, &page)) {
			lock_page(page);
			index = page->index;

			if (page_is_data(page))
				end_offset =
					min(end_offset,
					max(start_offset,
					    ((loff_t) index) << PAGE_SHIFT));
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

	for (index = start_offset >> PAGE_SHIFT;
	     index < end_offset >> PAGE_SHIFT;
	     index++)
		if (!page_slot_is_data(mapping, index))
			end_offset = max(start_offset,
					 ((loff_t) index) << PAGE_SHIFT);

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
