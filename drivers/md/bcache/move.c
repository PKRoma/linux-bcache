
#include "bcache.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
#include "io.h"
#include "move.h"
#include "super.h"
#include "keylist.h"

#include <trace/events/bcache.h>

static struct bch_extent_ptr *bkey_find_ptr(struct cache_set *c,
					    struct bkey_s_extent e,
					    struct bch_extent_ptr ptr)
{
	struct bch_extent_ptr *ptr2;
	struct cache_member_rcu *mi;
	unsigned bucket_bits;

	mi = cache_member_info_get(c);
	bucket_bits = ilog2(mi->m[ptr.dev].bucket_size);
	cache_member_info_put();

	extent_for_each_ptr(e, ptr2)
		if (ptr2->dev == ptr.dev &&
		    ptr2->gen == ptr.gen &&
		    (ptr2->offset >> bucket_bits) ==
		    (ptr.offset >> bucket_bits))
			return ptr2;

	return NULL;
}

static struct bch_extent_ptr *bch_migrate_matching_ptr(struct migrate_write *m,
						       struct bkey_s_extent e)
{
	const struct bch_extent_ptr *ptr;
	struct bch_extent_ptr *ret;

	if (m->move)
		ret = bkey_find_ptr(m->op.c, e, m->move_ptr);
	else
		extent_for_each_ptr(bkey_i_to_s_c_extent(&m->key), ptr)
			if ((ret = bkey_find_ptr(m->op.c, e, *ptr)))
				break;

	return ret;
}

static int bch_migrate_index_update(struct bch_write_op *op)
{
	struct cache_set *c = op->c;
	struct migrate_write *m =
		container_of(op, struct migrate_write, op);
	struct keylist *keys = &op->insert_keys;
	struct btree_iter iter;
	int ret = 0;

	bch_btree_iter_init_intent(&iter, c, BTREE_ID_EXTENTS,
		bkey_start_pos(&bch_keylist_front(keys)->k));

	while (1) {
		struct bkey_i *insert = bch_keylist_front(keys);
		struct bkey_s_c k = bch_btree_iter_peek_with_holes(&iter);
		struct bch_extent_ptr *ptr;
		struct bkey_s_extent e;
		BKEY_PADDED(k) new;

		if (!k.k) {
			ret = bch_btree_iter_unlock(&iter);
			break;
		}

		if (!bkey_extent_is_data(k.k))
			goto nomatch;

		bkey_reassemble(&new.k, k);
		bch_cut_front(iter.pos, &new.k);
		bch_cut_back(insert->k.p, &new.k.k);
		e = bkey_i_to_s_extent(&new.k);

		/* hack - promotes can race: */
		if (m->promote)
			extent_for_each_ptr(bkey_i_to_s_extent(insert), ptr)
				if (bch_extent_has_device(e.c, ptr->dev))
					goto nomatch;

		ptr = bch_migrate_matching_ptr(m, e);
		if (ptr) {
			if (m->move)
				__bch_extent_drop_ptr(e, ptr);

			memcpy_u64s(extent_entry_last(e),
				    &insert->v,
				    bkey_val_u64s(&insert->k));
			e.k->u64s += bkey_val_u64s(&insert->k);

			bch_extent_narrow_crcs(e);
			bch_extent_drop_redundant_crcs(e);
			bch_extent_normalize(c, e.s);

			ret = bch_btree_insert_at(c, &op->res,
					NULL, op_journal_seq(op),
					BTREE_INSERT_NOFAIL|BTREE_INSERT_ATOMIC,
					BTREE_INSERT_ENTRY(&iter, &new.k));
			if (ret && ret != -EINTR)
				break;
		} else {
nomatch:
			bch_btree_iter_advance_pos(&iter);
		}

		while (bkey_cmp(iter.pos, bch_keylist_front(keys)->k.p) >= 0) {
			bch_keylist_pop_front(keys);
			if (bch_keylist_empty(keys))
				goto out;
		}

		bch_cut_front(iter.pos, bch_keylist_front(keys));
	}
out:
	bch_btree_iter_unlock(&iter);
	return ret;
}

void bch_migrate_write_init(struct cache_set *c,
			    struct migrate_write *m,
			    struct write_point *wp,
			    struct bkey_s_c k,
			    const struct bch_extent_ptr *move_ptr,
			    unsigned flags)
{
	bkey_reassemble(&m->key, k);

	m->promote = false;
	m->move = move_ptr != NULL;
	if (move_ptr)
		m->move_ptr = *move_ptr;

	if (bkey_extent_is_cached(k.k))
		flags |= BCH_WRITE_CACHED;

	bch_write_op_init(&m->op, c, &m->wbio,
			  (struct disk_reservation) { 0 },
			  wp,
			  bkey_start_pos(k.k),
			  NULL, flags);

	m->op.nr_replicas	= 1;
	m->op.index_update_fn	= bch_migrate_index_update;
}

static void migrate_bio_init(struct moving_io *io, struct bio *bio,
			     unsigned sectors)
{
	bio_init(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= sectors << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(sectors, PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= io->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

static void moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->ctxt;

	//if (io->replace.failures)
	//	trace_bcache_copy_collision(q, &io->key.k);

	atomic_sub(io->write.key.k.size, &ctxt->sectors_in_flight);
	wake_up(&ctxt->wait);

	bch_bio_free_pages(&io->write.wbio.bio.bio);
	kfree(io);
}

static void moving_error(struct moving_context *ctxt, unsigned flag)
{
	atomic_inc(&ctxt->error_count);
	atomic_or(flag, &ctxt->error_flags);
}

static void moving_io_after_write(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->ctxt;

	if (io->write.op.error)
		moving_error(ctxt, MOVING_FLAG_WRITE);

	moving_io_destructor(cl);
}

static void write_moving(struct moving_io *io)
{
	struct bch_write_op *op = &io->write.op;

	if (op->error) {
		closure_return_with_destructor(&io->cl, moving_io_destructor);
	} else {
		closure_call(&op->cl, bch_write, NULL, &io->cl);
		closure_return_with_destructor(&io->cl, moving_io_after_write);
	}
}

static inline struct moving_io *next_pending_write(struct moving_context *ctxt)
{
	struct moving_io *io =
		list_first_entry_or_null(&ctxt->reads, struct moving_io, list);

	return io && io->read_completed ? io : NULL;
}

static void read_moving_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct moving_context *ctxt = io->ctxt;

	trace_bcache_move_read_done(&io->write.key.k);

	if (bio->bi_error) {
		io->write.op.error = bio->bi_error;
		moving_error(io->ctxt, MOVING_FLAG_READ);
	}

	io->read_completed = true;
	if (next_pending_write(ctxt))
		wake_up(&ctxt->wait);

	closure_put(&ctxt->cl);
}

static void __bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct cache_set *c = io->write.op.c;
	struct extent_pick_ptr pick;

	bch_extent_pick_ptr_avoiding(c, bkey_i_to_s_c(&io->write.key),
				     io->ctxt->avoid, &pick);
	if (IS_ERR_OR_NULL(pick.ca))
		closure_return_with_destructor(cl, moving_io_destructor);

	bio_set_op_attrs(&io->rbio.bio, REQ_OP_READ, 0);
	io->rbio.bio.bi_iter.bi_sector = bkey_start_offset(&io->write.key.k);
	io->rbio.bio.bi_end_io	= read_moving_endio;

	/*
	 * dropped by read_moving_endio() - guards against use after free of
	 * ctxt when doing wakeup
	 */
	closure_get(&io->ctxt->cl);

	bch_read_extent(c, &io->rbio,
			bkey_i_to_s_c(&io->write.key),
			&pick, BCH_READ_IS_LAST);
}

int bch_data_move(struct cache_set *c,
		  struct moving_context *ctxt,
		  struct write_point *wp,
		  struct bkey_s_c k,
		  const struct bch_extent_ptr *move_ptr)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec) *
		     DIV_ROUND_UP(k.k->size, PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return -ENOMEM;

	io->ctxt = ctxt;

	migrate_bio_init(io, &io->rbio.bio, k.k->size);

	if (bio_alloc_pages(&io->rbio.bio, GFP_KERNEL)) {
		kfree(io);
		return -ENOMEM;
	}

	migrate_bio_init(io, &io->write.wbio.bio.bio, k.k->size);
	bio_get(&io->write.wbio.bio.bio);
	io->write.wbio.bio.bio.bi_iter.bi_sector = bkey_start_offset(k.k);

	bch_migrate_write_init(c, &io->write, wp, k, move_ptr, 0);

	trace_bcache_move_read(&io->write.key.k);

	ctxt->keys_moved++;
	ctxt->sectors_moved += k.k->size;
	if (ctxt->rate)
		bch_ratelimit_increment(ctxt->rate, k.k->size);

	atomic_add(k.k->size, &ctxt->sectors_in_flight);
	list_add_tail(&io->list, &ctxt->reads);

	closure_call(&io->cl, __bch_data_move, NULL, &ctxt->cl);
	return 0;
}

static void do_pending_writes(struct moving_context *ctxt)
{
	struct moving_io *io;

	while ((io = next_pending_write(ctxt))) {
		list_del(&io->list);
		trace_bcache_move_write(&io->write.key.k);
		write_moving(io);
	}
}

#define move_ctxt_wait_event(_ctxt, _cond)			\
do {								\
	do_pending_writes(_ctxt);				\
								\
	if (_cond)						\
		break;						\
	__wait_event((_ctxt)->wait,				\
		     next_pending_write(_ctxt) || (_cond));	\
} while (1)

int bch_move_ctxt_wait(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt,
			     atomic_read(&ctxt->sectors_in_flight) <
			     ctxt->max_sectors_in_flight);

	return ctxt->rate
		? bch_ratelimit_wait_freezable_stoppable(ctxt->rate)
		: 0;
}

void bch_move_ctxt_wait_for_io(struct moving_context *ctxt)
{
	unsigned sectors_pending = atomic_read(&ctxt->sectors_in_flight);

	move_ctxt_wait_event(ctxt,
		!atomic_read(&ctxt->sectors_in_flight) ||
		atomic_read(&ctxt->sectors_in_flight) != sectors_pending);
}

void bch_move_ctxt_exit(struct moving_context *ctxt)
{
	move_ctxt_wait_event(ctxt, !atomic_read(&ctxt->sectors_in_flight));
	closure_sync(&ctxt->cl);

	EBUG_ON(!list_empty(&ctxt->reads));
	EBUG_ON(atomic_read(&ctxt->sectors_in_flight));
}

void bch_move_ctxt_init(struct moving_context *ctxt,
			struct bch_ratelimit *rate,
			unsigned max_sectors_in_flight)
{
	memset(ctxt, 0, sizeof(*ctxt));
	closure_init_stack(&ctxt->cl);

	ctxt->rate = rate;
	ctxt->max_sectors_in_flight = max_sectors_in_flight;

	INIT_LIST_HEAD(&ctxt->reads);
	init_waitqueue_head(&ctxt->wait);
}
