
#include "bcache.h"
#include "extents.h"
#include "io.h"
#include "move.h"

#include <trace/events/bcache.h>

void bch_moving_io_free(struct moving_io *io)
{
	bch_bio_free_pages(&io->bio.bio.bio);
	kfree(io);
}

static void bch_moving_io_destructor(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct move_context *m = container_of(cl->parent,
				struct move_context, cl);
	unsigned nr_pages = DIV_ROUND_UP(io->key.k.size, PAGE_SECTORS);

	while (nr_pages--)
		up(&m->nr_pages_limit);

	bch_moving_io_free(io);
}

static void moving_init(struct moving_io *io, struct bio *bio)
{
	bio_init(bio);
	bio_get(bio);
	bio_set_prio(bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

	bio->bi_iter.bi_size	= io->key.k.size << 9;
	bio->bi_max_vecs	= DIV_ROUND_UP(io->key.k.size,
					       PAGE_SECTORS);
	bio->bi_private		= &io->cl;
	bio->bi_io_vec		= io->bi_inline_vecs;
	bch_bio_map(bio, NULL);
}

static void write_moving(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (io->op.error)
		closure_return_with_destructor(&io->cl, bch_moving_io_destructor);

	moving_init(io);

	io->op.bio->bio.bio.bi_iter.bi_sector = bkey_start_offset(&io->key.k);

	closure_call(&io->op.cl, bch_write, NULL, &io->cl);
	closure_return_with_destructor(&io->cl, bch_moving_io_destructor);
}

static void read_moving_endio(struct bio *bio)
{
	struct closure *cl = bio->bi_private;
	struct moving_io *io = container_of(cl, struct moving_io, cl);

	if (bio->bi_error)
		io->op.error = bio->bi_error;

	closure_put(cl);
}

static void __bch_data_move(struct closure *cl)
{
	struct moving_io *io = container_of(cl, struct moving_io, cl);
	struct extent_pick_ptr pick;

	bch_extent_pick_ptr(io->op.c,
			    bkey_i_to_s_c(&io->key),
			    &pick);
	if (IS_ERR_OR_NULL(pick.ca))
		closure_return_with_destructor(cl, bch_moving_io_destructor);

	io->rbio.bio.bi_rw	= READ;
	io->rbio.bio.bi_iter.bi_sector = bkey_start_offset(&io->key.k);
	io->rbio.bio.bi_end_io	= read_moving_endio;

	closure_get(cl);
	bch_read_extent(io->op.c, &io->rbio,
			bkey_i_to_s_c(&io->key),
			&pick, BCH_READ_IS_LAST);

	continue_at(cl, write_moving, io->op.io_wq); /* XXX different wq */
}

void bch_data_move(struct move_context *m, struct moving_io *io)
{
	unsigned nr_pages = DIV_ROUND_UP(io->key.k.size, PAGE_SECTORS);

	while (nr_pages--)
		down(&m->nr_pages_limit);

	closure_call(&io->cl, __bch_data_move, NULL, &m->cl);
}

struct moving_io *bch_moving_io_alloc(struct bkey_s_c k)
{
	struct moving_io *io;

	io = kzalloc(sizeof(struct moving_io) + sizeof(struct bio_vec)
		     * DIV_ROUND_UP(k.k->size, PAGE_SECTORS),
		     GFP_KERNEL);
	if (!io)
		return NULL;

	bkey_reassemble(&io->key, k);

	moving_init(io);

	if (bio_alloc_pages(&io->bio.bio.bio, GFP_KERNEL)) {
		kfree(io);
		return NULL;
	}

	return io;
}
