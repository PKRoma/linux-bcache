#ifndef _BCACHE_MOVE_H
#define _BCACHE_MOVE_H

#include "buckets.h"
#include "io_types.h"
#include <linux/semaphore.h>

struct move_context {
	struct closure		cl;
	struct semaphore	nr_pages_limit;
};

static inline void move_context_init(struct move_context *m)
{
	closure_init_stack(&m->cl);
	sema_init(&m->nr_pages_limit, (8 << 20) / PAGE_SIZE);
}

struct moving_io {
	struct closure		cl;

	struct bch_write_op	op;
	struct bch_replace_info	replace;
	BKEY_PADDED(key);

	struct bch_read_bio	rbio;
	struct bch_write_bio	wbio;
	/* Must be last since it is variable size */
	struct bio_vec		bi_inline_vecs[0];
};

void bch_moving_io_free(struct moving_io *);
struct moving_io *bch_moving_io_alloc(struct bkey_s_c);
void bch_data_move(struct move_context *, struct moving_io *);

#endif /* _BCACHE_MOVE_H */
