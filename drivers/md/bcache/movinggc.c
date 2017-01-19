/*
 * Moving/copying garbage collector
 *
 * Copyright 2012 Google, Inc.
 */

#include "bcache.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "extents.h"
#include "io.h"
#include "keylist.h"
#include "move.h"
#include "movinggc.h"

#include <trace/events/bcache.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/wait.h>

/* Moving GC - IO loop */

static bool moving_pred(struct cache *ca, struct bkey_s_c k)
{
	struct cache_set *c = ca->set;
	const struct bch_extent_ptr *ptr;
	bool ret = false;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

		rcu_read_lock();
		extent_for_each_ptr(e, ptr)
			if (PTR_CACHE(c, ptr) == ca &&
			    PTR_BUCKET(ca, ptr)->copygc_gen)
				ret = true;
		rcu_read_unlock();
	}

	return ret;
}

static int issue_moving_gc_move(struct cache *ca,
				struct moving_context *ctxt,
				struct bkey_s_c k)
{
	struct moving_queue *q = &ca->moving_gc_queue;
	struct cache_set *c = ca->set;
	const struct bch_extent_ptr *ptr;
	struct moving_io *io;
	unsigned gen;

	extent_for_each_ptr(bkey_s_c_to_extent(k), ptr)
		if ((ca->sb.nr_this_dev == ptr->dev) &&
		    (gen = PTR_BUCKET(ca, ptr)->copygc_gen))
			goto found;

	/* We raced - bucket's been reused */
	return 0;
found:
	gen--;
	BUG_ON(gen > ARRAY_SIZE(ca->gc_buckets));

	io = moving_io_alloc(c, q, &ca->gc_buckets[gen], k, ptr);
	if (!io) {
		trace_bcache_moving_gc_alloc_fail(c, k.k->size);
		return -ENOMEM;
	}

	trace_bcache_gc_copy(k.k);

	bch_data_move(q, ctxt, io);
	return 0;
}

static void read_moving(struct cache *ca, struct moving_context *ctxt)
{
	struct cache_set *c = ca->set;
	struct btree_iter iter;
	struct bkey_s_c k;

	bch_ratelimit_reset(&ca->moving_gc_pd.rate);
	bch_btree_iter_init(&iter, c, BTREE_ID_EXTENTS, POS_MIN);

	while (!bch_moving_context_wait(ctxt) &&
	       (k = bch_btree_iter_peek(&iter)).k) {
		if (!moving_pred(ca, k))
			goto next;

		if (bch_queue_full(&ca->moving_gc_queue)) {
			bch_btree_iter_unlock(&iter);

			if (ca->moving_gc_queue.rotational)
				bch_queue_run(&ca->moving_gc_queue, ctxt);
			else
				wait_event(ca->moving_gc_queue.wait,
					!bch_queue_full(&ca->moving_gc_queue));
			continue;
		}

		if (issue_moving_gc_move(ca, ctxt, k)) {
			bch_btree_iter_unlock(&iter);

			/* memory allocation failure, wait for IOs to finish */
			bch_queue_run(&ca->moving_gc_queue, ctxt);
			continue;
		}
next:
		bch_btree_iter_advance_pos(&iter);
		//bch_btree_iter_cond_resched(&iter);

		/* unlock before calling moving_context_wait() */
		bch_btree_iter_unlock(&iter);
		cond_resched();
	}

	bch_btree_iter_unlock(&iter);
	bch_queue_run(&ca->moving_gc_queue, ctxt);
}

static bool have_copygc_reserve(struct cache *ca)
{
	bool ret;

	spin_lock(&ca->freelist_lock);
	ret = fifo_used(&ca->free[RESERVE_MOVINGGC]) >=
		COPYGC_BUCKETS_PER_ITER(ca);
	spin_unlock(&ca->freelist_lock);

	return ret;
}

static void bch_moving_gc(struct cache *ca)
{
	struct cache_set *c = ca->set;
	struct bucket *g;
	u64 sectors_to_move, sectors_gen, gen_current, sectors_total;
	size_t buckets_to_move, buckets_unused = 0;
	struct bucket_heap_entry e;
	unsigned sectors_used, i;
	int reserve_sectors;

	struct moving_context ctxt;

	bch_moving_context_init(&ctxt, &ca->moving_gc_pd.rate,
				MOVING_PURPOSE_COPY_GC);

	if (!have_copygc_reserve(ca)) {
		struct closure cl;

		closure_init_stack(&cl);
		while (1) {
			closure_wait(&c->freelist_wait, &cl);
			if (have_copygc_reserve(ca))
				break;
			closure_sync(&cl);
		}
		closure_wake_up(&c->freelist_wait);
	}

	reserve_sectors = COPYGC_SECTORS_PER_ITER(ca);

	trace_bcache_moving_gc_start(ca);

	/*
	 * Find buckets with lowest sector counts, skipping completely
	 * empty buckets, by building a maxheap sorted by sector count,
	 * and repeatedly replacing the maximum element until all
	 * buckets have been visited.
	 */

	/*
	 * We need bucket marks to be up to date, so gc can't be recalculating
	 * them, and we don't want the allocator invalidating a bucket after
	 * we've decided to evacuate it but before we set copygc_gen:
	 */
	down_read(&c->gc_lock);
	mutex_lock(&ca->heap_lock);
	mutex_lock(&ca->set->bucket_lock);

	ca->heap.used = 0;
	for_each_bucket(g, ca) {
		g->copygc_gen = 0;

		if (bucket_unused(g)) {
			buckets_unused++;
			continue;
		}

		if (g->mark.owned_by_allocator ||
		    g->mark.is_metadata)
			continue;

		sectors_used = bucket_sectors_used(g);

		if (sectors_used >= ca->mi.bucket_size)
			continue;

		bucket_heap_push(ca, g, sectors_used);
	}

	sectors_to_move = 0;
	for (i = 0; i < ca->heap.used; i++)
		sectors_to_move += ca->heap.data[i].val;

	while (sectors_to_move > COPYGC_SECTORS_PER_ITER(ca)) {
		BUG_ON(!heap_pop(&ca->heap, e, bucket_min_cmp));
		sectors_to_move -= e.val;
	}

	buckets_to_move = ca->heap.used;

	/*
	 * resort by write_prio to group into generations, attempts to
	 * keep hot and cold data in the same locality.
	 */

	for (i = 0; i < ca->heap.used; i++) {
		struct bucket_heap_entry *e = &ca->heap.data[i];

		e->val = (c->prio_clock[WRITE].hand - e->g->write_prio);
	}

	heap_resort(&ca->heap, bucket_max_cmp);

	sectors_gen = sectors_to_move / NUM_GC_GENS;
	gen_current = 1;
	sectors_total = 0;

	while (heap_pop(&ca->heap, e, bucket_max_cmp)) {
		sectors_total += bucket_sectors_used(e.g);
		e.g->copygc_gen = gen_current;
		if (gen_current < NUM_GC_GENS &&
		    sectors_total >= sectors_gen * gen_current)
			gen_current++;
	}

	mutex_unlock(&ca->set->bucket_lock);
	mutex_unlock(&ca->heap_lock);
	up_read(&c->gc_lock);

	read_moving(ca, &ctxt);

	if (IS_ENABLED(CONFIG_BCACHE_DEBUG)) {
		for_each_bucket(g, ca)
			BUG_ON(g->copygc_gen && bucket_sectors_used(g));
	}

	trace_bcache_moving_gc_end(ca, ctxt.sectors_moved, ctxt.keys_moved,
				buckets_to_move);
}

static int bch_moving_gc_thread(void *arg)
{
	struct cache *ca = arg;
	struct cache_set *c = ca->set;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last;
	u64 available, want, next;

	set_freezable();

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->copy_gc_enabled))
			break;

		last = atomic_long_read(&clock->now);
		/*
		 * don't start copygc until less than half the gc reserve is
		 * available:
		 */
		available = buckets_available_cache(ca);
		want = div64_u64((ca->mi.nbuckets - ca->mi.first_bucket) *
				 c->opts.gc_reserve_percent, 200);
		if (available > want) {
			next = last + (available - want) *
				ca->mi.bucket_size;
			bch_kthread_io_clock_wait(clock, next);
			continue;
		}

		bch_moving_gc(ca);
	}

	return 0;
}

#define MOVING_GC_NR 64
#define MOVING_GC_READ_NR 32
#define MOVING_GC_WRITE_NR 32

int bch_moving_init_cache(struct cache *ca)
{
	bool rotational = !blk_queue_nonrot(bdev_get_queue(ca->disk_sb.bdev));

	bch_pd_controller_init(&ca->moving_gc_pd);
	ca->moving_gc_pd.d_term = 0;

	return bch_queue_init(&ca->moving_gc_queue,
			      ca->set,
			      MOVING_GC_NR,
			      MOVING_GC_READ_NR,
			      MOVING_GC_WRITE_NR,
			      rotational,
			      "bch_copygc_write");
}

int bch_moving_gc_thread_start(struct cache *ca)
{
	struct task_struct *t;

	/* The moving gc read thread must be stopped */
	BUG_ON(ca->moving_gc_read != NULL);

	bch_queue_start(&ca->moving_gc_queue);

	if (cache_set_init_fault("moving_gc_start"))
		return -ENOMEM;

	t = kthread_create(bch_moving_gc_thread, ca, "bch_copygc_read");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ca->moving_gc_read = t;
	wake_up_process(ca->moving_gc_read);

	return 0;
}

void bch_moving_gc_stop(struct cache *ca)
{
	ca->moving_gc_pd.rate.rate = UINT_MAX;
	bch_ratelimit_reset(&ca->moving_gc_pd.rate);

	bch_queue_stop(&ca->moving_gc_queue);

	if (ca->moving_gc_read)
		kthread_stop(ca->moving_gc_read);
	ca->moving_gc_read = NULL;
}

void bch_moving_gc_destroy(struct cache *ca)
{
	bch_queue_destroy(&ca->moving_gc_queue);
}
