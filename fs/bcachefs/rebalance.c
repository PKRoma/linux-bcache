/*
 * Copygc, tiering:
 */

#include "bcache.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "io.h"
#include "move.h"

#include <trace/events/bcache.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/bsearch.h>
#include <linux/sort.h>

/*
 * XXX preserve ordering when reads complete out of order
 *
 * do performance testing with disk write cache off
 */

static inline bool rebalance_entry_sectors_cmp(struct rebalance_bucket_entry l,
					       struct rebalance_bucket_entry r)
{
	return l.sectors < r.sectors;
}

static int rebalance_entry_bucket_cmp(const void *_l, const void *_r)
{
	const struct rebalance_bucket_entry *l = _l;
	const struct rebalance_bucket_entry *r = _r;

	if (l->dev != r->dev)
		return l->dev < r->dev ? -1 : 1;
	if (l->bucket != r->bucket)
		return l->bucket < r->bucket ? -1 : 1;
	return 0;
}

static inline void rebalance_heap_push(struct rebalance_thread *r,
				       size_t bucket, u8 dev,
				       u8 gen, unsigned sectors)
{
	struct rebalance_bucket_entry new = {
		.bucket		= bucket,
		.dev		= dev,
		.gen		= gen,
		.sectors	= sectors,
	};

	if (!heap_full(&r->heap))
		heap_add(&r->heap, new, rebalance_entry_sectors_cmp);
	else if (rebalance_entry_sectors_cmp(new, heap_peek(&r->heap))) {
		r->heap.data[0] = new;
		heap_sift(&r->heap, 0, rebalance_entry_sectors_cmp);
	}
}

/* returns nr of extents that should be written to this tier: */
static unsigned should_tier_extent(struct cache_set *c,
				   struct rebalance_thread *r,
				   struct cache_member_rcu *mi,
				   struct bkey_s_c_extent e)
{
	const struct bch_extent_ptr *ptr;
	unsigned replicas = 0;

	/* Make sure we have room to add a new pointer: */
	if (bkey_val_u64s(e.k) + BKEY_EXTENT_PTR_U64s_MAX >
	    BKEY_EXTENT_VAL_U64s_MAX)
		return false;

	extent_for_each_ptr(e, ptr)
		if (PTR_TIER(mi, ptr) >= r->tier)
			replicas++;

	return replicas < c->opts.data_replicas
		? c->opts.data_replicas - replicas
		: 0;
}

static bool should_copygc_ptr(struct cache_set *c,
			      struct rebalance_thread *r,
			      struct cache_member_rcu *mi,
			      const struct bch_extent_ptr *ptr)
{
	struct cache *ca;
	bool ret = false;

	if (PTR_TIER(mi, ptr) == r->tier &&
	    (ca = PTR_CACHE(c, ptr))) {
		struct rebalance_bucket_entry *e, s = {
			.dev = ptr->dev,
			.bucket = PTR_BUCKET_NR(ca, ptr),
		};

		mutex_lock(&r->heap_lock);

		e = bsearch(&s,
			    r->heap.data,
			    r->heap.used,
			    sizeof(r->heap.data[0]),
			    rebalance_entry_bucket_cmp);
		if (e &&
		    e->gen == ptr->gen &&
		    e->gen == PTR_BUCKET_GEN(ca, ptr))
			ret = true;

		mutex_unlock(&r->heap_lock);
	}

	return ret;
}

static bool rebalance_pred(struct cache_set *c,
			   struct rebalance_thread *r,
			   struct bkey_s_c k)
{
	bool need_tier = false, need_copygc = false;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
		const struct bch_extent_ptr *ptr;
		struct cache_member_rcu *mi = cache_member_info_get(c);

		if (should_tier_extent(c, r, mi, e))
			need_tier = true;

		extent_for_each_ptr(e, ptr)
			if (should_copygc_ptr(c, r, mi, ptr))
				need_copygc = true;

		cache_member_info_put();
	}

	return need_tier || need_copygc;
}

static int rebalance_extent(struct cache_set *c,
			    struct rebalance_thread *r,
			    struct bkey_s_c k,
			    struct move_context *m)
{
	struct bkey_s_extent e;
	struct bch_extent_ptr *ptr;
	struct moving_io *io;
	unsigned nr_new_extents;
	bool have_faster_extent = false;
	struct cache_member_rcu *mi;

	io = bch_moving_io_alloc(k);
	if (!io) {
		//trace_bcache_moving_gc_alloc_fail(c, k.k->size);
		return -ENOMEM;
	}

	bch_replace_init(&io->replace, k);

	/* How the piss are reserves going to work? */

	bch_write_op_init(&io->op, c, &io->bio,
			  (struct disk_reservation) { 0 },
			  &r->wp, k,
			  &io->replace.hook, NULL,
			  bkey_extent_is_cached(k.k)
			  ? BCH_WRITE_CACHED : 0);

	io->op.io_wq = r->wq;

	e = bkey_i_to_s_extent(&io->op.insert_key);

	mi = cache_member_info_get(c);

	nr_new_extents = should_tier_extent(c, r, mi, e.c);

	extent_for_each_ptr_backwards(e, ptr) {
		if (PTR_TIER(mi, ptr) < r->tier) {
			if (have_faster_extent)
				bch_extent_drop_ptr(e, ptr);
			else
				have_faster_extent = true;
		}

		if (should_copygc_ptr(c, r, mi, ptr)) {
			bch_extent_drop_ptr(e, ptr);
			nr_new_extents++;
		}
	}

	cache_member_info_put();

	if (!nr_new_extents) {
		/* We raced - bucket's been reused */
		bch_moving_io_free(io);
		return 0;
	}
	io->op.nr_replicas	= nr_new_extents;

	bch_data_move(m, io);
	return 0;
}

static void rebalance_walk_extents(struct cache_set *c,
				   struct rebalance_thread *r)
{
	struct btree_iter iter;
	struct bkey_s_c k;
	struct move_context m;

	move_context_init(&m);
	bch_ratelimit_reset(&r->pd.rate);

	for_each_btree_key(&iter, c, BTREE_ID_EXTENTS, POS_MIN, k) {
		if (kthread_should_stop())
			break;

		if (rebalance_pred(c, r, k)) {
			BKEY_PADDED(k) tmp;

			bkey_reassemble(&tmp.k, k);
			bch_btree_iter_unlock(&iter);

			rebalance_extent(c, r,
					 bkey_i_to_s_c(&tmp.k),
					 &m);
		}

		bch_btree_iter_cond_resched(&iter);
	}
	bch_btree_iter_unlock(&iter);

	closure_sync(&m.cl);
}

static void bch_rebalance(struct cache_set *c, struct rebalance_thread *r)
{
	struct cache_group devs, *tier = &c->cache_tiers[r->tier];
	struct rebalance_bucket_entry e;
	unsigned i, seq, sectors_used;
	u64 sectors_to_move, reserve_sectors = 0;
	size_t buckets_unused = 0;

	rcu_read_lock();

	do {
		seq = read_seqcount_begin(&tier->lock);
		devs = *tier;
	} while (read_seqcount_retry(&tier->lock, seq));

	for (i = 0; i < devs.nr_devices; i++)
		percpu_ref_get(&rcu_dereference(devs.devices[i])->ref);

	rcu_read_unlock();

	mutex_lock(&r->heap_lock);

	r->heap.used = 0;

	for (i = 0; i < devs.nr_devices; i++) {
		struct cache *ca =
			rcu_dereference_protected(devs.devices[i], 1);
		size_t bucket;

		spin_lock(&ca->freelist_lock);
		reserve_sectors += ca->mi.bucket_size *
			fifo_used(&ca->free[RESERVE_MOVINGGC]);
		spin_unlock(&ca->freelist_lock);

		for (bucket = ca->mi.first_bucket;
		     bucket < ca->mi.nbuckets;
		     bucket++) {
			struct bucket *g = ca->buckets + bucket;

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

			rebalance_heap_push(r, bucket, ca->sb.nr_this_dev,
					    ca->bucket_gens[bucket],
					    sectors_used);
		}
	}

	/*
	 * Problems...
	 * XXX: wait on the allocator? perhaps the allocator just hasn't
	 * invalidated/discarded buckets we freed up from our last run?
	 */
	if (!reserve_sectors)
		goto out_put;

	sectors_to_move = 0;
	for (i = 0; i < r->heap.used; i++)
		sectors_to_move += r->heap.data[i].sectors;

	/*
	 * If there's not enough work to do, bail out so we aren't scanning the
	 * btree unnecessarily:
	 *
	 * XXX: calculate this threshold rigorously
	 */
#if 0
	if (r->heap.used < ca->free_inc.size / 2 &&
	    sectors_to_move < reserve_sectors)
		goto out_put;
#endif

	/* Pop buckets off until the they fit into our reserve: */
	while (sectors_to_move > reserve_sectors) {
		BUG_ON(!heap_pop(&r->heap, e, rebalance_entry_sectors_cmp));
		sectors_to_move -= e.sectors;
	}

	sort(r->heap.data,
	     r->heap.used,
	     sizeof(r->heap.data[0]),
	     rebalance_entry_bucket_cmp,
	     NULL);

	mutex_unlock(&r->heap_lock);

	for (i = 0; i < devs.nr_devices; i++)
		percpu_ref_put(&rcu_dereference_protected(devs.devices[i],
							  1)->ref);

	rebalance_walk_extents(c, r);
	return;

out_put:
	mutex_unlock(&r->heap_lock);
	for (i = 0; i < devs.nr_devices; i++)
		percpu_ref_put(&rcu_dereference(devs.devices[i])->ref);
}

static int bch_rebalance_thread(void *arg)
{
	struct rebalance_thread *r = arg;
	struct cache_set *c = container_of(r, struct cache_set,
					   rebalance[r->tier]);
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last;
	//bool moved;

	while (!kthread_should_stop()) {
		if (kthread_wait_freezable(c->copy_gc_enabled ||
					   c->tiering_enabled))
			break;

		last = atomic_long_read(&clock->now);

		bch_rebalance(c, r);

		/*
		 * This really should be a library code, but it has to be
		 * kthread specific... ugh
		 */
#if 0
		if (!moved)
			bch_kthread_io_clock_wait(clock,
					last + ca->free_inc.size / 2);
#endif
	}

	return 0;
}

static void bch_rebalance_exit_tier(struct rebalance_thread *r)
{
	if (r->p)
		kthread_stop(r->p);
	r->p = NULL;
	if (r->wq)
		destroy_workqueue(r->wq);
	r->wq = NULL;
	free_heap(&r->heap);
}

void bch_rebalance_exit(struct cache_set *c)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(c->rebalance); i++)
		bch_rebalance_exit_tier(&c->rebalance[i]);
}

/*
 * Called whenever we add a device - initializes the per tier rebalance thread,
 * or resizes the heap if necessary
 */
int bch_rebalance_init(struct cache_set *c, struct cache *ca)
{
	unsigned tier = ca->mi.tier;
	struct rebalance_thread *r = &c->rebalance[tier];
	struct task_struct *p;
	u64 nbuckets = 0;
	size_t heap_size;
	unsigned i;
	typeof(r->heap) old_heap;

	lockdep_assert_held(&bch_register_lock);

	if (!r->initialized) {
		r->tier = tier;
		mutex_init(&r->heap_lock);
		r->wp.group = &c->cache_tiers[tier];
		r->wp.reserve = RESERVE_MOVINGGC; /* XXX */
		r->initialized = 1;
	}

	if (!r->wq)
		r->wq = create_workqueue("bch_rebalance_io");
	if (!r->wq)
		return -ENOMEM;

	if (!r->p) {
		p = kthread_create(bch_rebalance_thread, r,
				   "bch_rebalance");
		if (IS_ERR(p))
			return PTR_ERR(p);

		r->p = p;
	}

	/* ca hasn't been added to array of devices yet: */
	nbuckets += ca->mi.nbuckets;

	rcu_read_lock();
	for_each_cache_rcu(ca, c, i)
		if (ca->mi.tier == tier)
			nbuckets += ca->mi.nbuckets;
	rcu_read_unlock();

	mutex_lock(&r->heap_lock);
	old_heap = r->heap;

	heap_size = max_t(size_t, nbuckets >> 7, old_heap.used);
	BUG_ON(!heap_size);

	if (!init_heap(&r->heap, heap_size, GFP_KERNEL)) {
		mutex_unlock(&r->heap_lock);
		return -ENOMEM;
	}

	if (old_heap.data) {
		memcpy(r->heap.data,
		       old_heap.data,
		       sizeof(old_heap.data[0]) * old_heap.used);
		r->heap.used = old_heap.used;
		free_heap(&old_heap);
	}

	mutex_unlock(&r->heap_lock);

	return 0;
}
