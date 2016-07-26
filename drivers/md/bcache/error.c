#include "bcache.h"
#include "error.h"
#include "io.h"
#include "notify.h"
#include "super.h"

void bch_inconsistent_error(struct cache_set *c)
{
	switch (c->opts.errors) {
	case BCH_ON_ERROR_CONTINUE:
		break;
	case BCH_ON_ERROR_RO:
		if (!test_bit(CACHE_SET_INITIAL_GC_DONE, &c->flags)) {
			/* XXX do something better here? */
			bch_cache_set_stop(c);
			return;
		}

		if (bch_cache_set_emergency_read_only(c))
			__bch_cache_set_error(c, "emergency read only");
		break;
	case BCH_ON_ERROR_PANIC:
		panic("bcache: (%s) panic after error\n",
		      c->vfs_sb ? c->vfs_sb->s_id : c->uuid);
		break;
	}
}

void bch_fatal_error(struct cache_set *c)
{
	if (bch_cache_set_emergency_read_only(c))
		__bch_cache_set_error(c, "emergency read only");
}

/* Nonfatal IO errors, IO error/latency accounting: */

/* Just does IO error accounting: */
void bch_account_io_completion(struct cache *ca)
{
	/*
	 * The halflife of an error is:
	 * log2(1/2)/log2(127/128) * refresh ~= 88 * refresh
	 */

	if (ca->set->error_decay) {
		unsigned count = atomic_inc_return(&ca->io_count);

		while (count > ca->set->error_decay) {
			unsigned errors;
			unsigned old = count;
			unsigned new = count - ca->set->error_decay;

			/*
			 * First we subtract refresh from count; each time we
			 * succesfully do so, we rescale the errors once:
			 */

			count = atomic_cmpxchg(&ca->io_count, old, new);

			if (count == old) {
				count = new;

				errors = atomic_read(&ca->io_errors);
				do {
					old = errors;
					new = ((uint64_t) errors * 127) / 128;
					errors = atomic_cmpxchg(&ca->io_errors,
								old, new);
				} while (old != errors);
			}
		}
	}
}

/* IO error accounting and latency accounting: */
void bch_account_io_completion_time(struct cache *ca,
				    unsigned submit_time_us, int rw)
{
	struct cache_set *c;
	unsigned threshold;

	if (!ca)
		return;

	c = ca->set;
	threshold = rw & REQ_WRITE
		? c->congested_write_threshold_us
		: c->congested_read_threshold_us;

	if (threshold && submit_time_us) {
		unsigned t = local_clock_us();

		int us = t - submit_time_us;
		int congested = atomic_read(&c->congested);

		if (us > (int) threshold) {
			int ms = us / 1024;
			c->congested_last_us = t;

			ms = min(ms, CONGESTED_MAX + congested);
			atomic_sub(ms, &c->congested);
		} else if (congested < 0)
			atomic_inc(&c->congested);
	}

	bch_account_io_completion(ca);
}

void bch_nonfatal_io_error_work(struct work_struct *work)
{
	struct cache *ca = container_of(work, struct cache, io_error_work);
	struct cache_set *c = ca->set;
	unsigned errors = atomic_read(&ca->io_errors);
	char buf[BDEVNAME_SIZE];
	bool dev;

	if (errors < c->error_limit) {
		bch_notify_cache_error(ca, false);
	} else {
		bch_notify_cache_error(ca, true);

		mutex_lock(&bch_register_lock);
		dev = bch_cache_may_remove(ca);
		if (dev
		    ? bch_cache_read_only(ca)
		    : bch_cache_set_emergency_read_only(c))
			__bch_cache_set_error(c,
				"too many IO errors on %s, setting %s RO",
				bdevname(ca->disk_sb.bdev, buf),
				dev ? "device" : "filesystem");
		mutex_unlock(&bch_register_lock);
	}
}

void bch_nonfatal_io_error(struct cache *ca)
{
	atomic_add(1 << IO_ERROR_SHIFT, &ca->io_errors);
	queue_work(system_long_wq, &ca->io_error_work);
}
