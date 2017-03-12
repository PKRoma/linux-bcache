#ifndef _BCACHE_H
#define _BCACHE_H

/*
 * SOME HIGH LEVEL CODE DOCUMENTATION:
 *
 * Bcache mostly works with cache sets, cache devices, and backing devices.
 *
 * Support for multiple cache devices hasn't quite been finished off yet, but
 * it's about 95% plumbed through. A cache set and its cache devices is sort of
 * like a md raid array and its component devices. Most of the code doesn't care
 * about individual cache devices, the main abstraction is the cache set.
 *
 * Multiple cache devices is intended to give us the ability to mirror dirty
 * cached data and metadata, without mirroring clean cached data.
 *
 * Backing devices are different, in that they have a lifetime independent of a
 * cache set. When you register a newly formatted backing device it'll come up
 * in passthrough mode, and then you can attach and detach a backing device from
 * a cache set at runtime - while it's mounted and in use. Detaching implicitly
 * invalidates any cached data for that backing device.
 *
 * A cache set can have multiple (many) backing devices attached to it.
 *
 * There's also flash only volumes - this is the reason for the distinction
 * between struct cached_dev and struct bcache_device. A flash only volume
 * works much like a bcache device that has a backing device, except the
 * "cached" data is always dirty. The end result is that we get thin
 * provisioning with very little additional code.
 *
 * Flash only volumes work but they're not production ready because the moving
 * garbage collector needs more work. More on that later.
 *
 * BUCKETS/ALLOCATION:
 *
 * Bcache is primarily designed for caching, which means that in normal
 * operation all of our available space will be allocated. Thus, we need an
 * efficient way of deleting things from the cache so we can write new things to
 * it.
 *
 * To do this, we first divide the cache device up into buckets. A bucket is the
 * unit of allocation; they're typically around 1 mb - anywhere from 128k to 2M+
 * works efficiently.
 *
 * Each bucket has a 16 bit priority, and an 8 bit generation associated with
 * it. The gens and priorities for all the buckets are stored contiguously and
 * packed on disk (in a linked list of buckets - aside from the superblock, all
 * of bcache's metadata is stored in buckets).
 *
 * The priority is used to implement an LRU. We reset a bucket's priority when
 * we allocate it or on cache it, and every so often we decrement the priority
 * of each bucket. It could be used to implement something more sophisticated,
 * if anyone ever gets around to it.
 *
 * The generation is used for invalidating buckets. Each pointer also has an 8
 * bit generation embedded in it; for a pointer to be considered valid, its gen
 * must match the gen of the bucket it points into.  Thus, to reuse a bucket all
 * we have to do is increment its gen (and write its new gen to disk; we batch
 * this up).
 *
 * Bcache is entirely COW - we never write twice to a bucket, even buckets that
 * contain metadata (including btree nodes).
 *
 * THE BTREE:
 *
 * Bcache is in large part design around the btree.
 *
 * At a high level, the btree is just an index of key -> ptr tuples.
 *
 * Keys represent extents, and thus have a size field. Keys also have a variable
 * number of pointers attached to them (potentially zero, which is handy for
 * invalidating the cache).
 *
 * The key itself is an inode:offset pair. The inode number corresponds to a
 * backing device or a flash only volume. The offset is the ending offset of the
 * extent within the inode - not the starting offset; this makes lookups
 * slightly more convenient.
 *
 * Pointers contain the cache device id, the offset on that device, and an 8 bit
 * generation number. More on the gen later.
 *
 * Index lookups are not fully abstracted - cache lookups in particular are
 * still somewhat mixed in with the btree code, but things are headed in that
 * direction.
 *
 * Updates are fairly well abstracted, though. There are two different ways of
 * updating the btree; insert and replace.
 *
 * BTREE_INSERT will just take a list of keys and insert them into the btree -
 * overwriting (possibly only partially) any extents they overlap with. This is
 * used to update the index after a write.
 *
 * BTREE_REPLACE is really cmpxchg(); it inserts a key into the btree iff it is
 * overwriting a key that matches another given key. This is used for inserting
 * data into the cache after a cache miss, and for background writeback, and for
 * the moving garbage collector.
 *
 * There is no "delete" operation; deleting things from the index is
 * accomplished by either by invalidating pointers (by incrementing a bucket's
 * gen) or by inserting a key with 0 pointers - which will overwrite anything
 * previously present at that location in the index.
 *
 * This means that there are always stale/invalid keys in the btree. They're
 * filtered out by the code that iterates through a btree node, and removed when
 * a btree node is rewritten.
 *
 * BTREE NODES:
 *
 * Our unit of allocation is a bucket, and we we can't arbitrarily allocate and
 * free smaller than a bucket - so, that's how big our btree nodes are.
 *
 * (If buckets are really big we'll only use part of the bucket for a btree node
 * - no less than 1/4th - but a bucket still contains no more than a single
 * btree node. I'd actually like to change this, but for now we rely on the
 * bucket's gen for deleting btree nodes when we rewrite/split a node.)
 *
 * Anyways, btree nodes are big - big enough to be inefficient with a textbook
 * btree implementation.
 *
 * The way this is solved is that btree nodes are internally log structured; we
 * can append new keys to an existing btree node without rewriting it. This
 * means each set of keys we write is sorted, but the node is not.
 *
 * We maintain this log structure in memory - keeping 1Mb of keys sorted would
 * be expensive, and we have to distinguish between the keys we have written and
 * the keys we haven't. So to do a lookup in a btree node, we have to search
 * each sorted set. But we do merge written sets together lazily, so the cost of
 * these extra searches is quite low (normally most of the keys in a btree node
 * will be in one big set, and then there'll be one or two sets that are much
 * smaller).
 *
 * This log structure makes bcache's btree more of a hybrid between a
 * conventional btree and a compacting data structure, with some of the
 * advantages of both.
 *
 * GARBAGE COLLECTION:
 *
 * We can't just invalidate any bucket - it might contain dirty data or
 * metadata. If it once contained dirty data, other writes might overwrite it
 * later, leaving no valid pointers into that bucket in the index.
 *
 * Thus, the primary purpose of garbage collection is to find buckets to reuse.
 * It also counts how much valid data it each bucket currently contains, so that
 * allocation can reuse buckets sooner when they've been mostly overwritten.
 *
 * It also does some things that are really internal to the btree
 * implementation. If a btree node contains pointers that are stale by more than
 * some threshold, it rewrites the btree node to avoid the bucket's generation
 * wrapping around. It also merges adjacent btree nodes if they're empty enough.
 *
 * THE JOURNAL:
 *
 * Bcache's journal is not necessary for consistency; we always strictly
 * order metadata writes so that the btree and everything else is consistent on
 * disk in the event of an unclean shutdown, and in fact bcache had writeback
 * caching (with recovery from unclean shutdown) before journalling was
 * implemented.
 *
 * Rather, the journal is purely a performance optimization; we can't complete a
 * write until we've updated the index on disk, otherwise the cache would be
 * inconsistent in the event of an unclean shutdown. This means that without the
 * journal, on random write workloads we constantly have to update all the leaf
 * nodes in the btree, and those writes will be mostly empty (appending at most
 * a few keys each) - highly inefficient in terms of amount of metadata writes,
 * and it puts more strain on the various btree resorting/compacting code.
 *
 * The journal is just a log of keys we've inserted; on startup we just reinsert
 * all the keys in the open journal entries. That means that when we're updating
 * a node in the btree, we can wait until a 4k block of keys fills up before
 * writing them out.
 *
 * For simplicity, we only journal updates to leaf nodes; updates to parent
 * nodes are rare enough (since our leaf nodes are huge) that it wasn't worth
 * the complexity to deal with journalling them (in particular, journal replay)
 * - updates to non leaf nodes just happen synchronously (see btree_split()).
 */

#undef pr_fmt
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/bug.h>
#include <linux/bcache.h>
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/lglock.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu-refcount.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rhashtable.h>
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "bset.h"
#include "fifo.h"
#include "util.h"
#include "closure.h"
#include "opts.h"

#include <linux/dynamic_fault.h>

#define bch_fs_init_fault(name)						\
	dynamic_fault("bcache:bch_fs_init:" name)
#define bch_meta_read_fault(name)					\
	 dynamic_fault("bcache:meta:read:" name)
#define bch_meta_write_fault(name)					\
	 dynamic_fault("bcache:meta:write:" name)

#ifndef bch_fmt
#define bch_fmt(_c, fmt)	"bcache (%s): " fmt "\n", ((_c)->name)
#endif

#define bch_info(c, fmt, ...) \
	printk(KERN_INFO bch_fmt(c, fmt), ##__VA_ARGS__)
#define bch_notice(c, fmt, ...) \
	printk(KERN_NOTICE bch_fmt(c, fmt), ##__VA_ARGS__)
#define bch_warn(c, fmt, ...) \
	printk(KERN_WARNING bch_fmt(c, fmt), ##__VA_ARGS__)
#define bch_err(c, fmt, ...) \
	printk(KERN_ERR bch_fmt(c, fmt), ##__VA_ARGS__)

#define bch_verbose(c, fmt, ...)					\
do {									\
	if ((c)->opts.verbose_recovery)					\
		bch_info(c, fmt, ##__VA_ARGS__);			\
} while (0)

/* Parameters that are useful for debugging, but should always be compiled in: */
#define BCH_DEBUG_PARAMS_ALWAYS()					\
	BCH_DEBUG_PARAM(key_merging_disabled,				\
		"Disables merging of extents")				\
	BCH_DEBUG_PARAM(btree_gc_always_rewrite,			\
		"Causes mark and sweep to compact and rewrite every "	\
		"btree node it traverses")				\
	BCH_DEBUG_PARAM(btree_gc_rewrite_disabled,			\
		"Disables rewriting of btree nodes during mark and sweep")\
	BCH_DEBUG_PARAM(btree_gc_coalesce_disabled,			\
		"Disables coalescing of btree nodes")			\
	BCH_DEBUG_PARAM(btree_shrinker_disabled,			\
		"Disables the shrinker callback for the btree node cache")

/* Parameters that should only be compiled in in debug mode: */
#define BCH_DEBUG_PARAMS_DEBUG()					\
	BCH_DEBUG_PARAM(expensive_debug_checks,				\
		"Enables various runtime debugging checks that "	\
		"significantly affect performance")			\
	BCH_DEBUG_PARAM(debug_check_bkeys,				\
		"Run bkey_debugcheck (primarily checking GC/allocation "\
		"information) when iterating over keys")		\
	BCH_DEBUG_PARAM(version_stress_test,				\
		"Assigns random version numbers to newly written "	\
		"extents, to test overlapping extent cases")		\
	BCH_DEBUG_PARAM(verify_btree_ondisk,				\
		"Reread btree nodes at various points to verify the "	\
		"mergesort in the read path against modifications "	\
		"done in memory")					\

#define BCH_DEBUG_PARAMS_ALL() BCH_DEBUG_PARAMS_ALWAYS() BCH_DEBUG_PARAMS_DEBUG()

#ifdef CONFIG_BCACHE_DEBUG
#define BCH_DEBUG_PARAMS() BCH_DEBUG_PARAMS_ALL()
#else
#define BCH_DEBUG_PARAMS() BCH_DEBUG_PARAMS_ALWAYS()
#endif

/* name, frequency_units, duration_units */
#define BCH_TIME_STATS()						\
	BCH_TIME_STAT(mca_alloc,		sec, us)		\
	BCH_TIME_STAT(mca_scan,			sec, ms)		\
	BCH_TIME_STAT(btree_gc,			sec, ms)		\
	BCH_TIME_STAT(btree_coalesce,		sec, ms)		\
	BCH_TIME_STAT(btree_split,		sec, us)		\
	BCH_TIME_STAT(btree_sort,		ms, us)			\
	BCH_TIME_STAT(btree_read,		ms, us)			\
	BCH_TIME_STAT(journal_write,		us, us)			\
	BCH_TIME_STAT(journal_delay,		ms, us)			\
	BCH_TIME_STAT(journal_blocked,		sec, ms)		\
	BCH_TIME_STAT(journal_flush_seq,	us, us)

#include "alloc_types.h"
#include "blockdev_types.h"
#include "buckets_types.h"
#include "clock_types.h"
#include "io_types.h"
#include "journal_types.h"
#include "keylist_types.h"
#include "keybuf_types.h"
#include "move_types.h"
#include "stats_types.h"
#include "super_types.h"

/* 256k, in sectors */
#define BTREE_NODE_SIZE_MAX		512

/*
 * Number of nodes we might have to allocate in a worst case btree split
 * operation - we split all the way up to the root, then allocate a new root.
 */
#define btree_reserve_required_nodes(depth)	(((depth) + 1) * 2 + 1)

/* Number of nodes btree coalesce will try to coalesce at once */
#define GC_MERGE_NODES		4U

/* Maximum number of nodes we might need to allocate atomically: */
#define BTREE_RESERVE_MAX						\
	(btree_reserve_required_nodes(BTREE_MAX_DEPTH) + GC_MERGE_NODES)

/* Size of the freelist we allocate btree nodes from: */
#define BTREE_NODE_RESERVE		(BTREE_RESERVE_MAX * 2)

struct btree;
struct crypto_blkcipher;
struct crypto_ahash;

enum gc_phase {
	GC_PHASE_SB_METADATA		= BTREE_ID_NR + 1,
	GC_PHASE_PENDING_DELETE,
	GC_PHASE_DONE
};

struct gc_pos {
	enum gc_phase		phase;
	struct bpos		pos;
	unsigned		level;
};

struct bch_member_cpu {
	u64			nbuckets;	/* device size */
	u16			first_bucket;   /* index of first bucket used */
	u16			bucket_size;	/* sectors */
	u8			state;
	u8			tier;
	u8			has_metadata;
	u8			has_data;
	u8			replacement;
	u8			discard;
	u8			valid;
};

struct bch_dev {
	struct kobject		kobj;
	struct percpu_ref	ref;
	struct percpu_ref	io_ref;
	struct completion	stop_complete;
	struct completion	offline_complete;

	struct bch_fs		*fs;

	u8			dev_idx;
	/*
	 * Cached version of this device's member info from superblock
	 * Committed by bch_write_super() -> bch_fs_mi_update()
	 */
	struct bch_member_cpu	mi;
	uuid_le			uuid;
	char			name[BDEVNAME_SIZE];

	struct bcache_superblock disk_sb;

	struct dev_group	self;

	/* biosets used in cloned bios for replicas and moving_gc */
	struct bio_set		replica_set;

	struct task_struct	*alloc_thread;

	struct prio_set		*disk_buckets;

	/*
	 * When allocating new buckets, prio_write() gets first dibs - since we
	 * may not be allocate at all without writing priorities and gens.
	 * prio_last_buckets[] contains the last buckets we wrote priorities to
	 * (so gc can mark them as metadata).
	 */
	u64			*prio_buckets;
	u64			*prio_last_buckets;
	spinlock_t		prio_buckets_lock;
	struct bio		*bio_prio;

	/*
	 * free: Buckets that are ready to be used
	 *
	 * free_inc: Incoming buckets - these are buckets that currently have
	 * cached data in them, and we can't reuse them until after we write
	 * their new gen to disk. After prio_write() finishes writing the new
	 * gens/prios, they'll be moved to the free list (and possibly discarded
	 * in the process)
	 */
	DECLARE_FIFO(long, free)[RESERVE_NR];
	DECLARE_FIFO(long, free_inc);
	spinlock_t		freelist_lock;

	size_t			fifo_last_bucket;

	/* Allocation stuff: */

	/* most out of date gen in the btree */
	u8			*oldest_gens;
	struct bucket		*buckets;
	unsigned short		bucket_bits;	/* ilog2(bucket_size) */

	/* last calculated minimum prio */
	u16			min_prio[2];

	/*
	 * Bucket book keeping. The first element is updated by GC, the
	 * second contains a saved copy of the stats from the beginning
	 * of GC.
	 */
	struct bch_dev_usage __percpu *usage_percpu;
	struct bch_dev_usage	usage_cached;

	atomic_long_t		saturated_count;
	size_t			inc_gen_needs_gc;

	struct mutex		heap_lock;
	DECLARE_HEAP(struct bucket_heap_entry, heap);

	/* Moving GC: */
	struct task_struct	*moving_gc_read;

	struct bch_pd_controller moving_gc_pd;

	/* Tiering: */
	struct write_point	tiering_write_point;

	struct write_point	copygc_write_point;

	struct journal_device	journal;

	struct work_struct	io_error_work;

	/* The rest of this all shows up in sysfs */
#define IO_ERROR_SHIFT		20
	atomic_t		io_errors;
	atomic_t		io_count;

	atomic64_t		meta_sectors_written;
	atomic64_t		btree_sectors_written;
	u64 __percpu		*sectors_written;
};

/*
 * Flag bits for what phase of startup/shutdown the cache set is at, how we're
 * shutting down, etc.:
 *
 * BCH_FS_UNREGISTERING means we're not just shutting down, we're detaching
 * all the backing devices first (their cached data gets invalidated, and they
 * won't automatically reattach).
 */
enum {
	BCH_FS_INITIAL_GC_DONE,
	BCH_FS_DETACHING,
	BCH_FS_EMERGENCY_RO,
	BCH_FS_WRITE_DISABLE_COMPLETE,
	BCH_FS_GC_STOPPING,
	BCH_FS_GC_FAILURE,
	BCH_FS_BDEV_MOUNTED,
	BCH_FS_ERROR,
	BCH_FS_FSCK_FIXED_ERRORS,
};

struct btree_debug {
	unsigned		id;
	struct dentry		*btree;
	struct dentry		*btree_format;
	struct dentry		*failed;
};

struct bch_tier {
	unsigned		idx;
	struct task_struct	*migrate;
	struct bch_pd_controller pd;

	struct dev_group	devs;
};

enum bch_fs_state {
	BCH_FS_STARTING		= 0,
	BCH_FS_STOPPING,
	BCH_FS_RO,
	BCH_FS_RW,
};

struct bch_fs {
	struct closure		cl;

	struct list_head	list;
	struct kobject		kobj;
	struct kobject		internal;
	struct kobject		opts_dir;
	struct kobject		time_stats;
	unsigned long		flags;

	int			minor;
	struct device		*chardev;
	struct super_block	*vfs_sb;
	char			name[40];

	/* ro/rw, add/remove devices: */
	struct mutex		state_lock;
	enum bch_fs_state	state;

	/* Counts outstanding writes, for clean transition to read-only */
	struct percpu_ref	writes;
	struct work_struct	read_only_work;

	struct bch_dev __rcu	*devs[BCH_SB_MEMBERS_MAX];

	struct bch_opts		opts;

	/* Updated by bch_sb_update():*/
	struct {
		uuid_le		uuid;
		uuid_le		user_uuid;

		u16		block_size;
		u16		btree_node_size;

		u8		nr_devices;
		u8		clean;

		u8		meta_replicas_have;
		u8		data_replicas_have;

		u8		str_hash_type;
		u8		encryption_type;

		u64		time_base_lo;
		u32		time_base_hi;
		u32		time_precision;
	}			sb;

	struct bch_sb		*disk_sb;
	unsigned		disk_sb_order;

	unsigned short		block_bits;	/* ilog2(block_size) */

	struct closure		sb_write;
	struct mutex		sb_lock;

	struct backing_dev_info bdi;

	/* BTREE CACHE */
	struct bio_set		btree_read_bio;

	struct btree_root	btree_roots[BTREE_ID_NR];
	struct mutex		btree_root_lock;

	bool			btree_cache_table_init_done;
	struct rhashtable	btree_cache_table;

	/*
	 * We never free a struct btree, except on shutdown - we just put it on
	 * the btree_cache_freed list and reuse it later. This simplifies the
	 * code, and it doesn't cost us much memory as the memory usage is
	 * dominated by buffers that hold the actual btree node data and those
	 * can be freed - and the number of struct btrees allocated is
	 * effectively bounded.
	 *
	 * btree_cache_freeable effectively is a small cache - we use it because
	 * high order page allocations can be rather expensive, and it's quite
	 * common to delete and allocate btree nodes in quick succession. It
	 * should never grow past ~2-3 nodes in practice.
	 */
	struct mutex		btree_cache_lock;
	struct list_head	btree_cache;
	struct list_head	btree_cache_freeable;
	struct list_head	btree_cache_freed;

	/* Number of elements in btree_cache + btree_cache_freeable lists */
	unsigned		btree_cache_used;
	unsigned		btree_cache_reserve;
	struct shrinker		btree_cache_shrink;

	/*
	 * If we need to allocate memory for a new btree node and that
	 * allocation fails, we can cannibalize another node in the btree cache
	 * to satisfy the allocation - lock to guarantee only one thread does
	 * this at a time:
	 */
	struct closure_waitlist	mca_wait;
	struct task_struct	*btree_cache_alloc_lock;

	mempool_t		btree_reserve_pool;

	/*
	 * Cache of allocated btree nodes - if we allocate a btree node and
	 * don't use it, if we free it that space can't be reused until going
	 * _all_ the way through the allocator (which exposes us to a livelock
	 * when allocating btree reserves fail halfway through) - instead, we
	 * can stick them here:
	 */
	struct btree_alloc {
		struct open_bucket	*ob;
		BKEY_PADDED(k);
	}			btree_reserve_cache[BTREE_NODE_RESERVE * 2];
	unsigned		btree_reserve_cache_nr;
	struct mutex		btree_reserve_cache_lock;

	mempool_t		btree_interior_update_pool;
	struct list_head	btree_interior_update_list;
	struct mutex		btree_interior_update_lock;

	struct workqueue_struct	*wq;
	/* copygc needs its own workqueue for index updates.. */
	struct workqueue_struct	*copygc_wq;

	/* ALLOCATION */
	struct bch_pd_controller foreground_write_pd;
	struct delayed_work	pd_controllers_update;
	unsigned		pd_controllers_update_seconds;
	spinlock_t		foreground_write_pd_lock;
	struct bch_write_op	*write_wait_head;
	struct bch_write_op	*write_wait_tail;

	struct timer_list	foreground_write_wakeup;

	/*
	 * These contain all r/w devices - i.e. devices we can currently
	 * allocate from:
	 */
	struct dev_group	all_devs;
	struct bch_tier		tiers[BCH_TIER_MAX];
	/* NULL if we only have devices in one tier: */
	struct bch_tier		*fastest_tier;

	u64			capacity; /* sectors */

	/*
	 * When capacity _decreases_ (due to a disk being removed), we
	 * increment capacity_gen - this invalidates outstanding reservations
	 * and forces them to be revalidated
	 */
	u32			capacity_gen;

	atomic64_t		sectors_available;

	struct bch_fs_usage __percpu *usage_percpu;
	struct bch_fs_usage	usage_cached;
	struct lglock		usage_lock;

	struct mutex		bucket_lock;

	struct closure_waitlist	freelist_wait;

	/*
	 * When we invalidate buckets, we use both the priority and the amount
	 * of good data to determine which buckets to reuse first - to weight
	 * those together consistently we keep track of the smallest nonzero
	 * priority of any bucket.
	 */
	struct prio_clock	prio_clock[2];

	struct io_clock		io_clock[2];

	/* SECTOR ALLOCATOR */
	struct list_head	open_buckets_open;
	struct list_head	open_buckets_free;
	unsigned		open_buckets_nr_free;
	struct closure_waitlist	open_buckets_wait;
	spinlock_t		open_buckets_lock;
	struct open_bucket	open_buckets[OPEN_BUCKETS_COUNT];

	struct write_point	btree_write_point;

	struct write_point	write_points[WRITE_POINT_COUNT];
	struct write_point	promote_write_point;

	/*
	 * This write point is used for migrating data off a device
	 * and can point to any other device.
	 * We can't use the normal write points because those will
	 * gang up n replicas, and for migration we want only one new
	 * replica.
	 */
	struct write_point	migration_write_point;

	/* GARBAGE COLLECTION */
	struct task_struct	*gc_thread;
	atomic_t		kick_gc;

	/*
	 * Tracks GC's progress - everything in the range [ZERO_KEY..gc_cur_pos]
	 * has been marked by GC.
	 *
	 * gc_cur_phase is a superset of btree_ids (BTREE_ID_EXTENTS etc.)
	 *
	 * gc_cur_phase == GC_PHASE_DONE indicates that gc is finished/not
	 * currently running, and gc marks are currently valid
	 *
	 * Protected by gc_pos_lock. Only written to by GC thread, so GC thread
	 * can read without a lock.
	 */
	seqcount_t		gc_pos_lock;
	struct gc_pos		gc_pos;

	/*
	 * The allocation code needs gc_mark in struct bucket to be correct, but
	 * it's not while a gc is in progress.
	 */
	struct rw_semaphore	gc_lock;

	/* IO PATH */
	struct bio_set		bio_read;
	struct bio_set		bio_read_split;
	struct bio_set		bio_write;
	struct mutex		bio_bounce_pages_lock;
	mempool_t		bio_bounce_pages;

	mempool_t		lz4_workspace_pool;
	void			*zlib_workspace;
	struct mutex		zlib_workspace_lock;
	mempool_t		compression_bounce[2];
	struct bio_decompress_worker __percpu
				*bio_decompress_worker;

	struct crypto_blkcipher	*chacha20;
	struct crypto_shash	*poly1305;

	atomic64_t		key_version;

	/* For punting bio submissions to workqueue, io.c */
	struct bio_list		bio_submit_list;
	struct work_struct	bio_submit_work;
	spinlock_t		bio_submit_lock;

	struct bio_list		read_retry_list;
	struct work_struct	read_retry_work;
	spinlock_t		read_retry_lock;

	/* FILESYSTEM */
	wait_queue_head_t	writeback_wait;
	atomic_t		writeback_pages;
	unsigned		writeback_pages_max;
	atomic_long_t		nr_inodes;

	/* NOTIFICATIONS */
	struct mutex		uevent_lock;
	struct kobj_uevent_env	uevent_env;

	/* DEBUG JUNK */
	struct dentry		*debug;
	struct btree_debug	btree_debug[BTREE_ID_NR];
#ifdef CONFIG_BCACHE_DEBUG
	struct btree		*verify_data;
	struct btree_node	*verify_ondisk;
	struct mutex		verify_lock;
#endif

	u64			unused_inode_hint;

	/*
	 * A btree node on disk could have too many bsets for an iterator to fit
	 * on the stack - have to dynamically allocate them
	 */
	mempool_t		fill_iter;

	mempool_t		btree_bounce_pool;

	struct journal		journal;

	unsigned		bucket_journal_seq;

	/* CACHING OTHER BLOCK DEVICES */
	mempool_t		search;
	struct radix_tree_root	devices;
	struct list_head	cached_devs;
	u64			cached_dev_sectors;
	struct closure		caching;

#define CONGESTED_MAX		1024
	unsigned		congested_last_us;
	atomic_t		congested;

	/* The rest of this all shows up in sysfs */
	unsigned		congested_read_threshold_us;
	unsigned		congested_write_threshold_us;

	struct cache_accounting accounting;
	atomic_long_t		cache_read_races;
	atomic_long_t		writeback_keys_done;
	atomic_long_t		writeback_keys_failed;

	unsigned		error_limit;
	unsigned		error_decay;

	unsigned		foreground_write_ratelimit_enabled:1;
	unsigned		copy_gc_enabled:1;
	unsigned		tiering_enabled:1;
	unsigned		tiering_percent;

	/*
	 * foreground writes will be throttled when the number of free
	 * buckets is below this percentage
	 */
	unsigned		foreground_target_percent;

#define BCH_DEBUG_PARAM(name, description) bool name;
	BCH_DEBUG_PARAMS_ALL()
#undef BCH_DEBUG_PARAM

#define BCH_TIME_STAT(name, frequency_units, duration_units)		\
	struct time_stats	name##_time;
	BCH_TIME_STATS()
#undef BCH_TIME_STAT
};

static inline bool bch_fs_running(struct bch_fs *c)
{
	return c->state == BCH_FS_RO || c->state == BCH_FS_RW;
}

static inline unsigned bucket_pages(const struct bch_dev *ca)
{
	return ca->mi.bucket_size / PAGE_SECTORS;
}

static inline unsigned bucket_bytes(const struct bch_dev *ca)
{
	return ca->mi.bucket_size << 9;
}

static inline unsigned block_bytes(const struct bch_fs *c)
{
	return c->sb.block_size << 9;
}

#endif /* _BCACHE_H */
