#ifndef _BCACHE_ALLOC_H
#define _BCACHE_ALLOC_H

#include "alloc_types.h"

struct bkey;
struct bucket;
struct bch_dev;
struct bch_fs;
struct dev_group;

static inline size_t prios_per_bucket(const struct bch_dev *ca)
{
	return (bucket_bytes(ca) - sizeof(struct prio_set)) /
		sizeof(struct bucket_disk);
}

static inline size_t prio_buckets(const struct bch_dev *ca)
{
	return DIV_ROUND_UP((size_t) (ca)->mi.nbuckets, prios_per_bucket(ca));
}

void bch_dev_group_remove(struct dev_group *, struct bch_dev *);
void bch_dev_group_add(struct dev_group *, struct bch_dev *);

int bch_prio_read(struct bch_dev *);

void bch_recalc_min_prio(struct bch_dev *, int);

size_t bch_bucket_alloc(struct bch_dev *, enum alloc_reserve);

void bch_open_bucket_put(struct bch_fs *, struct open_bucket *);

struct open_bucket *bch_alloc_sectors_start(struct bch_fs *,
					    struct write_point *,
					    unsigned, unsigned,
					    enum alloc_reserve,
					    struct closure *);

void bch_alloc_sectors_append_ptrs(struct bch_fs *, struct bkey_i_extent *,
				   unsigned, struct open_bucket *, unsigned);
void bch_alloc_sectors_done(struct bch_fs *, struct write_point *,
			    struct open_bucket *);

struct open_bucket *bch_alloc_sectors(struct bch_fs *, struct write_point *,
				      struct bkey_i_extent *, unsigned, unsigned,
				      enum alloc_reserve, struct closure *);

static inline void bch_wake_allocator(struct bch_dev *ca)
{
	struct task_struct *p;

	rcu_read_lock();
	if ((p = ACCESS_ONCE(ca->alloc_thread)))
		wake_up_process(p);
	rcu_read_unlock();
}

static inline struct bch_dev *dev_group_next_rcu(struct dev_group *devs,
						 unsigned *iter)
{
	struct bch_dev *ret = NULL;

	while (*iter < devs->nr &&
	       !(ret = rcu_dereference(devs->d[*iter].dev)))
		(*iter)++;

	return ret;
}

#define group_for_each_dev_rcu(ca, devs, iter)				\
	for ((iter) = 0;						\
	     ((ca) = dev_group_next_rcu((devs), &(iter)));		\
	     (iter)++)

static inline struct bch_dev *dev_group_next(struct dev_group *devs,
					     unsigned *iter)
{
	struct bch_dev *ret;

	rcu_read_lock();
	if ((ret = dev_group_next_rcu(devs, iter)))
		percpu_ref_get(&ret->ref);
	rcu_read_unlock();

	return ret;
}

#define group_for_each_dev(ca, devs, iter)				\
	for ((iter) = 0;						\
	     (ca = dev_group_next(devs, &(iter)));			\
	     percpu_ref_put(&ca->ref), (iter)++)

#define __open_bucket_next_online_device(_c, _ob, _ptr, _ca)            \
({									\
	(_ca) = NULL;							\
									\
	while ((_ptr) < (_ob)->ptrs + (_ob)->nr_ptrs &&			\
	       !((_ca) = PTR_DEV(_c, _ptr)))				\
		(_ptr)++;						\
	(_ca);								\
})

#define open_bucket_for_each_online_device(_c, _ob, _ptr, _ca)		\
	for ((_ptr) = (_ob)->ptrs;					\
	     ((_ca) = __open_bucket_next_online_device(_c, _ob,	_ptr, _ca));\
	     (_ptr)++)

void bch_recalc_capacity(struct bch_fs *);
void bch_dev_allocator_stop(struct bch_dev *);
int bch_dev_allocator_start(struct bch_dev *);
void bch_fs_allocator_init(struct bch_fs *);

#endif /* _BCACHE_ALLOC_H */
