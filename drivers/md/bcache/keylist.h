#ifndef _BCACHE_KEYLIST_H
#define _BCACHE_KEYLIST_H

#include "keylist_types.h"

int bch_keylist_realloc(struct keylist *, u64 *, size_t, size_t);
void bch_keylist_add_in_order(struct keylist *, struct bkey_i *);
void bch_keylist_pop_front(struct keylist *);

static inline void bch_keylist_init(struct keylist *l, u64 *inline_keys,
				    size_t nr_inline_u64s)
{
	l->top_p = l->keys_p = inline_keys;
}

static inline void bch_keylist_free(struct keylist *l, u64 *inline_keys)
{
	if (l->keys_p != inline_keys)
		kfree(l->keys_p);
	memset(l, 0, sizeof(*l));
}

static inline void bch_keylist_push(struct keylist *l)
{
	l->top = bkey_next(l->top);
}

static inline void bch_keylist_add(struct keylist *l, const struct bkey_i *k)
{
	bkey_copy(l->top, k);
	bch_keylist_push(l);
}

static inline bool bch_keylist_empty(struct keylist *l)
{
	return l->top == l->keys;
}

static inline size_t bch_keylist_u64s(struct keylist *l)
{
	return l->top_p - l->keys_p;
}

static inline size_t bch_keylist_bytes(struct keylist *l)
{
	return bch_keylist_u64s(l) * sizeof(u64);
}

static inline struct bkey_i *bch_keylist_front(struct keylist *l)
{
	return l->keys;
}

#define for_each_keylist_key(_keylist, _k)			\
	for (_k = (_keylist)->keys;				\
	     _k != (_keylist)->top;				\
	     _k = bkey_next(_k))

#define keylist_single(k)					\
	((struct keylist) { .keys = k, .top = bkey_next(k) })

#endif /* _BCACHE_KEYLIST_H */
