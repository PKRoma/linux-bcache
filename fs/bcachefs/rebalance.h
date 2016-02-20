#ifndef _BCACHE_REBALANCE_H
#define _BCACHE_REBALANCE_H

void bch_rebalance_exit(struct cache_set *);
int bch_rebalance_init(struct cache_set *, struct cache *ca);

#endif /* _BCACHE_REBALANCE_H */
