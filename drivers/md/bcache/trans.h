#ifndef _BCACHE_TRANS_H
#define _BCACHE_TRANS_H

#include "trans_types.h"
#include "journal.h"

enum btree_insert_ret
bch_insert_fixup_transaction_key(struct btree_insert *,
				 struct btree_insert_entry *,
				 struct journal_res *);

int bch_transaction_done(struct cache_set *, struct bch_transaction *);
int bch_transaction_start(struct cache_set *, struct bch_transaction *);

int bch_transactions_replay(struct cache_set *);

void bch_transactions_exit_cache_set(struct cache_set *);
void bch_transactions_init_cache_set(struct cache_set *);

static inline bool bch_transaction_active(struct bch_transaction *trans)
{
	return journal_pin_active(&trans->journal_pin);
}

#endif /* _BCACHE_TRANS_H */
