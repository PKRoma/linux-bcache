
#include "bcache.h"
#include "bkey.h"
#include "btree_update.h"
#include "journal.h"
#include "trans.h"

/* Long running transactions: */

struct bch_transaction_replay {
	struct list_head		list;
	struct bch_transaction		trans;
};

static void __bch_journal_transaction(struct journal *j,
				      struct bch_transaction *,
				      struct journal_res *);

/* Called when the journal wants us to release our pin so it can reclaim: */
static void bch_transaction_flush(struct journal *j,
				  struct journal_entry_pin *pin)
{
	struct bch_transaction *trans =
		container_of(pin, struct bch_transaction, journal_pin);
	struct journal_res res;
	unsigned u64s = jset_u64s(trans->k.k.u64s);
	int ret;

	BUG_ON(!bch_transaction_active(trans));

	/*
	 * XXX: this can deadlock because we're holding a journal pin, we need
	 * reservations:
	 */
	ret = bch_journal_res_get(j, &res, u64s, u64s);
	if (ret)
		return;

	__bch_journal_transaction(j, trans, &res);
	bch_journal_res_put(j, &res, NULL);
}

static void __bch_journal_transaction(struct journal *j,
				      struct bch_transaction *trans,
				      struct journal_res *res)
{
	/*
	 * There's no race between dropping the old pin and adding the new one
	 * because we're holding a journal reservation:
	 */
	bch_journal_pin_drop(j, &trans->journal_pin);
	bch_journal_pin_add(j, &trans->journal_pin, bch_transaction_flush);
	bch_journal_add_keys(j, res, BTREE_ID_TRANSACTIONS, &trans->k);
}

enum btree_insert_ret
bch_insert_fixup_transaction_key(struct btree_insert *insert,
				 struct btree_insert_entry *insert_entry,
				 struct journal_res *res)
{
	struct cache_set *c = insert->c;
	struct journal *j = &c->journal;
	struct bch_transaction *trans;

	if (test_bit(JOURNAL_REPLAY_DONE, &j->flags)) {
		trans = insert_entry->trans;

		BUG_ON(!bch_transaction_active(trans));
		BUG_ON(insert_entry->k->k.u64s != trans->k.k.u64s);

		bkey_copy(&trans->k, insert_entry->k);
		__bch_journal_transaction(j, trans, res);
	} else {
		struct bch_transaction_replay *r;

		if (insert_entry->k->k.p.offset >=
		    atomic64_read(&c->transactions_cur_id))
			atomic64_set(&c->transactions_cur_id,
				     insert_entry->k->k.p.offset);

		/*
		 * In journal replay - add the transaction to the list to be
		 * replayed:
		 */
		list_for_each_entry(r, &c->transactions_replay, list)
			if (!bkey_cmp(insert_entry->k->k.p, r->trans.k.k.p)) {
				BUG_ON(insert_entry->k->k.u64s !=
				       r->trans.k.k.u64s);
				goto found;
			}

		r = kzalloc(sizeof(*r) + bkey_val_bytes(&insert_entry->k->k),
			    GFP_KERNEL);
		if (!r)
			return BTREE_INSERT_ENOMEM;

		list_add(&r->list, &c->transactions_replay);
found:
		trans = &r->trans;
		bkey_copy(&trans->k, insert_entry->k);
		bch_journal_pin_drop(j, &trans->journal_pin);
		bch_journal_pin_add(j, &trans->journal_pin, bch_transaction_flush);
	}

	insert->did_work = true;
	return BTREE_INSERT_OK;
}

int bch_transaction_done(struct cache_set *c, struct bch_transaction *trans)
{
	struct journal *j = &c->journal;
	struct journal_res res;
	unsigned u64s;
	int ret;

	BUG_ON(!bch_transaction_active(trans));

	set_bkey_deleted(&trans->k.k);

	u64s = jset_u64s(trans->k.k.u64s);

	/*
	 * XXX: this can deadlock because we're holding a journal pin, we need
	 * reservations:
	 */
	ret = bch_journal_res_get(j, &res, u64s, u64s);
	if (ret)
		return ret;

	bch_journal_pin_drop(j, &trans->journal_pin);
	bch_journal_add_keys(j, &res, BTREE_ID_TRANSACTIONS, &trans->k);
	bch_journal_res_put(j, &res, NULL);
	return 0;
}

int bch_transaction_start(struct cache_set *c, struct bch_transaction *trans)
{
	struct journal *j = &c->journal;
	struct journal_res res;
	unsigned u64s = jset_u64s(trans->k.k.u64s);
	int ret;

	BUG_ON(trans->k.k.u64s <= BKEY_U64s);

	memset(&trans->journal_pin, 0, sizeof(trans->journal_pin));
	trans->k.k.p = POS(0, atomic64_inc_return(&c->transactions_cur_id));

	ret = bch_journal_res_get(j, &res, u64s, u64s);
	if (ret)
		return ret;

	__bch_journal_transaction(j, trans, &res);
	bch_journal_res_put(j, &res, NULL);
	return 0;
}

static int bch_transaction_replay_one(struct cache_set *c,
				      struct bch_transaction *trans)
{
	struct journal *j = &c->journal;

	switch (trans->k.k.type) {
	case KEY_TYPE_DELETED:
		bch_journal_pin_drop(j, &trans->journal_pin);
		break;
	case BCH_TRANS_INODE_CREATE:
		__journal_pin_add(j, trans->journal_pin.pin_list,
				  &c->inode_create.__journal_pin,
				  bch_transaction_flush);
		bkey_copy(&c->inode_create.k.k_i, &trans->k);

		bch_journal_pin_drop(j, &trans->journal_pin);
		break;
	case BCH_TRANS_FCOLLAPSE:
		break;
	default:
		BUG();
	};

	return 0;
}

int bch_transactions_replay(struct cache_set *c)
{
	struct bch_transaction_replay *r;
	int ret = 0;

	while (!list_empty(&c->transactions_replay)) {
		r = list_first_entry(&c->transactions_replay,
				     struct bch_transaction_replay,
				     list);
		list_del(&r->list);

		ret = bch_transaction_replay_one(c, &r->trans);
		if (ret)
			break;

		kfree(r);
	}

	return ret;
}

void bch_transactions_exit_cache_set(struct cache_set *c)
{
	struct bch_transaction_replay *r;

	while (!list_empty(&c->transactions_replay)) {
		r = list_first_entry(&c->transactions_replay,
				     struct bch_transaction_replay,
				     list);
		list_del(&r->list);
		kfree(r);
	}
}

void bch_transactions_init_cache_set(struct cache_set *c)
{
	INIT_LIST_HEAD(&c->transactions_replay);
}
