#ifndef _BCACHE_TRANS_TYPES_H
#define _BCACHE_TRANS_TYPES_H

#include "journal_types.h"

struct bch_transaction {
	struct journal_entry_pin	journal_pin;
	struct bkey_i			k;
};

#define BCH_TRANS_TYPE(name, nr)					\
struct bch_trans_##name {						\
	union {								\
	struct {							\
		struct bch_transaction	t;				\
		struct bch_trans_##name##_val	v;			\
	};								\
	struct {							\
		struct journal_entry_pin __journal_pin;			\
		struct bkey_i_trans_##name##_val	k;		\
	};								\
	};								\
}

BCH_TRANS_TYPE(inode_create,	BCH_TRANS_INODE_CREATE);
BCH_TRANS_TYPE(fcollapse,	BCH_TRANS_FCOLLAPSE);

#endif /* _BCACHE_TRANS_TYPES_H */
