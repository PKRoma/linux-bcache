
#define pr_fmt(fmt) "bcache: %s() " fmt "\n", __func__

#include <linux/kernel.h>

#include "bkey.h"
#include "bset.h"
#include "util.h"

const struct bkey_format bch_bkey_format_current = BKEY_FORMAT_CURRENT;

struct bkey __bkey_unpack_key(const struct bkey_format *,
			      const struct bkey_packed *);

void bch_to_binary(char *out, const u64 *p, unsigned nr_bits)
{
	unsigned bit = high_bit_offset, done = 0;

	while (1) {
		while (bit < 64) {
			if (done && !(done % 8))
				*out++ = ' ';
			*out++ = *p & (1ULL << (63 - bit)) ? '1' : '0';
			bit++;
			done++;
			if (done == nr_bits) {
				*out++ = '\0';
				return;
			}
		}

		p = next_word(p);
		bit = 0;
	}
}

#ifdef CONFIG_BCACHE_DEBUG

static void bch_bkey_pack_verify(const struct bkey_packed *packed,
				 const struct bkey *unpacked,
				 const struct bkey_format *format)
{
	struct bkey tmp;

	BUG_ON(bkeyp_val_u64s(format, packed) !=
	       bkey_val_u64s(unpacked));

	BUG_ON(packed->u64s < bkeyp_key_u64s(format, packed));

	tmp = __bkey_unpack_key(format, packed);

	if (memcmp(&tmp, unpacked, sizeof(struct bkey))) {
		char buf1[160], buf2[160];
		char buf3[160], buf4[160];

		bch_bkey_to_text(buf1, sizeof(buf1), unpacked);
		bch_bkey_to_text(buf2, sizeof(buf2), &tmp);
		bch_to_binary(buf3, (void *) unpacked, 80);
		bch_to_binary(buf4, high_word(format, packed), 80);

		panic("keys differ: format u64s %u fields %u %u %u %u %u\n%s\n%s\n%s\n%s\n",
		      format->key_u64s,
		      format->bits_per_field[0],
		      format->bits_per_field[1],
		      format->bits_per_field[2],
		      format->bits_per_field[3],
		      format->bits_per_field[4],
		      buf1, buf2, buf3, buf4);
	}
}

#else
static inline void bch_bkey_pack_verify(const struct bkey_packed *packed,
					const struct bkey *unpacked,
					const struct bkey_format *format) {}
#endif

int bch_bkey_to_text(char *buf, size_t size, const struct bkey *k)
{
	char *out = buf, *end = buf + size;

#define p(...)	(out += scnprintf(out, end - out, __VA_ARGS__))

	p("u64s %u type %u %llu:%llu snap %u len %u ver %u",
	  k->u64s, k->type, k->p.inode, k->p.offset,
	  k->p.snapshot, k->size, k->version);

	BUG_ON(bkey_packed(k));

	switch (k->type) {
	case KEY_TYPE_DELETED:
		p(" deleted");
		break;
	case KEY_TYPE_DISCARD:
		p(" discard");
		break;
	case KEY_TYPE_ERROR:
		p(" error");
		break;
	case KEY_TYPE_COOKIE:
		p(" cookie");
		break;
	}
#undef p

	return out - buf;
}

struct pack_state {
	const struct bkey_format *format;
	unsigned		bits;	/* bits remaining in current word */
	u64			w;	/* current word */
	u64			*p;	/* pointer to next word */
};

__always_inline
static struct pack_state pack_state_init(const struct bkey_format *format,
					 struct bkey_packed *k)
{
	u64 *p = high_word(format, k);

	return (struct pack_state) {
		.format	= format,
		.bits	= 64 - high_bit_offset,
		.w	= 0,
		.p	= p,
	};
}

__always_inline
static void pack_state_finish(struct pack_state *state,
			      struct bkey_packed *k)
{
	EBUG_ON(state->p <  k->_data);
	EBUG_ON(state->p >= k->_data + state->format->key_u64s);

	*state->p = state->w;
}

struct unpack_state {
	const struct bkey_format *format;
	unsigned		bits;	/* bits remaining in current word */
	u64			w;	/* current word */
	const u64		*p;	/* pointer to next word */
};

__always_inline
static struct unpack_state unpack_state_init(const struct bkey_format *format,
					     const struct bkey_packed *k)
{
	const u64 *p = high_word(format, k);

	return (struct unpack_state) {
		.format	= format,
		.bits	= 64 - high_bit_offset,
		.w	= *p << high_bit_offset,
		.p	= p,
	};
}

__always_inline
static u64 get_inc_field(struct unpack_state *state, unsigned field)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 v = 0, offset = le64_to_cpu(state->format->field_offset[field]);

	if (bits >= state->bits) {
		v = state->w >> (64 - bits);
		bits -= state->bits;

		state->p = next_word(state->p);
		state->w = *state->p;
		state->bits = 64;
	}

	/* avoid shift by 64 if bits is 0 - bits is never 64 here: */
	v |= (state->w >> 1) >> (63 - bits);
	state->w <<= bits;
	state->bits -= bits;

	return v + offset;
}

__always_inline
static bool set_inc_field(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = le64_to_cpu(state->format->field_offset[field]);

	if (v < offset)
		return false;

	v -= offset;

	if (fls64(v) > bits)
		return false;

	if (bits > state->bits) {
		bits -= state->bits;
		/* avoid shift by 64 if bits is 0 - bits is never 64 here: */
		state->w |= (v >> 1) >> (bits - 1);

		*state->p = state->w;
		state->p = next_word(state->p);
		state->w = 0;
		state->bits = 64;
	}

	state->bits -= bits;
	state->w |= v << state->bits;

	return true;
}

/*
 * Note: does NOT set out->format (we don't know what it should be here!)
 *
 * Also: doesn't work on extents - it doesn't preserve the invariant that
 * if k is packed bkey_start_pos(k) will successfully pack
 */
static bool bch_bkey_transform_key(const struct bkey_format *out_f,
				   struct bkey_packed *out,
				   const struct bkey_format *in_f,
				   const struct bkey_packed *in)
{
	struct pack_state out_s = pack_state_init(out_f, out);
	struct unpack_state in_s = unpack_state_init(in_f, in);
	unsigned i;

	out->_data[0] = 0;

	for (i = 0; i < BKEY_NR_FIELDS; i++)
		if (!set_inc_field(&out_s, i, get_inc_field(&in_s, i)))
			return false;

	/* Can't happen because the val would be too big to unpack: */
	EBUG_ON(in->u64s - in_f->key_u64s + out_f->key_u64s > U8_MAX);

	pack_state_finish(&out_s, out);
	out->u64s	= out_f->key_u64s + in->u64s - in_f->key_u64s;
	out->needs_whiteout = in->needs_whiteout;
	out->type	= in->type;

	return true;
}

bool bch_bkey_transform(const struct bkey_format *out_f,
			struct bkey_packed *out,
			const struct bkey_format *in_f,
			const struct bkey_packed *in)
{
	if (!bch_bkey_transform_key(out_f, out, in_f, in))
		return false;

	memcpy_u64s((u64 *) out + out_f->key_u64s,
		    (u64 *) in + in_f->key_u64s,
		    (in->u64s - in_f->key_u64s));
	return true;
}

struct bkey __bkey_unpack_key(const struct bkey_format *format,
			      const struct bkey_packed *in)
{
	struct unpack_state state = unpack_state_init(format, in);
	struct bkey out;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);
	EBUG_ON(in->u64s - format->key_u64s + BKEY_U64s > U8_MAX);

	out.u64s	= BKEY_U64s + in->u64s - format->key_u64s;
	out.format	= KEY_FORMAT_CURRENT;
	out.needs_whiteout = in->needs_whiteout;
	out.type	= in->type;
	out.pad[0]	= 0;
	out.p.inode	= get_inc_field(&state, BKEY_FIELD_INODE);
	out.p.offset	= get_inc_field(&state, BKEY_FIELD_OFFSET);
	out.p.snapshot	= get_inc_field(&state, BKEY_FIELD_SNAPSHOT);
	out.size	= get_inc_field(&state, BKEY_FIELD_SIZE);
	out.version	= get_inc_field(&state, BKEY_FIELD_VERSION);

	return out;
}

#ifndef HAVE_BCACHE_COMPILED_UNPACK
static struct bpos __bkey_unpack_pos(const struct bkey_format *format,
				     const struct bkey_packed *in)
{
	struct unpack_state state = unpack_state_init(format, in);
	struct bpos out;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	out.inode	= get_inc_field(&state, BKEY_FIELD_INODE);
	out.offset	= get_inc_field(&state, BKEY_FIELD_OFFSET);
	out.snapshot	= get_inc_field(&state, BKEY_FIELD_SNAPSHOT);

	return out;
}
#endif

/**
 * bkey_pack_key -- pack just the key, not the value
 */
bool bkey_pack_key(struct bkey_packed *out, const struct bkey *in,
		   const struct bkey_format *format)
{
	struct pack_state state = pack_state_init(format, out);

	EBUG_ON((void *) in == (void *) out);
	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->format != KEY_FORMAT_CURRENT);

	out->_data[0] = 0;

	if (!set_inc_field(&state, BKEY_FIELD_INODE,	in->p.inode) ||
	    !set_inc_field(&state, BKEY_FIELD_OFFSET,	in->p.offset) ||
	    !set_inc_field(&state, BKEY_FIELD_SNAPSHOT,	in->p.snapshot) ||
	    !set_inc_field(&state, BKEY_FIELD_SIZE,	in->size) ||
	    !set_inc_field(&state, BKEY_FIELD_VERSION,	in->version))
		return false;

	/*
	 * Extents - we have to guarantee that if an extent is packed, a trimmed
	 * version will also pack:
	 */
	if (bkey_start_offset(in) < format->field_offset[BKEY_FIELD_OFFSET])
		return false;

	pack_state_finish(&state, out);
	out->u64s	= format->key_u64s + in->u64s - BKEY_U64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->needs_whiteout = in->needs_whiteout;
	out->type	= in->type;

	bch_bkey_pack_verify(out, in, format);
	return true;
}

/*
 * Alternate implementations using bch_bkey_transform_key() - unfortunately, too
 * slow
 */
#if 0
struct bkey __bkey_unpack_key(const struct bkey_format *format,
			      const struct bkey_packed *in)
{
	struct bkey out;
	bool s;

	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->u64s < format->key_u64s);
	EBUG_ON(in->format != KEY_FORMAT_LOCAL_BTREE);

	s = bch_bkey_transform_key(&bch_bkey_format_current, (void *) &out,
				   format, in);
	EBUG_ON(!s);

	out.format = KEY_FORMAT_CURRENT;

	return out;
}

bool bkey_pack_key(struct bkey_packed *out, const struct bkey *in,
		   const struct bkey_format *format)
{
	EBUG_ON(format->nr_fields != 5);
	EBUG_ON(in->format != KEY_FORMAT_CURRENT);

	if (!bch_bkey_transform_key(format, out,
				    &bch_bkey_format_current, (void *) in))
		return false;

	out->format = KEY_FORMAT_LOCAL_BTREE;

	bch_bkey_pack_verify(out, in, format);
	return true;
}
#endif

/**
 * bkey_unpack -- unpack the key and the value
 */
void bkey_unpack(const struct btree_keys *b, struct bkey_i *dst,
		 const struct bkey_packed *src)
{
	dst->k = bkey_unpack_key(b, src);

	memcpy_u64s(&dst->v,
		    bkeyp_val(&b->format, src),
		    bkeyp_val_u64s(&b->format, src));
}

/**
 * bkey_pack -- pack the key and the value
 */
bool bkey_pack(struct bkey_packed *out, const struct bkey_i *in,
	       const struct bkey_format *format)
{
	struct bkey_packed tmp;

	if (!bkey_pack_key(&tmp, &in->k, format))
		return false;

	memmove_u64s((u64 *) out + format->key_u64s,
		     &in->v,
		     bkey_val_u64s(&in->k));
	memcpy_u64s(out, &tmp, format->key_u64s);

	return true;
}

__always_inline
static bool set_inc_field_lossy(struct pack_state *state, unsigned field, u64 v)
{
	unsigned bits = state->format->bits_per_field[field];
	u64 offset = le64_to_cpu(state->format->field_offset[field]);
	bool ret = true;

	EBUG_ON(v < offset);
	v -= offset;

	if (fls64(v) > bits) {
		v = ~(~0ULL << bits);
		ret = false;
	}

	if (bits > state->bits) {
		bits -= state->bits;
		state->w |= (v >> 1) >> (bits - 1);

		*state->p = state->w;
		state->p = next_word(state->p);
		state->w = 0;
		state->bits = 64;
	}

	state->bits -= bits;
	state->w |= v << state->bits;

	return ret;
}

#ifdef CONFIG_BCACHE_DEBUG
static bool bkey_packed_successor(struct bkey_packed *out,
				  const struct btree_keys *b,
				  struct bkey_packed k)
{
	const struct bkey_format *f = &b->format;
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned first_bit, offset;
	u64 *p;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(f));

	if (!nr_key_bits)
		return false;

	*out = k;

	first_bit = high_bit_offset + nr_key_bits - 1;
	p = nth_word(high_word(f, out), first_bit >> 6);
	offset = 63 - (first_bit & 63);

	while (nr_key_bits) {
		unsigned bits = min(64 - offset, nr_key_bits);
		u64 mask = (~0ULL >> (64 - bits)) << offset;

		if ((*p & mask) != mask) {
			*p += 1ULL << offset;
			EBUG_ON(bkey_cmp_packed(b, out, &k) <= 0);
			return true;
		}

		*p &= ~mask;
		p = prev_word(p);
		nr_key_bits -= bits;
		offset = 0;
	}

	return false;
}
#endif

/*
 * Returns a packed key that compares <= in
 *
 * This is used in bset_search_tree(), where we need a packed pos in order to be
 * able to compare against the keys in the auxiliary search tree - and it's
 * legal to use a packed pos that isn't equivalent to the original pos,
 * _provided_ it compares <= to the original pos.
 */
enum bkey_pack_pos_ret bkey_pack_pos_lossy(struct bkey_packed *out,
					   struct bpos in,
					   const struct btree_keys *b)
{
	const struct bkey_format *f = &b->format;
	struct pack_state state = pack_state_init(f, out);
#ifdef CONFIG_BCACHE_DEBUG
	struct bpos orig = in;
#endif
	bool exact = true;

	out->_data[0] = 0;

	if (unlikely(in.snapshot <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_SNAPSHOT]))) {
		if (!in.offset-- &&
		    !in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.offset <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_OFFSET]))) {
		if (!in.inode--)
			return BKEY_PACK_POS_FAIL;
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (unlikely(in.inode <
		     le64_to_cpu(f->field_offset[BKEY_FIELD_INODE])))
		return BKEY_PACK_POS_FAIL;

	if (!set_inc_field_lossy(&state, BKEY_FIELD_INODE, in.inode)) {
		in.offset	= KEY_OFFSET_MAX;
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (!set_inc_field_lossy(&state, BKEY_FIELD_OFFSET, in.offset)) {
		in.snapshot	= KEY_SNAPSHOT_MAX;
		exact = false;
	}

	if (!set_inc_field_lossy(&state, BKEY_FIELD_SNAPSHOT, in.snapshot))
		exact = false;

	pack_state_finish(&state, out);
	out->u64s	= f->key_u64s;
	out->format	= KEY_FORMAT_LOCAL_BTREE;
	out->type	= KEY_TYPE_DELETED;

#ifdef CONFIG_BCACHE_DEBUG
	if (exact) {
		BUG_ON(bkey_cmp_left_packed(b, out, &orig));
	} else {
		struct bkey_packed successor;

		BUG_ON(bkey_cmp_left_packed(b, out, &orig) >= 0);
		BUG_ON(bkey_packed_successor(&successor, b, *out) &&
		       bkey_cmp_left_packed(b, &successor, &orig) < 0);
	}
#endif

	return exact ? BKEY_PACK_POS_EXACT : BKEY_PACK_POS_SMALLER;
}

void bch_bkey_format_init(struct bkey_format_state *s)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++)
		s->field_min[i] = U64_MAX;

	for (i = 0; i < ARRAY_SIZE(s->field_max); i++)
		s->field_max[i] = 0;

	/* Make sure we can store a size of 0: */
	s->field_min[BKEY_FIELD_SIZE] = 0;
}

static void __bkey_format_add(struct bkey_format_state *s,
			      unsigned field, u64 v)
{
	s->field_min[field] = min(s->field_min[field], v);
	s->field_max[field] = max(s->field_max[field], v);
}

/*
 * Changes @format so that @k can be successfully packed with @format
 */
void bch_bkey_format_add_key(struct bkey_format_state *s, const struct bkey *k)
{
	__bkey_format_add(s, BKEY_FIELD_INODE, k->p.inode);
	__bkey_format_add(s, BKEY_FIELD_OFFSET, k->p.offset);
	__bkey_format_add(s, BKEY_FIELD_OFFSET, bkey_start_offset(k));
	__bkey_format_add(s, BKEY_FIELD_SNAPSHOT, k->p.snapshot);
	__bkey_format_add(s, BKEY_FIELD_SIZE, k->size);
	__bkey_format_add(s, BKEY_FIELD_VERSION, k->version);
}

void bch_bkey_format_add_pos(struct bkey_format_state *s, struct bpos p)
{
	unsigned field = 0;

	__bkey_format_add(s, field++, p.inode);
	__bkey_format_add(s, field++, p.offset);
	__bkey_format_add(s, field++, p.snapshot);
}

/*
 * We don't want it to be possible for the packed format to represent fields
 * bigger than a u64... that will cause confusion and issues (like with
 * bkey_packed_successor())
 */
static void set_format_field(struct bkey_format *f, enum bch_bkey_fields i,
			     unsigned bits, u64 offset)
{
	offset = bits == 64 ? 0 : min(offset, U64_MAX - ((1ULL << bits) - 1));

	f->bits_per_field[i]	= bits;
	f->field_offset[i]	= cpu_to_le64(offset);
}

struct bkey_format bch_bkey_format_done(struct bkey_format_state *s)
{
	unsigned i, bits = KEY_PACKED_BITS_START;
	struct bkey_format ret = {
		.nr_fields = BKEY_NR_FIELDS,
	};

	for (i = 0; i < ARRAY_SIZE(s->field_min); i++) {
		s->field_min[i] = min(s->field_min[i], s->field_max[i]);

		set_format_field(&ret, i,
				 fls64(s->field_max[i] - s->field_min[i]),
				 s->field_min[i]);

		bits += ret.bits_per_field[i];
	}

	ret.key_u64s = DIV_ROUND_UP(bits, 64);

	/* if we have enough spare bits, round fields up to nearest byte */
	bits = ret.key_u64s * 64 - bits;

	for (i = 0; i < ARRAY_SIZE(ret.bits_per_field); i++) {
		unsigned r = round_up(ret.bits_per_field[i], 8) -
			ret.bits_per_field[i];

		if (r <= bits) {
			set_format_field(&ret, i,
					 ret.bits_per_field[i] + r,
					 le64_to_cpu(ret.field_offset[i]));
			bits -= r;
		}
	}

	EBUG_ON(bch_bkey_format_validate(&ret));
	return ret;
}

const char *bch_bkey_format_validate(struct bkey_format *f)
{
	unsigned i, bits = KEY_PACKED_BITS_START;

	if (f->nr_fields != BKEY_NR_FIELDS)
		return "invalid format: incorrect number of fields";

	for (i = 0; i < f->nr_fields; i++) {
		u64 field_offset = le64_to_cpu(f->field_offset[i]);

		if (f->bits_per_field[i] > 64)
			return "invalid format: field too large";

		if (field_offset &&
		    (f->bits_per_field[i] == 64 ||
		    (field_offset + ((1ULL << f->bits_per_field[i]) - 1) <
		     field_offset)))
			return "invalid format: offset + bits overflow";

		bits += f->bits_per_field[i];
	}

	if (f->key_u64s != DIV_ROUND_UP(bits, 64))
		return "invalid format: incorrect key_u64s";

	return NULL;
}

/*
 * Most significant differing bit
 * Bits are indexed from 0 - return is [0, nr_key_bits)
 */
__pure
unsigned bkey_greatest_differing_bit(const struct btree_keys *b,
				     const struct bkey_packed *l_k,
				     const struct bkey_packed *r_k)
{
	const u64 *l = high_word(&b->format, l_k);
	const u64 *r = high_word(&b->format, r_k);
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned word_bits = 64 - high_bit_offset;
	u64 l_v, r_v;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(&b->format));

	/* for big endian, skip past header */
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (nr_key_bits) {
		if (nr_key_bits < word_bits) {
			l_v >>= word_bits - nr_key_bits;
			r_v >>= word_bits - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= word_bits;
		}

		if (l_v != r_v)
			return fls64(l_v ^ r_v) - 1 + nr_key_bits;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
		word_bits = 64;
	}

	return 0;
}

/*
 * First set bit
 * Bits are indexed from 0 - return is [0, nr_key_bits)
 */
__pure
unsigned bkey_ffs(const struct btree_keys *b,
		  const struct bkey_packed *k)
{
	const u64 *p = high_word(&b->format, k);
	unsigned nr_key_bits = b->nr_key_bits;
	unsigned ret = 0, offset;

	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(&b->format));

	offset = nr_key_bits;
	while (offset > 64) {
		p = next_word(p);
		offset -= 64;
	}

	offset = 64 - offset;

	while (nr_key_bits) {
		unsigned bits = nr_key_bits + offset < 64
			? nr_key_bits
			: 64 - offset;

		u64 mask = (~0ULL >> (64 - bits)) << offset;

		if (*p & mask)
			return ret + __ffs64(*p & mask) - offset;

		p = prev_word(p);
		nr_key_bits -= bits;
		ret += bits;
		offset = 0;
	}

	return 0;
}

#ifdef CONFIG_X86_64

static inline int __bkey_cmp_bits(const u64 *l, const u64 *r,
				  unsigned nr_key_bits)
{
	long d0, d1, d2, d3;
	int cmp;

	/* we shouldn't need asm for this, but gcc is being retarded: */

	asm(".intel_syntax noprefix;"
	    "xor eax, eax;"
	    "xor edx, edx;"
	    "1:;"
	    "mov r8, [rdi];"
	    "mov r9, [rsi];"
	    "sub ecx, 64;"
	    "jl 2f;"

	    "cmp r8, r9;"
	    "jnz 3f;"

	    "lea rdi, [rdi - 8];"
	    "lea rsi, [rsi - 8];"
	    "jmp 1b;"

	    "2:;"
	    "not ecx;"
	    "shr r8, 1;"
	    "shr r9, 1;"
	    "shr r8, cl;"
	    "shr r9, cl;"
	    "cmp r8, r9;"

	    "3:\n"
	    "seta al;"
	    "setb dl;"
	    "sub eax, edx;"
	    ".att_syntax prefix;"
	    : "=&D" (d0), "=&S" (d1), "=&d" (d2), "=&c" (d3), "=&a" (cmp)
	    : "0" (l), "1" (r), "3" (nr_key_bits)
	    : "r8", "r9", "cc", "memory");

	return cmp;
}

#define I(_x)			(*(out)++ = (_x))
#define I1(i0)						I(i0)
#define I2(i0, i1)		(I1(i0),		I(i1))
#define I3(i0, i1, i2)		(I2(i0, i1),		I(i2))
#define I4(i0, i1, i2, i3)	(I3(i0, i1, i2),	I(i3))
#define I5(i0, i1, i2, i3, i4)	(I4(i0, i1, i2, i3),	I(i4))

static u8 *compile_bkey_field(const struct bkey_format *format, u8 *out,
			      enum bch_bkey_fields field,
			      unsigned dst_offset, unsigned dst_size,
			      bool *eax_zeroed)
{
	unsigned byte = format->key_u64s * sizeof(u64);
	unsigned bits = format->bits_per_field[field];
	u64 offset = format->field_offset[field];
	unsigned i, bit_offset = 0;
	unsigned shl, shr;

	if (!bits && !offset) {
		if (!*eax_zeroed) {
			/* xor eax, eax */
			I2(0x31, 0xc0);
		}

		*eax_zeroed = true;
		goto set_field;
	}

	if (!bits) {
		/* just return offset: */

		switch (dst_size) {
		case 8:
			if (offset > S32_MAX) {
				/* mov [rdi + dst_offset], offset */
				I3(0xc7, 0x47, dst_offset);
				memcpy(out, &offset, 4);
				out += 4;

				I3(0xc7, 0x47, dst_offset + 4);
				memcpy(out, (void *) &offset + 4, 4);
				out += 4;
			} else {
				/* mov [rdi + dst_offset], offset */
				/* sign extended */
				I4(0x48, 0xc7, 0x47, dst_offset);
				memcpy(out, &offset, 4);
				out += 4;
			}
			break;
		case 4:
			/* mov [rdi + dst_offset], offset */
			I3(0xc7, 0x47, dst_offset);
			memcpy(out, &offset, 4);
			out += 4;
			break;
		default:
			BUG();
		}

		return out;
	}

	for (i = 0; i <= field; i++)
		bit_offset += format->bits_per_field[i];

	byte -= DIV_ROUND_UP(bit_offset, 8);
	bit_offset = round_up(bit_offset, 8) - bit_offset;

	*eax_zeroed = false;

	if (bit_offset == 0 && bits == 8) {
		/* movzx eax, BYTE PTR [rsi + imm8] */
		I4(0x0f, 0xb6, 0x46, byte);
	} else if (bit_offset == 0 && bits == 16) {
		/* movzx eax, WORD PTR [rsi + imm8] */
		I4(0x0f, 0xb7, 0x46, byte);
	} else if (bit_offset + bits <= 32) {
		/* mov eax, [rsi + imm8] */
		I3(0x8b, 0x46, byte);

		if (bit_offset) {
			/* shr eax, imm8 */
			I3(0xc1, 0xe8, bit_offset);
		}

		if (bit_offset + bits < 32) {
			unsigned mask = ~0U >> (32 - bits);

			/* and eax, imm32 */
			I1(0x25);
			memcpy(out, &mask, 4);
			out += 4;
		}
	} else if (bit_offset + bits <= 64) {
		/* mov rax, [rsi + imm8] */
		I4(0x48, 0x8b, 0x46, byte);

		shl = 64 - bit_offset - bits;
		shr = bit_offset + shl;

		if (shl) {
			/* shl rax, imm8 */
			I4(0x48, 0xc1, 0xe0, shl);
		}

		if (shr) {
			/* shr rax, imm8 */
			I4(0x48, 0xc1, 0xe8, shr);
		}
	} else {
		/* mov rax, [rsi + byte] */
		I4(0x48, 0x8b, 0x46, byte);

		/* mov edx, [rsi + byte + 8] */
		I3(0x8b, 0x56, byte + 8);

		/* bits from next word: */
		shr = bit_offset + bits - 64;
		BUG_ON(shr > bit_offset);

		/* shr rax, bit_offset */
		I4(0x48, 0xc1, 0xe8, shr);

		/* shl rdx, imm8 */
		I4(0x48, 0xc1, 0xe2, 64 - shr);

		/* or rax, rdx */
		I3(0x48, 0x09, 0xd0);

		shr = bit_offset - shr;

		if (shr) {
			/* shr rax, imm8 */
			I4(0x48, 0xc1, 0xe8, shr);
		}
	}

	/* rax += offset: */
	if (offset > S32_MAX) {
		/* mov rdx, imm64 */
		I2(0x48, 0xba);
		memcpy(out, &offset, 8);
		out += 8;
		/* add %rdx, %rax */
		I3(0x48, 0x01, 0xd0);
	} else if (offset + (~0ULL >> (64 - bits)) > U32_MAX) {
		/* add rax, imm32 */
		I2(0x48, 0x05);
		memcpy(out, &offset, 4);
		out += 4;
	} else if (offset) {
		/* add eax, imm32 */
		I1(0x05);
		memcpy(out, &offset, 4);
		out += 4;
	}
set_field:
	switch (dst_size) {
	case 8:
		/* mov [rdi + dst_offset], rax */
		I4(0x48, 0x89, 0x47, dst_offset);
		break;
	case 4:
		/* mov [rdi + dst_offset], eax */
		I3(0x89, 0x47, dst_offset);
		break;
	default:
		BUG();
	}

	return out;
}

int bch_compile_bkey_format(const struct bkey_format *format, void *_out)
{
	bool eax_zeroed = false;
	u8 *out = _out;

	/*
	 * rdi: dst - unpacked key
	 * rsi: src - packed key
	 */

	/* k->u64s, k->format, k->type */

	/* mov eax, [rsi] */
	I2(0x8b, 0x06);

	/* add eax, BKEY_U64s - format->key_u64s */
	I5(0x05, BKEY_U64s - format->key_u64s, KEY_FORMAT_CURRENT, 0, 0);

	/* and eax, imm32: mask out k->pad: */
	I5(0x25, 0xff, 0xff, 0xff, 0);

	/* mov [rdi], eax */
	I2(0x89, 0x07);

	out = compile_bkey_field(format, out,	BKEY_FIELD_INODE,
				 offsetof(struct bkey, p.inode), 8,
				 &eax_zeroed);

	out = compile_bkey_field(format, out,	BKEY_FIELD_OFFSET,
				 offsetof(struct bkey, p.offset), 8,
				 &eax_zeroed);

	out = compile_bkey_field(format, out,	BKEY_FIELD_SNAPSHOT,
				 offsetof(struct bkey, p.snapshot), 4,
				 &eax_zeroed);

	out = compile_bkey_field(format, out,	BKEY_FIELD_SIZE,
				 offsetof(struct bkey, size), 4,
				 &eax_zeroed);

	out = compile_bkey_field(format, out,	BKEY_FIELD_VERSION,
				 offsetof(struct bkey, version), 4,
				 &eax_zeroed);

	/* retq */
	I1(0xc3);

	return (void *) out - _out;
}

#else
static inline int __bkey_cmp_bits(const u64 *l, const u64 *r,
				  unsigned nr_key_bits)
{
	u64 l_v, r_v;

	if (!nr_key_bits)
		return 0;

	/* for big endian, skip past header */
	nr_key_bits += high_bit_offset;
	l_v = *l & (~0ULL >> high_bit_offset);
	r_v = *r & (~0ULL >> high_bit_offset);

	while (1) {
		if (nr_key_bits < 64) {
			l_v >>= 64 - nr_key_bits;
			r_v >>= 64 - nr_key_bits;
			nr_key_bits = 0;
		} else {
			nr_key_bits -= 64;
		}

		if (l_v != r_v)
			return l_v < r_v ? -1 : 1;

		if (!nr_key_bits)
			return 0;

		l = next_word(l);
		r = next_word(r);

		l_v = *l;
		r_v = *r;
	}
}
#endif

/*
 * Would like to use this if we can make __bkey_cmp_bits() fast enough, it'll be
 * a decent reduction in code size
 */
#if 0
static int bkey_cmp_verify(const struct bkey *l, const struct bkey *r)
{
	if (l->p.inode != r->p.inode)
		return l->p.inode < r->p.inode ? -1 : 1;

	if (l->p.offset != r->p.offset)
		return l->p.offset < r->p.offset ? -1 : 1;

	if (l->p.snapshot != r->p.snapshot)
		return l->p.snapshot < r->p.snapshot ? -1 : 1;

	return 0;
}

int bkey_cmp(const struct bkey *l, const struct bkey *r)
{
	int ret;

	EBUG_ON(bkey_packed(l) || bkey_packed(r));

	ret = __bkey_cmp_bits((sizeof(l->inode) +
			       sizeof(l->offset) +
			       sizeof(l->snapshot)) * BITS_PER_BYTE,
			      __high_word(BKEY_U64s, l),
			      __high_word(BKEY_U64s, r));

	BUG_ON(ret != bkey_cmp_verify(l, r));

	return ret;
}
#endif

__pure
int __bkey_cmp_packed_format_checked(const struct bkey_packed *l,
				     const struct bkey_packed *r,
				     const struct btree_keys *b)
{
	const struct bkey_format *f = &b->format;
	int ret;

	EBUG_ON(!bkey_packed(l) || !bkey_packed(r));
	EBUG_ON(b->nr_key_bits != bkey_format_key_bits(f));

	ret = __bkey_cmp_bits(high_word(f, l),
			      high_word(f, r),
			      b->nr_key_bits);

	EBUG_ON(ret != bkey_cmp(bkey_unpack_key_format_checked(b, l).p,
				bkey_unpack_key_format_checked(b, r).p));
	return ret;
}

__pure __flatten
int __bkey_cmp_left_packed_format_checked(const struct btree_keys *b,
					  const struct bkey_packed *l,
					  const struct bpos *r)
{
#ifdef HAVE_BCACHE_COMPILED_UNPACK
	return bkey_cmp(bkey_unpack_key_format_checked(b, l).p, *r);
#else
	return bkey_cmp(__bkey_unpack_pos(&b->format, l), *r);
#endif
}

__pure __flatten
int __bkey_cmp_packed(const struct bkey_packed *l,
		      const struct bkey_packed *r,
		      const struct btree_keys *b)
{
	int packed = bkey_lr_packed(l, r);

	if (likely(packed == BKEY_PACKED_BOTH))
		return __bkey_cmp_packed_format_checked(l, r, b);

	switch (packed) {
	case BKEY_PACKED_NONE:
		return bkey_cmp(((struct bkey *) l)->p,
				((struct bkey *) r)->p);
	case BKEY_PACKED_LEFT:
		return __bkey_cmp_left_packed_format_checked(b,
				  (struct bkey_packed *) l,
				  &((struct bkey *) r)->p);
	case BKEY_PACKED_RIGHT:
		return -__bkey_cmp_left_packed_format_checked(b,
				  (struct bkey_packed *) r,
				  &((struct bkey *) l)->p);
	default:
		unreachable();
	}
}

__pure __flatten
int bkey_cmp_left_packed(const struct btree_keys *b,
			 const struct bkey_packed *l, const struct bpos *r)
{
	const struct bkey *l_unpacked;

	return unlikely(l_unpacked = packed_to_bkey_c(l))
		? bkey_cmp(l_unpacked->p, *r)
		: __bkey_cmp_left_packed_format_checked(b, l, r);
}

void bch_bpos_swab(struct bpos *p)
{
	u8 *l = (u8 *) p;
	u8 *h = ((u8 *) &p[1]) - 1;

	while (l < h) {
		swap(*l, *h);
		l++;
		--h;
	}
}

void bch_bkey_swab_key(const struct bkey_format *_f, struct bkey_packed *k)
{
	const struct bkey_format *f = bkey_packed(k) ? _f : &bch_bkey_format_current;
	u8 *l = k->key_start;
	u8 *h = (u8 *) (k->_data + f->key_u64s) - 1;

	while (l < h) {
		swap(*l, *h);
		l++;
		--h;
	}
}

#ifdef CONFIG_BCACHE_DEBUG
void bkey_pack_test(void)
{
	struct bkey t = KEY(4134ULL, 1250629070527416633ULL, 0);
	struct bkey_packed p;

	struct bkey_format test_format = {
		.key_u64s	= 2,
		.nr_fields	= 5,
		.bits_per_field = {
			13,
			64,
		},
	};

	struct unpack_state in_s =
		unpack_state_init(&bch_bkey_format_current, (void *) &t);
	struct pack_state out_s = pack_state_init(&test_format, &p);
	unsigned i;

	for (i = 0; i < out_s.format->nr_fields; i++) {
		u64 a, v = get_inc_field(&in_s, i);

		switch (i) {
		case 0:
			a = t.p.inode;
			break;
		case 1:
			a = t.p.offset;
			break;
		case 2:
			a = t.p.snapshot;
			break;
		case 3:
			a = t.size;
			break;
		case 4:
			a = t.version;
			break;
		default:
			BUG();
		}

		if (a != v)
			panic("got %llu actual %llu i %u\n", v, a, i);

		if (!set_inc_field(&out_s, i, v))
			panic("failed at %u\n", i);
	}

	BUG_ON(!bkey_pack_key(&p, &t, &test_format));
}
#endif
