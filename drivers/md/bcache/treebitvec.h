#ifndef _TREEBITVEC_H
#define _TREEBITVEC_H

#include <linux/kernel.h>

/* d-ary tree laid out in an array */

#define BITSHIFT	ilog2(BITS_PER_LONG)

struct treebitvec {
	size_t			size;
	size_t			leaf_offset;
	unsigned		depth;
	unsigned long		*bits;
};

static inline size_t treebitvec_up(size_t n)
{
	return n = (n - 1) >> BITSHIFT;
}

static inline size_t treebitvec_down(size_t n)
{
	return (n << BITSHIFT) + 1;
}

static inline void treebitvec_set(struct treebitvec *bv, size_t n)
{
	unsigned bit;

	bit = n & (BITS_PER_LONG - 1);
	n = (bit >> BITSHIFT) + bv->leaf_offset;

	while (!(bv->bits[n] & (1UL << bit))) {
		bv->bits[n] |= (1UL << bit);

		if (!n)
			break;

		bit = n & (BITS_PER_LONG - 1);
		n = treebitvec_up(n);
	}
}

static inline size_t treebitvec_next_set_bit(struct treebitvec *bv, size_t n)
{
	unsigned bit;

	n = (n >> BITSHIFT) + bv->leaf_offset;

	while (1) {
		if (!bv->bits[n]) {
			if (!n)
				return SIZE_MAX;

			n = treebitvec_up(n);
			continue;
		}

		bit = __ffs(bv->bits[n]);
		bv->bits[n] &= ~(1UL << bit);

		if (n >= bv->leaf_offset)
			return ((n - bv->leaf_offset) << BITSHIFT) + bit;

		n = treebitvec_down(n) + bit;
	}
}

static inline int treebitvec_init(struct treebitvec *bv, size_t size)
{
	size_t buf_size;

	bv->size	= size;
	bv->depth	= ilog2(size - 1) / ilog2(BITS_PER_LONG);
	bv->leaf_offset	= ((1UL << ((bv->depth + 1) * BITSHIFT)) - 1) /
		(BITS_PER_LONG - 1);

	buf_size = DIV_ROUND_UP(size, BITS_PER_LONG) + bv->leaf_offset;

	bv->bits = kcalloc(buf_size, sizeof(unsigned long), GFP_KERNEL);
	if (!bv->bits)
		return -ENOMEM;

	return 0;
}

#endif
