#ifndef _LINUX_CNUM_H
#define _LINUX_CNUM_H

#include <linux/types.h>

/*
 * cnum: a circular number.
 * A unified representation for signed and unsigned 32-bit ranges.
 *
 * Assume that 32-bit range is a circle, with 0 being in 12-o'clock
 * position, numbers put sequentially in a clockwise order and U32_MAX
 * in 11-o'clock position.
 *
 * @cnum32 represents an arc on this circle drawn in clockwise direction.
 * For a given unsigned range @base corresponds to minimal value of the range.
 * @size corresponds to the number of integers in the range excluding @base.
 * (The @base is excluded to avoid integer overflow when representing full
 *  0..U32_MAX range, that corresponds to 2^32 which can't be stored in u32).
 * For a given signed range ... TODO: explain ...
 */
struct cnum32 {
	u32 base;
	u32 size;
};

struct cnum32 cnum32_from_urange(u32 min, u32 max);
struct cnum32 cnum32_from_srange(s32 min, s32 max);
u32 cnum32_umin(struct cnum32 cnum);
u32 cnum32_umax(struct cnum32 cnum);
s32 cnum32_smin(struct cnum32 cnum);
s32 cnum32_smax(struct cnum32 cnum);
bool cnum32_intersect(struct cnum32 a, struct cnum32 b, struct cnum32 *out);
bool cnum32_contains(struct cnum32 cnum, u32 v);

struct cnum64 {
	u64 base;
	u64 size;
};

struct cnum64 cnum64_from_urange(u64 min, u64 max);
struct cnum64 cnum64_from_srange(s64 min, s64 max);
u64 cnum64_umin(struct cnum64 cnum);
u64 cnum64_umax(struct cnum64 cnum);
s64 cnum64_smin(struct cnum64 cnum);
s64 cnum64_smax(struct cnum64 cnum);
bool cnum64_intersect(struct cnum64 a, struct cnum64 b, struct cnum64 *out);
bool cnum64_contains(struct cnum64 cnum, u64 v);

#endif /* _LINUX_CNUM_H */
