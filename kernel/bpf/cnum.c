// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bits.h>
#include <linux/math64.h>

/* *result = c*d - a*b, if fits in u32; all operands unsigned */
static bool check_mul_u32_u32_sub(u32 a, u32 b, u32 c, u32 d, u32 *result)
{
	u64 size = (u64)c * d - (u64)a * b;

	if (size > U32_MAX)
		return false;
	*result = size;
	return true;
}

/* *result = c*d - a*b, if fits in u32; all operands signed */
static bool check_mul_s32_s32_sub(s32 a, s32 b, s32 c, s32 d, u32 *result)
{
	s64 size = (s64)c * d - (s64)a * b;

	if (size > U32_MAX)
		return false;
	*result = size;
	return true;
}

/* Return (s128)a * b >> shift */
static s64 mul_s64_s64_shr(s64 a, s64 b, unsigned int shift)
{
	return mul_s64_u64_shr(a, abs(b), shift) * (b < 0 ? -1 : 1);
}

/* *result = c*d - a*b, if fits in u64; all operands unsigned */
static bool check_mul_u64_u64_sub(u64 a, u64 b, u64 c, u64 d, u64 *result)
{
	u64 cd_hi = mul_u64_u64_shr(c, d, 64);
	u64 cd_lo = c * d;
	u64 ab_hi = mul_u64_u64_shr(a, b, 64);
	u64 ab_lo = a * b;
	u64 borrow = cd_lo < ab_lo;
	u64 hi = cd_hi - ab_hi - borrow;

	if (hi != 0)
		return false;
	*result = cd_lo - ab_lo;
	return true;
}

/* *result = c*d - a*b, if fits in u64; all operands signed */
static bool check_mul_s64_s64_sub(s64 a, s64 b, s64 c, s64 d, u64 *result)
{
	s64 cd_hi = mul_s64_s64_shr(c, d, 64);
	u64 cd_lo = (u64)c * (u64)d;
	s64 ab_hi = mul_s64_s64_shr(a, b, 64);
	u64 ab_lo = (u64)a * (u64)b;
	u64 borrow = cd_lo < ab_lo;
	s64 hi = cd_hi - ab_hi - borrow;

	if (hi != 0)
		return false;
	*result = cd_lo - ab_lo;
	return true;
}

#define T 32
#include "cnum_defs.h"
#undef T

#define T 64
#include "cnum_defs.h"
#undef T

struct cnum32 cnum32_from_cnum64(struct cnum64 cnum)
{
	if (cnum64_is_empty(cnum))
		return CNUM32_EMPTY;

	if (cnum.size > U32_MAX)
		return (struct cnum32){ .base = 0, .size = U32_MAX };
	else
		return (struct cnum32){ .base = (u32)cnum.base, .size = cnum.size };
}

/*
 * Suppose 'a' and 'b' are laid out as follows:
 *
 *                                                          64-bit number axis --->
 *
 * N*2^32                   (N+1)*2^32                (N+2)*2^32                (N+3)*2^32
 * ||------|---|=====|-------||----------|=====|-------||----------|=====|----|--||
 *         |   |< b >|                   |< b >|                   |< b >|    |
 *         |   |                                                         |    |
 *         |<--+--------------------------- a ---------------------------+--->|
 *             |                                                         |
 *             |<-------------------------- t -------------------------->|
 *
 * In such a case it is possible to infer a more tight representation t
 * such that ∀ v ∈ a, (u32)a ∈ b: v ∈ t.
 */
struct cnum64 cnum64_cnum32_intersect(struct cnum64 a, struct cnum32 b)
{
	/*
	 * To simplify reasoning, rotate the circles so that [virtual] a1 starts
	 * at u32 boundary, b1 represents b in this new frame of reference.
	 */
	struct cnum32 b1 = { b.base - (u32)a.base, b.size };
	struct cnum64 t = a;
	u64 d, b1_max;

	if (cnum64_is_empty(a) || cnum32_is_empty(b))
		return CNUM64_EMPTY;

	if (cnum32_urange_overflow(b1)) {
		b1_max = (u32)b1.base + (u32)b1.size; /* overflow here is fine and necessary */
		if ((u32)a.size > b1_max && (u32)a.size < b1.base) {
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||=====|------------|=====||=====|---------|---|=====||
			 *  |b1 ->|            |<- b1||b1 ->|         |   |<- b1|
			 *  |<----------------- a1 ------------------>|
			 *  |<-------------- t ------------>|<-- d -->| (after adjustment)
			 *                                  ^
			 *                                b1_max
			 */
			d = (u32)a.size - b1_max;
			t.size -= d;
		} else {
			/*
			 * No adjustments possible in the following cases:
			 *
			 * ||=====|------------|=====||===|=|-------------|=|===||
			 *  |b1 ->|            |<- b1||b1 +>|             |<+ b1|
			 *  |<----------------- a1 ------>|                 |
			 *  |<----------------- (or) a1 ------------------->|
			 */
		}
	} else {
		if (t.size < b1.base)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||----------|--|=======|--||------>
			 *  |<-- a1 -->|  |<- b ->|
			 */
			return CNUM64_EMPTY;
		/*
		 * N*2^32                   (N+1)*2^32
		 * ||-------------|========|-||-----| -------|========|-||
		 *  |             |<- b1 ->|        |        |<- b1 ->|
		 *  |<------------+ a1 ------------>|
		 *                |<------ t ------>| (after adjustment)
		 */
		t.base += b1.base;
		t.size -= b1.base;
		b1_max = b1.base + b1.size;
		d = 0;
		if ((u32)a.size < b1.base)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||-------------|========|-||------|-------|========|-||
			 *  |             |<- b1 ->|         |       |<- b1 ->|
			 *  |<------------+-- a1 --+-------->|
			 *                |<- t  ->|<-- d -->| (after adjustment)
			 */
			d = (u32)a.size + (BIT_ULL(32) - b1_max);
		else if ((u32)a.size >= b1_max)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||--|========|------------||--|========|-------|-----||
			 *  |  |<- b1 ->|                |<- b1 ->|       |
			 *  |<-+------------------ a1 ------------+------>|
			 *     |<-------------- t --------------->|<- d ->| (after adjustment)
			 */
			d = (u32)a.size - b1_max;
		if (t.size < d)
			return CNUM64_EMPTY;
		t.size -= d;
	}
	return t;
}
