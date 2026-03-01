/*
 * cnum_defs.h - circular number definitions, poor man's C template.
 *
 * Usage:
 *   #define T 8
 *   #include "cnum_defs.h"
 *   #undef T
 *
 * Caller must pre-define: uT, sT, UT_MAX, ST_MAX, ST_MIN
 * (e.g. u8, s8, U8_MAX, S8_MAX, S8_MIN for T=8)
 */

#ifndef T
#error "Define T (bit width: 8, 16, 32, 64) before including cnum_defs.h"
#endif

/* Common includes */
#include <linux/cnum.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/compiler_types.h>

/* Parameterized names for this instantiation */
#define cnum_t  __PASTE(cnum, T)
#define ut      __PASTE(u, T)
#define st      __PASTE(s, T)
#define UT_MAX  __PASTE(__PASTE(U, T), _MAX)
#define ST_MAX  __PASTE(__PASTE(S, T), _MAX)
#define ST_MIN  __PASTE(__PASTE(S, T), _MIN)
#define FN(name) __PASTE(__PASTE(cnum, T), __PASTE(_, name))

struct cnum_t FN(from_urange)(ut min, ut max)
{
	return (struct cnum_t){ .base = min, .size = max - min };
}

struct cnum_t FN(from_srange)(st min, st max)
{
	ut size = (ut)max - (ut)min;
	ut base = size == UT_MAX ? 0 : (ut)min;

	return (struct cnum_t){ .base = base, .size = size };
}

static inline bool FN(urange_overflow)(struct cnum_t cnum)
{
	return cnum.size > UT_MAX - cnum.base;
}

ut FN(umin)(struct cnum_t cnum)
{
	return FN(urange_overflow)(cnum) ? 0 : cnum.base;
}

ut FN(umax)(struct cnum_t cnum)
{
	return FN(urange_overflow)(cnum) ? UT_MAX : cnum.base + cnum.size;
}

static inline bool FN(srange_overflow)(struct cnum_t cnum)
{
	return FN(contains)(cnum, (ut)ST_MAX) && FN(contains)(cnum, (ut)ST_MIN);
}

st FN(smin)(struct cnum_t cnum)
{
	return FN(srange_overflow)(cnum)
	       ? ST_MIN
	       : min((st)cnum.base, (st)(cnum.base + cnum.size));
}

st FN(smax)(struct cnum_t cnum)
{
	return FN(srange_overflow)(cnum)
	       ? ST_MAX
	       : max((st)cnum.base, (st)(cnum.base + cnum.size));
}

bool FN(intersect)(struct cnum_t a, struct cnum_t b, struct cnum_t *out)
{
	struct cnum_t b1;
	ut dbase;

	if (a.base > b.base)
		swap(a, b);

	dbase = b.base - a.base;
	b1 = (struct cnum_t){ dbase, b.size };
	if (FN(urange_overflow)(b1)) {
		if (b1.base <= a.size) {
			/* a and b intersect in two arcs */
			*out = a.size < b.size ? a : b;
			return true;
		} else {
			/* b "tail" intersects 'a' */
			out->base = a.base;
			out->size = min(a.size, (ut)(b1.base + b1.size));
			return true;
		}
	} else if (a.size >= b1.base) {
		out->base = b.base;
		out->size = min((ut)(a.size - dbase), b1.size);
		return true;
	} else {
		return false;
	}
}

bool FN(contains)(struct cnum_t cnum, ut v)
{
	if (FN(urange_overflow)(cnum))
		return v >= cnum.base || v <= (ut)(cnum.base + cnum.size);
	else
		return v >= cnum.base && v <= (ut)(cnum.base + cnum.size);
}

/* Clean up parameterized macros */
#undef cnum_t
#undef ut
#undef st
#undef UT_MAX
#undef ST_MAX
#undef ST_MIN
#undef FN
