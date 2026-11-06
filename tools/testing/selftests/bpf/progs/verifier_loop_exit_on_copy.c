// SPDX-License-Identifier: GPL-2.0
/*
 * A 1024-byte map value holds NUL-terminated strings back to back. The program walks them with one
 * index: while the byte at the index is not NUL, the outer loop checks that the index is at most
 * 512, records where the string starts and skips to its end with "while (buf[idx++] && idx < 512)".
 * clang keeps the index in one register (r1), increments it at the head of the skip loop and tests
 * the bound and loads the byte through a copy (r3) taken before the increment and refreshed before
 * the back edge; after the loop the index itself, which no jump of the loop tests, is added to the
 * buffer to load the byte of the outer condition. That is safe: the copy equals the index on both
 * edges into the head, so the index is the tested copy plus one, at most 513 in 1024 bytes.
 *
 * Scalar evolution describes the index but has no closed form for the copy, which holds the entry
 * value at the head in the first trip and the previous index afterwards, so the exit that tests the
 * copy is not linear, the back edge tests a loaded byte, and the loop is not counted:
 *
 *	scev at header 16:
 *	  r1=(+ r1 1) / (linear r1 1)
 *	  r3=(+ r1 1) / ?
 *	loop header at 16, non-linear latch at 22
 *	loop header at 16, non-linear exit at 17
 *	loop header at 16, can't compute iterations count
 *
 * The outer loop ends on a loaded byte too and is followed trip by trip (its states carry
 * iter(29)=0); nested in that walk, the skip loop has no room to be followed to its end, which
 * takes up to 512 trips, so the state that comes back to its head is widened. The index is linear
 * and its bound moved, but the only compare of the loop is on the copy: no jump gives the index a
 * stop and it is forgotten; the copy is widened to S32_MAX and bounded again by the exit test. The
 * exits meet with the index unknown, where following each path gives a constant 1..513:
 *
 *	from 22 to 16: widened
 *	16: (07) r1 += 1                      ; R1=scalar() iter(29)=0 loop_stack=29,16
 *	from 17 to 23: joined
 *	24: (0f) r3 += r1
 *	math between map_value pointer and register with unbounded min value is not allowed
 *
 * The loops of nested_skip_loop_exit_tests_index_copy() as compiled (insns 0-15 look the map value
 * up, leave when its first byte is NUL, set idx = 0 and jump to 29):
 *	16: r1 += 0x1                     <- head of the skip loop: idx += 1
 *	17: if r3 > 0x1fe goto 23         <- exit: tests the copy
 *	18: r4 = r0
 *	19: r4 += r3
 *	20: w4 = *(u8 *)(r4 + 0x0)        <- buf[copy]
 *	21: r3 = r1                       <- copy = idx
 *	22: if w4 != 0x0 goto 16          <- back edge: the byte is not NUL
 *	23: r3 = r0
 *	24: r3 += r1                      <- rejected: idx, which no jump of the skip loop tests
 *	25: w3 = *(u8 *)(r3 + 0x0)        <- buf[idx], the outer condition
 *	26: if w3 != 0x0 goto 29          <- back edge of the outer loop (27-28: return 0)
 *	29: if r1 > 0x200 goto 27         <- head of the outer loop: leave when idx > 512
 *	30: *(u64 *)(r2 + 0x0) = r1       <- last = idx
 *	31: r3 = r1                       <- copy = idx
 *	32: goto 16
 * The test depends on the skip loop testing and loading through the copy while the index it adds
 * to the buffer afterwards is tested by no jump of it, and on the nesting, which cuts the walk of
 * the skip loop short.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* Unsigned, so that the two tests on the signed index fold into one unsigned compare. */
#define STR_MAX 512UL

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[2 * STR_MAX]);
} strings SEC(".maps");

/* Where the last string starts. */
long last;

SEC("socket")
__success __retval(0)
int nested_skip_loop_exit_tests_index_copy(void *ctx)
{
	__u32 zero = 0;
	long idx = 0;
	char *buf;

	buf = bpf_map_lookup_elem(&strings, &zero);
	if (!buf)
		return 0;
	while (buf[idx]) {
		/* Without the negative-index test clang hoists the bound test above the load. */
		if (idx < 0 || idx > STR_MAX)
			break;
		/* Gives the loops an effect; a store stays ahead of the loads of the skip loop. */
		last = idx;
		while (buf[idx++] && idx < STR_MAX)
			;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
