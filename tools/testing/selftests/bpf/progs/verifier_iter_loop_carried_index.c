// SPDX-License-Identifier: GPL-2.0
/*
 * A profiler appends records to a buffer in a map value. An open-coded iterator loop (bpf_for
 * over four values) walks a chain of nodes: it counts its trips in a 32-bit stack slot tested at
 * the top of the body, reads three fields of the chain with calls whose failure ends the loop,
 * looks the node up in a map and copies its records into the buffer in an inner loop. The index
 * of the next free record is carried from trip to trip; the compiler forms the record address
 * from the index before the inner loop and tests only the sum of the index and the inner counter
 * inside it, against a limit of nine. The stores are safe because that sum test keeps the index
 * below nine and, independently, four trips of at most nine records fit a buffer of 48 records.
 *
 * The outer loop is not counted: only the four exit conditions nearest to the back edge are
 * examined, all four test results of calls, and the test of the trip counter at insn 66, the
 * fifth one up the chain (the 15th in the original program), is not looked at:
 *   scev at header 63:
 *     r8=(any (any r8 ?) (+ (s>> (<< (zext32 r8) 32) 32) ?)) / ?
 *     *fp-8=(spill32 (+ *fp-8 1)) / (spill32 (linear (zext32 *fp-8) 1))
 *   loop header at 63, non-linear latch at 57
 *   loop header at 63, non-linear exit at 85
 *   loop header at 63, non-linear exit at 79
 *   loop header at 63, non-linear exit at 73
 *   loop header at 63, can't compute iterations count
 * Bounded by the iterator, the loop is not walked trip by trip either: what comes back on the
 * back edge is widened into the head state. The index r8 is 0 at the head and comes back as
 * [0,9]; its only comparison, "31: (65) if r8 s> 0x8", would let it stop at 8, and 9 is above:
 *   from 57 to 63: widened
 *   R8=scalar(smin=smin32=0,smax=umax=umax32=0x7fffffff,var_off=(0x0; 0x7fffffff))
 *   fp-8=ppppscalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))
 * In the second pass the pointer formed at insns 92-98 has the offset [16, 0x13ffffffe8], the
 * inner loop is counted ("loop header at 25, header_count is [0..9]"), its test at 31 narrows
 * the sum alone, and the first store of the copy, "37: (7b) *(u64 *)(r5 +32) = r9", is rejected:
 *   R5 unbounded memory access, make sure to bounds check any such access
 *
 * Expected assembly of the loops, trimmed to the insns that matter:
 *   25: r8 = r1                     <- inner head; 26: r8 += r3 makes idx + j (r1 = idx, r3 = j)
 *   30: if r3 s>= r5 goto 51        <- inner exit: j >= node->cnt
 *   31: if r8 s> 0x8 goto 51        <- inner exit: idx + j > 8, the only test of the index
 *   37: *(u64 *)(r5 + 0x20) = r9    <- rejected; 33: r5 += r4 made r5 = &buf->recs[idx] + j * 40
 *   48: if r4 != 0x168 goto 25      <- inner back edge; 49: idx += j
 *   51: w1 = *(u32 *)(r10 - 0x8)    <- latch block: trips++ in the slot (51-53), then the iterator
 *   57: if r0 != 0x0 goto 63        <- the only back edge; the inner exits and 91 lead here too
 *   63: w1 = *(u32 *)(r0 + 0x0)     <- head
 *   64: if w1 > 0x3 goto 58         <- exit: the range of bpf_for
 *   66: if w1 == 0x4 goto 58        <- exit: the trip counter
 *   73: if r0 != 0x0 goto 58        <- exit: status of bpf_probe_read_kernel()
 *   79: if r0 != 0x0 goto 58        <- exit: status of bpf_probe_read_kernel()
 *   85: if r0 != 0x0 goto 58        <- exit: status of bpf_probe_read_kernel()
 *   91: if r0 == 0x0 goto 51        <- no node: to the latch block
 *   98: r2 += r3                       r2 = &buf->recs[idx]: 92-97 sign-extend idx, times 40
 * The test depends on the single back edge being the iterator's NULL test, on the three status
 * checks between the trip test and that back edge, and on the hoisting of the record pointer.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define NR_TRIPS	4
#define RECS_PER_NODE	9
#define MAX_IDX		9
#define BUF_RECS	48	/* room for NR_TRIPS * RECS_PER_NODE records */

struct rec {
	__u64 addr;
	char name[32];
};

struct buf {
	__u64 top;
	__u32 cnt;
	struct rec recs[BUF_RECS];
};

struct node {
	int cnt;
	struct rec recs[RECS_PER_NODE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct buf);
} buf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct node);
} node_map SEC(".maps");

SEC("socket")
__success __retval(0)
int iter_loop_carried_index_tested_only_as_sum(void *ctx)
{
	/*
	 * volatile: the trip counter lives in a 32-bit stack slot, as in the original program;
	 * 8-aligned: the slot is a spill the verifier tracks, not misc bytes that bound nothing.
	 */
	volatile __u32 trips __aligned(8) = 0;
	struct buf *buf;
	struct node *node;
	__u64 cur, code;
	__u32 zero = 0, id;
	int idx = 0, i, j;

	buf = bpf_map_lookup_elem(&buf_map, &zero);
	if (!buf)
		return 0;
	cur = buf->top;
	bpf_for(i, 0, NR_TRIPS) {
		if (trips == NR_TRIPS)
			break;
		if (bpf_probe_read_kernel(&code, sizeof(code), (void *)(cur + 8)))
			break;
		if (bpf_probe_read_kernel(&id, sizeof(id), (void *)code))
			break;
		if (bpf_probe_read_kernel(&cur, sizeof(cur), (void *)cur))
			break;
		node = bpf_map_lookup_elem(&node_map, &id);
		if (node) {
			/* Unrolled, the inner loop would test each index as a constant. */
#pragma clang loop unroll(disable)
			/* Running index: clang tests the sum idx + j and hoists &buf->recs[idx]. */
			for (j = 0; j < RECS_PER_NODE && j < node->cnt && idx < MAX_IDX; j++, idx++)
				buf->recs[idx] = node->recs[j];
		}
		/* Incremented at the back edge, tested at the head, as in the original program. */
		trips++;
	}
	buf->cnt = idx;
	return 0;
}

char _license[] SEC("license") = "GPL";
