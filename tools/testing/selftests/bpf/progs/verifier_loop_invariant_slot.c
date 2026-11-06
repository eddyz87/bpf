// SPDX-License-Identifier: GPL-2.0
/*
 * An LSM hook keeps its verdict in a 32-bit stack slot: it stores 0 (allow) and, when a rule
 * denies, -1 over it, so two states, one with the slot at 0 and one with it at 0xffffffff, meet
 * before a loop and both enter it. The loop is an open-coded iterator loop (bpf_for) whose body
 * overwrites a 64-bit stack variable with bpf_probe_read_kernel() and never touches the slot; the
 * variable is read after the loop, so it is live at the head, a constant on entry and unknown
 * after an iteration. After the loop the slot is loaded once and tested: a non-zero value is
 * returned, otherwise the verdict of the earlier hooks, which is in [-4095, 0].
 * Nothing but the two constant stores writes the slot, so the hook returns 0, -1 or that earlier
 * verdict on every path, inside the [-4095, 0] range of the 32-bit LSM return check.
 *
 * The verifier keeps the two states apart before and at the loop head: the slot is tested after
 * the loop and its two values leave a gap. The loop is not counted,
 *   loop header at 20, non-linear latch at 30
 *   loop header at 20, can't compute iterations count
 * and not walked, an iterator loop being bounded at run time, so two head states arrive:
 *   from 19 to 20: ... fp-8=pppp0 fp-16=0 fp-24=iter_num(id=1,state=active) ...
 *   from 19 to 20: ... fp-8=pppp0xffffffff fp-16=0 fp-24=iter_num(id=3,state=active) ...
 * The state that comes back over the latch is not within the head state it started from (fp-16
 * is unknown now), so it is joined with both head states, its own and the other entry's, and
 * widened; the rules that kept the two entries apart do not apply to a state that arrives over
 * a back edge:
 *   from 30 to 20: widened
 *   from 30 to 20: ... fp-8=ppppscalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) ...
 *   from 30 to 20: within
 * One head state is left whose slot covers everything from 0 to 0xffffffff although no path
 * stores anything but 0 or 0xffffffff. After the loop "39: if w1 == 0x0" leaves [1, 0xffffffff]
 * with a full 32-bit signed range and the exit is rejected: "At program exit the register R0 has
 * smin=0 smax=4294967295 should have been in [-4095, 0]". A verifier that follows the paths sees
 * 0 or 0xffffffff in the slot and loads the program.
 *
 * Expected assembly, trimmed to the insns that matter, jump targets as absolute insn numbers:
 *     3: *(u32 *)(r10 - 0x8) = w1     <- verdict = 0
 *     8: if w0 == 0x0 goto 11         <- the rule
 *    10: *(u32 *)(r10 - 0x8) = w1     <- verdict = -1; the two states meet at 11
 *    19: if r0 == 0x0 goto 31         <- exit: bpf_iter_num_next() gave no first element
 *    20: w1 = *(u32 *)(r0 + 0x0)      <- head
 *    21: if w1 > 0x7 goto 31          <- exit: the range of bpf_for
 *    26: call 0x71                       bpf_probe_read_kernel() into fp-16
 *    29: call -0x1                       bpf_iter_num_next()
 *    30: if r0 != 0x0 goto 20         <- latch, the only back edge
 *    36: r2 = *(u64 *)(r10 - 0x10)    <- fp-16 is read: live at the head
 *    38: w1 = *(u32 *)(r10 - 0x8)     <- the slot is loaded
 *    39: if w1 == 0x0 goto 41         <- and tested
 *    40: w6 = w1
 *    41: w0 = w6
 *    42: exit                         <- rejected
 * The test depends on the slot being written by two stores on two paths and loaded through fp at
 * an 8-byte aligned offset, on the iterator's NULL test being the only back edge, and on the body
 * overwriting a stack value that is live at the head.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

__u64 last;

SEC("lsm/file_open")
__success
int BPF_PROG(verdict_slot_invariant_across_iter_loop, struct file *file, int ret)
{
	/* volatile: stored and loaded through fp; aligned(8): in its own 8-byte aligned slot */
	volatile __u32 verdict __aligned(8);
	__u64 n = 0;	/* its address is taken: a stack value, a constant at the loop head */
	__u32 v;
	int i;

	verdict = 0;
	if (bpf_get_prandom_u32() & 1)
		verdict = -1;	/* a second volatile store: not merged with the first */

	bpf_for(i, 0, 8)
		bpf_probe_read_kernel(&n, sizeof(n), file);	/* n becomes unknown */
	last = n;	/* read after the loop: n is live at the loop head */

	v = verdict;	/* one load of the slot */
	return v ? (int)v : ret;	/* ret: the verdict of the earlier hooks, in [-4095, 0] */
}

char _license[] SEC("license") = "GPL";
