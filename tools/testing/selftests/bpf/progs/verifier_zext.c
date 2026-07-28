// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * regsafe() ignores subreg_def, so a 32-bit subreg def can be pruned against a
 * full 64-bit def, dropping the pending zext mark. STATE_FREQ forces the prune,
 * RND_HI32 makes the missing zero-extension observable on x86.
 */
SEC("socket")
__flag(BPF_F_TEST_STATE_FREQ)
__flag(BPF_F_TEST_RND_HI32)
__success __retval(0)
__naked void zext_lost_across_checkpoint(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	r8 = r0;		/* unknown, nonzero at runtime */	\
	r6 = 0xdeadbeefcafebabe ll;	/* attacker residual */	\
	/* fall-through (safe) cached first, branch (danger) pruned */	\
	if r8 != 0 goto l_danger_%=;			\
	r6 = 32;		/* full 64-bit def */		\
	goto l_use_%=;					\
l_danger_%=:						\
	w6 = 32;		/* 32-bit def, zext mark lost */	\
l_use_%=:						\
	r0 = r6;		/* verifier believes upper 32 bits are 0 */	\
	r0 >>= 32;					\
	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
