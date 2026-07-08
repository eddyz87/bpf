// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/*
 * Linear induction over a PTR_TO_BTF_ID register in a terminating loop.
 *
 * r6 holds a PTR_TO_BTF_ID pointer that is stepped by a fixed stride and read
 * through with bpf_probe_read_kernel(). SCEV widens r6 into a stepped offset
 * range, so - like the scalar convergence tests in verifier_scev.c - the loop
 * should converge in a bounded number of processed instructions, independently
 * of the trip count.
 *
 * PTR_TO_BTF_ID used to fall through to regs_exact() in regsafe(), which
 * requires a byte-exact range/offset; the widened pointer never matched a
 * cached state and the loop failed to converge (fully unrolled / budget blown).
 * The loop body is written in asm so the compiler cannot strength-reduce the
 * pointer induction into a scalar offset or unroll it.
 */
SEC("fentry/bpf_fentry_test1")
__success
__log_level(2)
__msg("widening r6")
/*
 * The widened PTR_TO_BTF_ID must converge: without the regsafe() fix this loop
 * is fully unrolled ("processed 1004 insns", 101 states) instead of converging.
 */
__msg("processed 15 insns")
int widen_btf_ptr(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_struct *p = task->group_leader;

	asm volatile ("						\
	r6 = %[p];						\
	r7 = 0;							\
l0_%=:								\
	r1 = r10;						\
	r1 += -8;						\
	r2 = 8;							\
	r3 = r6;						\
	call %[bpf_probe_read_kernel];				\
	r6 += 16;						\
	r7 += 1;						\
	if r7 < 100 goto l0_%=;					\
"	:
	: [p]"r"(p), __imm(bpf_probe_read_kernel)
	: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "memory");
	return 0;
}
