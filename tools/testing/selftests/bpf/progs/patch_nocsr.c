// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("kprobe/bpf_jit_inlines_helper_call")
int no_bpf_jit_inlines_helper_call(struct pt_regs *ctx)
{
	/* ask verifier to not inline helpers when this
	 * probe is installed
	 */
	bpf_override_return(ctx, 0);
	return 0;
}

SEC("?raw_tp")
__success
__naked void get_current_task_no_csr_patched(void)
{
	/* bump stack depth and use caller saved registers in-between
	 * calls to bpf_get_current_task(), verifier should insert
	 * spills/fills for r1/r2/r3 if the function is not jitted.
	 */
	asm volatile ("					\
	*(u64 *)(r10 - 8) = 5;				\
	r1 = 7;						\
	r2 = 35;					\
	call %[bpf_get_current_task];			\
	r3 = r1;					\
	r3 += r2;					\
	call %[bpf_get_current_task];			\
	r0 = r3;					\
	exit;						\
"	:
	: __imm(bpf_get_current_task)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
