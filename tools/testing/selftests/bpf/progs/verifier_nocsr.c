// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__success __retval(42)
__naked void get_current_task_no_csr(void)
{
	asm volatile ("					\
	r1 = 42;					\
	call %[bpf_get_current_task];			\
	r0 = r1;					\
	exit;						\
"	:
	: __imm(bpf_get_current_task)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
