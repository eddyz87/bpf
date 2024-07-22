// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("tp")
__jited_x86("f:	endbr64")
__jited_x86("13:	movabs $0x.*,%r9")
__jited_x86("1d:	add    %gs:0x.*,%r9")
__jited_x86("26:	mov    $0x1,%edi")
__jited_x86("2b:	mov    %rdi,-0x8(%r9)")
__jited_x86("2f:	mov    -0x8(%r9),%rdi")
__jited_x86("33:	xor    %eax,%eax")
__jited_x86("35:	lock xchg %rax,-0x8(%r9)")
__jited_x86("3a:	lock xadd %rax,-0x8(%r9)")
__naked void stack_access_insns(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = *(u64 *)(r10 - 8);"
	"r0 = 0;"
	"r0 = xchg_64(r10 - 8, r0);"
	"r0 = atomic_fetch_add((u64 *)(r10 - 8), r0);"
	"exit;"
	::: __clobber_all);
}

SEC("tp")
__jited_x86("f:	endbr64")
__jited_x86("13:	movabs $0x.*,%r9")
__jited_x86("1d:	add    %gs:.*,%r9")
__jited_x86("26:	push   %r9")
__jited_x86("28:	call   0x.*")
__jited_x86("2d:	pop    %r9")
__jited_x86("2f:	push   %r9")
__jited_x86("31:	call   0x.*")
__jited_x86("36:	pop    %r9")
__jited_x86("38:	leave")
__naked void calls(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"call dummy_subprog;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

static __naked __noinline __used
void dummy_subprog(void)
{
	asm volatile (
	"r0 = 0;"
	"exit"
	::: __clobber_all);
}
