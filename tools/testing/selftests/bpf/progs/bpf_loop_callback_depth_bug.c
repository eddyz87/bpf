// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct ctx {
	__u64 a;
	__u64 b;
	__u64 c;
};

static __naked void loop_cb(void)
{
	/* This is the same as C code below, but written
	 * in assembly to control which branches are fall-through.
	 *
	 *   switch (bpf_get_prandom_u32()) {
	 *   case 1:  ctx->a = 42; break;
	 *   case 2:  ctx->b = 42; break;
	 *   default: ctx->c = 42; break;
	 *   }
	 */
	asm volatile (
	"r9 = r2;"
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r2 = 42;"
	"r0 = 0;"
	"if r1 == 0x1 goto 1f;"
	"if r1 == 0x2 goto 2f;"
	"*(u64 *)(r9 + 16) = r2;"
	"exit;"
	"1: *(u64 *)(r9 + 0) = r2;"
	"exit;"
	"2: *(u64 *)(r9 + 8) = r2;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all
	);
}

SEC("tc")
int test(struct __sk_buff *skb)
{
	struct ctx ctx = { 7, 7, 7 };

	bpf_loop(2, loop_cb, &ctx, 0);
	if (ctx.a == 42 && ctx.b == 42 && ctx.c == 7)
		asm volatile("r0 /= 0;":::"r0");
	return 0;
}

char _license[] SEC("license") = "GPL";
