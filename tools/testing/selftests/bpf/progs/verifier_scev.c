// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
SEC("xdp")
__success
__log_level(2)
__msg("scev at header 1: r0=(+ r0 1) / (linear r0 1)")
__naked void simple_loop1(void)
{
	asm volatile ("					\
	r0 = 0;						\
loop_%=:						\
	if r0 == 10 goto exit_%=;			\
	r0 += 1;					\
	goto loop_%=;					\
exit_%=:						\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg("scev at header 2: r0=(+ fp-8 1) / ? fp-8=(+ fp-8 1) / (linear fp-8 1)")
__msg(" scev at latch 3: r0=fp-8 / (linear fp-8 1)")
__naked void simple_loop2(void)
{
	asm volatile ("					\
	r0 = 0;						\
	*(u64 *)(r10 - 8) = r0;				\
loop_%=:						\
	r0 = *(u64 *)(r10 - 8);				\
	if r0 == 10 goto exit_%=;			\
	r0 = *(u64 *)(r10 - 8);				\
	r0 += 1;					\
	*(u64 *)(r10 - 8) = r0;				\
	goto loop_%=;					\
exit_%=:						\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg("scev at header 2: r1=(+ r1 1) / (linear r1 1)")
__naked void meet_agrees(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = 0;						\
1:							\
	if r1 == 2 goto 3f;				\
	if r0 == 7 goto 2f;				\
	r1 += 1;					\
	goto 1b;					\
2:							\
	r1 += 1;					\
	goto 1b;					\
3:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__failure
__log_level(2)
__msg("scev at header 1: r0=? r1=? r2=? r3=? r4=? r5=? r6=?")
__naked void meet_disagrees(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 3f;				\
	call %[bpf_get_prandom_u32];			\
	if r0 == 7 goto 1b;				\
	r6 += 1;					\
	goto 1b;					\
3:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__failure
__log_level(2)
__msg("scev at header 1: r6=(bswap32 (bswap32 (zext32 (- (- (zext32 (+ (>> (<< (+ r6 1) 32) 32) 1)))))))")
__naked void expr_chain(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 2f;				\
	r6 += 1;					\
	r6 <<= 32;					\
	r6 >>= 32;					\
	w6 += 1;					\
	r6 = -r6;					\
	w6 = -w6;					\
	r6 = bswap32 r6;				\
	r6 = bswap32 r6;				\
	goto 1b;					\
2:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__msg("scev at header 1: r6=(+ r6 1) / (linear r6 1) r7=?")
__msg("scev at header 4: r7=(+ r7 1) / (linear r7 1)")
__naked void nested_loop1(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:							\
	if r6 == 2 goto 2f;				\
	r6 += 1;					\
	r7 = 0;						\
3:							\
	if r7 == 2 goto 4f;				\
	r7 += 1;					\
	goto 3b;					\
4:							\
	goto 1b;					\
2:							\
	r0 = r7;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
