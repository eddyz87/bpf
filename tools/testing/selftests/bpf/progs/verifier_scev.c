// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct map_val {
	char foo[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct map_val);
} map SEC(".maps");

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

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 10 post-cond")
__msg("loop header at 1, widening r0 by 9")
__msg("processed 6 insns")
__naked void post_cond_jlt(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 8")
__msg("loop header at 1, widening r0 by 7")
__msg("1: R0=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=9,{{.*}})")
__msg("processed 6 insns")
__naked void post_cond_jlt_with_base(void)
{
	asm volatile ("					\
	r0 = 2;						\
1:	r0 += 1;					\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 11")
__msg("loop header at 1, widening r0 by 10")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})") // TODO: __msg_next
__msg("processed 6 insns")
__naked void post_cond_jle(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 <= 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 10")
__msg("loop header at 1, widening r0 by 9")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=9,{{.*}})")
__msg("processed 7 insns")
__naked void post_cond_jge(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 >= 10 goto 2f;				\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 11")
__msg("loop header at 1, widening r0 by 10")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=10,{{.*}})")
__msg("processed 9 insns")
__naked void pre_cond_jge(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	if r0 >= 10 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 2 post-cond")
__naked void post_cond_jgt(void)
{
	asm volatile ("					\
	r0 = 2;						\
1:	r0 += -1;					\
	if r0 > 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("scev at header 1: r0=(+ r0 1) / (linear r0 1)")
__msg(" scev at latch 2: r0=(+ r0 1) / (linear (+ r0 1) 1)")
__msg("      latch at 2: (55) if r0 != 0x3 goto pc-2")
__msg("loop header at 1, widening r0")
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2,{{.*}})")
__msg("1: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})")
__msg("2: (55) if r0 != 0x3 goto pc-2")
__msg("2: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})")
__msg("loop header at 1, clamping r0")
__msg("1: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=2,{{.*}})")
__msg("1: (07) r0 += 1")
__msg("2: safe")
__msg("from 2 to 3: R0=3")
__msg("3: R0=3")
__msg("3: (95) exit")
__msg("processed 6 insns")
__naked void post_cond_jne(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 != 3 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("scev at header 1: r0=(+ r0 1) / (linear r0 1)")
__msg(" scev at latch 1: r0=(+ r0 1) / (linear r0 1)")
__msg("      latch at 1: (15) if r0 == 0x3 goto pc+2")
__msg("loop header at 1, widening r0")
/*
 * Checkpoint created at this point is not helpful for loop convergence,
 * as loop_stack_push() and widening happen after is_state_visited() call.
 */
__msg("1: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=3,{{.*}})")
__msg("1: (15) if r0 == 0x3 goto pc+2")
__msg("2: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=4,{{.*}})")
__msg("3: (05) goto pc-3")
/* Hence, second iteration is verified in full. */
__msg("loop header at 1, clamping r0")
__msg("1: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=3,{{.*}})")
__msg("1: (15) if r0 == 0x3 goto pc+2")
__msg("2: (07) r0 += 1                       ; R0=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=4,{{.*}})")
__msg("3: (05) goto pc-3")
__msg("1: safe")
__msg("from 1 to 4: R0=3")
__msg("4: R0=3")
__msg("4: (95) exit")
__msg("processed 9 insns")
__naked void pre_cond_je1(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	if r0 == 3 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is [0..3] post-cond")
__naked void one_backedge_two_exits(void)
{
	asm volatile ("					\
	r6 = 0;						\
1:	call %[bpf_get_prandom_u32];			\
	if r0 == 0 goto 2f;				\
	r6 += 1;					\
	if r6 != 3 goto 1b;				\
2:	r0 = r6;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("scev at header 11: r0=(+ r0 1) / (linear r0 1) r1=(+ r1 2) / (linear r1 2) r2=(+ r6 r1) / ?")
__msg(" scev at latch 16: r0=(+ r0 1) / (linear (+ r0 1) 1) r1=(+ r1 2) / (linear (+ r1 2) 2) r2=(+ r6 r1) / (+ r6 (linear r1 2))")
__msg("      latch at 16: (a5) if r0 < 0x8 goto pc-6")
__msg("loop header at 11, widening r0")
__msg("loop header at 11, widening r1")
__msg("11: R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7)) R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=14,var_off=(0x0; 0xf))")
__msg("loop header at 11, clamping r0")
__msg("loop header at 11, clamping r1")
__msg("11: R0=scalar(smin=umin=smin32=umin32=1,smax=umax=smax32=umax32=7,var_off=(0x0; 0x7)) R1=scalar(smin=umin=smin32=umin32=2,smax=umax=smax32=umax32=14,var_off=(0x0; 0xf))")
__msg("16: safe")
__not_msg("11:")
/* loop exit */
__msg("from 16 to 17: R0=8")
__msg("17: R0=8")
__msg("17: (95) exit")
/* map lookup error path */
__msg("from 7 to 17: R0=0")
__msg("17: R0=0")
__msg("17: (95) exit")
__naked void correlated_regs(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64*)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[map] ll;					\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto 2f;				\
	r6 = r0;					\
	r0 = 0;						\
	r1 = 0;						\
1:	r2 = r6;					\
	r2 += r1;					\
	*(u8 *)(r2 + 0) = 1;				\
	r0 += 1;					\
	r1 += 2;					\
	if r0 < 8 goto 1b;				\
2:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map)
	: __clobber_all);
}

/*
 * k = 0
 * for (i = 0; i < 4; i++):
 *   for (j = 0; j < 4; j++):
 *     k += 1
 *     k <<= 1   // make SCEV construction not possible
 *     k >>= 1
 * map[k] = 1    // make k precise
 */
SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("19: (72) *(u8 *)(r4 +0) = 1           ; R4=map_value(id={{.*}},map=map,ks=4,vs=1024,imm=16)")
__not_msg("19: ")
__msg("processed 106 insns")
__naked void nested_loops_precise_var1(void)
{
	asm volatile ("					\
	*(u64*)(r10 - 8) = 0;				\
	r1 = %[map] ll;					\
	r2 = r10;					\
	r2 += -8;					\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto 3f;				\
	r1 = 0;						\
	r3 = 0;						\
	/* outer loop */				\
1:	r2 = 0;						\
	/* inner loop */				\
2:	r2 += 1;					\
	r3 += 1;					\
	r3 <<= 1;					\
	r3 >>= 1;					\
	if r2 < 4 goto 2b;				\
	r1 += 1;					\
	if r1 < 4 goto 1b;				\
	r4 = r0;					\
	r4 += r3;					\
	*(u8 *)(r4 + 0) = 1;				\
	r0 = 0;						\
3:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(map)
	: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 1 pre-cond")
__naked void pre_cond_jgt(void)
{
	asm volatile ("					\
	r0 = -1;					\
1:	if r0 > 1 goto 2f;				\
	r0 += 1;					\
	goto 1b;					\
2:	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 2 post-cond")
__naked void loop_jslt_latch_post(void)
{
	asm volatile ("					\
	r0 = -2;					\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 1 post-cond")
__naked void loop_jslt_latch_post1(void)
{
	asm volatile ("					\
	r0 = -1;					\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, 0 iterations count")
__naked void loop_jslt_latch_post2(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 s< 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

SEC("xdp")
__success
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("loop header at 1, header_count is 3 post-cond")
__naked void loop_jsle_latch_post(void)
{
	asm volatile ("					\
	r0 = -2;					\
1:	r0 += 1;					\
	if r0 s<= 0 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
