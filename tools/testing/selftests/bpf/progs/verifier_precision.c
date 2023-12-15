// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 SUSE LLC */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("?raw_tp")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0xfffffff8 goto pc+2")
__msg("mark_precise: frame0: regs=r2 stack= before 1: (87) r2 = -r2")
__msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 8")
__naked int bpf_neg(void)
{
	asm volatile (
		"r2 = 8;"
		"r2 = -r2;"
		"if r2 != -8 goto 1f;"
		"r1 = r10;"
		"r1 += r2;"
	"1:"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

SEC("?raw_tp")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2")
__msg("mark_precise: frame0: regs=r2 stack= before 1: (d4) r2 = le16 r2")
__msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0")
__naked int bpf_end_to_le(void)
{
	asm volatile (
		"r2 = 0;"
		"r2 = le16 r2;"
		"if r2 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += r2;"
	"1:"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}


SEC("?raw_tp")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2")
__msg("mark_precise: frame0: regs=r2 stack= before 1: (dc) r2 = be16 r2")
__msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0")
__naked int bpf_end_to_be(void)
{
	asm volatile (
		"r2 = 0;"
		"r2 = be16 r2;"
		"if r2 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += r2;"
	"1:"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

#if (defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) || \
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) || \
	defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_s390)) && \
	__clang_major__ >= 18

SEC("?raw_tp")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (55) if r2 != 0x0 goto pc+2")
__msg("mark_precise: frame0: regs=r2 stack= before 1: (d7) r2 = bswap16 r2")
__msg("mark_precise: frame0: regs=r2 stack= before 0: (b7) r2 = 0")
__naked int bpf_end_bswap(void)
{
	asm volatile (
		"r2 = 0;"
		"r2 = bswap16 r2;"
		"if r2 != 0 goto 1f;"
		"r1 = r10;"
		"r1 += r2;"
	"1:"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

#endif /* v4 instruction */

SEC("?raw_tp")
__success __log_level(2)
/*
 * Without the bug fix there will be no history between "last_idx 3 first_idx 3"
 * and "parent state regs=" lines. "R0_w=6" parts are here to help anchor
 * expected log messages to the one specific mark_chain_precision operation.
 *
 * This is quite fragile: if verifier checkpointing heuristic changes, this
 * might need adjusting.
 */
__msg("2: (07) r0 += 1                       ; R0_w=6")
__msg("3: (35) if r0 >= 0xa goto pc+1")
__msg("mark_precise: frame0: last_idx 3 first_idx 3 subseq_idx -1")
__msg("mark_precise: frame0: regs=r0 stack= before 2: (07) r0 += 1")
__msg("mark_precise: frame0: regs=r0 stack= before 1: (07) r0 += 1")
__msg("mark_precise: frame0: regs=r0 stack= before 4: (05) goto pc-4")
__msg("mark_precise: frame0: regs=r0 stack= before 3: (35) if r0 >= 0xa goto pc+1")
__msg("mark_precise: frame0: parent state regs= stack=:  R0_rw=P4")
__msg("3: R0_w=6")
__naked int state_loop_first_last_equal(void)
{
	asm volatile (
		"r0 = 0;"
	"l0_%=:"
		"r0 += 1;"
		"r0 += 1;"
		/* every few iterations we'll have a checkpoint here with
		 * first_idx == last_idx, potentially confusing precision
		 * backtracking logic
		 */
		"if r0 >= 10 goto l1_%=;"	/* checkpoint + mark_precise */
		"goto l0_%=;"
	"l1_%=:"
		"exit;"
		::: __clobber_common
	);
}

SEC("socket")
__failure
__flag(BPF_F_TEST_STATE_FREQ)
__msg("8: (37) r0 /= 0")
__msg("div by zero")
__naked void middle_state_breaks_id_link(void)
{
	asm volatile (
	"   call %[bpf_get_prandom_u32];\n"
	"   r7 = r0;\n"
	"   r8 = r0;\n"
	"   call %[bpf_get_prandom_u32];\n"
	"   if r0 > 1 goto +0;\n"
	"   if r8 >= r0 goto 1f;\n"
	"   r8 += r8;\n"
	"   if r7 == 0 goto 1f;\n"
	"   r0 /= 0;\n"
	"1: r0 = 42;\n"
	"   exit;\n"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#include "../../../include/linux/filter.h"

SEC("socket")
__success __log_level(2)
__msg("30: (18) r0 = 0x4")
__naked void pruning_test(void)
{
	asm volatile (
	/*  0 */ "r2 = 0x1a000000be ll;\n"
	/*  2 */ "r5 = r1;\n"
	/*  3 */ "r8 = r2;\n"
	/*  4 */ "w4 = w5;\n"
	/*  5 */ "call %[bpf_get_prandom_u32];\n"
	/*  6 */ "if w8 >= 0x69 goto +1;\n"
	/*  7 */ "exit;\n"
	/*  8 */ "r4 = 0x52 ll;\n"
	/* 10 */ "w4 = -w4;\n"
	/* 11 */ ".8byte %[r0_jset];\n"	/* if r0 & 0xfffffffe goto pc+3; */
	/* 12 */ "r8 -= r4;\n"
	/* 13 */ "r0 += r0;\n"
	/* 14 */ "r4 *= r4;\n"
	/* 15 */ "r3 = 0x1f00000034 ll;\n"
	/* 17 */ "w4 s>>= 29;\n"
	/* 18 */ "if w8 != 0xf goto +3;\n"
	/* 19 */ ".8byte %[bswap32_r3];\n" /* bswap32 r3; */
	/* 20 */ "r2 = 0x1c ll;\n"
	/* 22 */ "r4 <<= 2;\n"
	/* 23 */ "r5 = r8;\n"
	/* 24 */ "r2 = 0x4 ll;\n"
	/* 26 */ "if w8 s>= w0 goto +5;\n"
	/* 27 */ "r8 |= r8;\n"
	/* 28 */ "r8 += r8;\n"
	/* 29 */ "if w5 s<= 0x1d goto +2;\n"
	/* 30 */ "r0 = 0x4 ll;\n"
	/* 32 */ "exit;\n"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_insn(r0_jset, BPF_JMP_IMM(BPF_JSET, BPF_REG_0, 0xfffffffe, 3)),
	  __imm_insn(bswap32_r3, BPF_RAW_INSN(BPF_ALU64 | BPF_TO_LE | BPF_END,
					      BPF_REG_3, 0, 0, 32))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
