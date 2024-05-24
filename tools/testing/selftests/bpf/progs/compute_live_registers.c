// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Results of bpf_compute_live_registers() are not currently available
 * in the program verification log.
 * Make these results available to selftests by capturing return from
 * bpf_compute_live_registers() and copying computed live registers to
 * the 'log_map', where these results could be examined by a
 * prog_tests/compute_live_registers.c.
 *
 * This file contains the following programs:
 * - fexit tracing program 'liveness_logger', which is responsible for
 *   maintaining of 'log_map';
 * - programs with name strating from 'lv_' are actual test cases for
 *   liveness analysis, comments in the assembly code denote expected
 *   analysis results.
 */

#define MAX_INSN	128
#define NAME_LEN	16

struct log_entry {
	__u32 prog_len;
	struct bpf_insn insns[MAX_INSN];
	__u16 live_regs[MAX_INSN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, char[NAME_LEN]);
	__type(value, struct log_entry);
} log_map SEC(".maps");

char zero_entry[sizeof(struct log_entry)] = {};

static inline u32 min_u32(u32 a, u32 b)
{
	return a <= b ? a : b;
}

SEC("fexit/bpf_compute_live_registers")
int BPF_PROG(liveness_logger, struct bpf_verifier_env *env, int ret)
{
	struct log_entry *entry;
	char name[NAME_LEN] = {};
	int err, i;
	__u32 len;

	// TODO: thread ID guard

	len = min_u32(sizeof(env->prog->aux->name), NAME_LEN);
	err = bpf_probe_read_kernel_str(name, len, env->prog->aux->name);
	if (err < 0) {
		bpf_printk("livness_logger '%s': can't copy name err=%d",
			   env->prog->aux->name, err);
		return 0;
	}
	if (bpf_strncmp(name, 3, "lv_") != 0)
		return 0;
	err = bpf_map_update_elem(&log_map, name, &zero_entry, BPF_ANY);
	if (err) {
		bpf_printk("livness_logger '%s': failed to allocate new map entry", name);
		return 0;
	}
	entry = bpf_map_lookup_elem(&log_map, name);
	if (!entry) {
		bpf_printk("livness_logger '%s': failed to lookup fresh new map entry", name);
		return 0;
	}
	entry->prog_len = env->prog->len;
	len = min_u32(env->prog->len, MAX_INSN);
	bpf_probe_read_kernel(entry->insns, len * sizeof(*entry->insns), env->prog->insnsi);
	for (i = 0; i < len; ++i)
		bpf_probe_read_kernel(&entry->live_regs[i], sizeof(*entry->live_regs),
				      &env->insn_aux_data[i].live_regs);

	return 0;
}

SEC("?socket")
__naked void lv_assign_chain(void)
{
	asm volatile (
		"r0 = 42;"			/* 0......... */
		"r1 = r0;"			/* .1........ */
		"r2 = r1;"			/* ..2....... */
		"r3 = r2;"			/* ...3...... */
		"r4 = r3;"			/* ....4..... */
		"r5 = r4;"			/* .....5.... */
		"r6 = r5;"			/* ......6... */
		"r7 = r6;"			/* .......7.. */
		"r8 = r7;"			/* ........8. */
		"r9 = r8;"			/* .........9 */
		"r0 = r9;"			/* 0......... */
		"exit;"				/* .......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_arithmetics(void)
{
	asm volatile (
		"r1 = 7;"			/* .1........ */
		"r1 += 7;"			/* .......... */
		"r2 = 7;"			/* ..2....... */
		"r3 = 42;"			/* ..23...... */
		"r2 += r3;"			/* .......... */
		"r0 = 0;"			/* 0......... */
		"exit;"				/* .......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_store(void)
{
	asm volatile (
		"r1 = r10;"			/* .1........ */
		"r1 += -8;"			/* .1........ */
		"*(u64 *)(r1 +0) = 7;"		/* .1........ */
		"r2 = 42;"			/* .12....... */
		"*(u64 *)(r1 +0) = r2;"		/* .12....... */
		"*(u64 *)(r1 +0) = r2;"		/* .......... */
		"r0 = 0;"			/* 0......... */
		"exit;"				/* .......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_load(void)
{
	asm volatile (
		"r4 = r10;"			/* ....4..... */
		"r4 += -8;"			/* ....4..... */
		"r5 = *(u64 *)(r4 +0);"		/* ....45.... */
		"r4 += -8;"			/* .....5.... */
		"r0 = r5;"			/* 0......... */
		"exit;"				/* .......... */
		: :: __clobber_all);
}

// TODO: atomics

SEC("?socket")
__naked void lv_nocsr_call(void)
{
	asm volatile (
		"r1 = 42;"			/* .1........ */
		"call %[bpf_get_current_task];"	/* .1........ */
		"r0 = r1;"			/* 0......... */
		"exit;"				/* .......... */
		:
		: __imm(bpf_get_current_task)
		: __clobber_all);
}

SEC("?socket")
__naked void lv_regular_call(void)
{
	asm volatile (
		"r7 = 1;"			/* ...345.7.. */
		"r1 = r10;"			/* .1.345.7.. */
		"r1 += -8;"			/* .1.345.7.. */
		"*(u8 *)(r1 +0) = 0;"		/* .1.345.7.. */
		"r2 = 1;"			/* .12345.7.. */
		"call %[bpf_trace_printk];"	/* 0......7.. */
		"r0 += r7;"			/* 0......... */
		"exit;"				/* .......... */
		:
		: __imm(bpf_trace_printk)
		: __clobber_all);
}

SEC("?socket")
__naked void lv_if1(void)
{
	asm volatile (
		"r0 = 1;"			/* 01........ */
		"r2 = 2;"			/* 012....... */
		"if r1 > 0x7 goto +1;"		/* 0.2....... */
		"r0 = r2;"			/* 0......... */
		"exit;"				/* .......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_if2(void)
{
	asm volatile (
		"r0 = 1;"			/* 01........ */
		"r2 = 2;"			/* 012....... */
		"r3 = 7;"			/* 0123...... */
		"if r1 > r3 goto +1;"		/* 0.2....... */
		"r0 = r2;"			/* 0......... */
		"exit;"				/* .......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_loop(void)
{
	asm volatile (
		"r1 = 0;"			/* .1........ */
		"r2 = 7;"			/* .12....... */
		"if r1 > 0x7 goto +4;"		/* .12....... */
		"r1 += 1;"			/* .12....... */
		"r2 *= 2;"			/* .12....... */
		"goto +0;"			/* .12....... */
		"goto -5;"			/* .12....... */
		"r0 = 0;"			/* 0......... */
		"exit;"				/* .......... */
		:
		: __imm(bpf_trace_printk)
		: __clobber_all);
}

// TODO: control flow:
// - gotol

char _license[] SEC("license") = "GPL";
