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
				      &env->insn_aux_data[i].live_regs_before);

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} test_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

SEC("?socket")
__naked void lv_assign_chain(void)
{
	asm volatile (
		"r0 = 42;"			/* .......... */
		"r1 = r0;"			/* 0......... */
		"r2 = r1;"			/* .1........ */
		"r3 = r2;"			/* ..2....... */
		"r4 = r3;"			/* ...3...... */
		"r5 = r4;"			/* ....4..... */
		"r6 = r5;"			/* .....5.... */
		"r7 = r6;"			/* ......6... */
		"r8 = r7;"			/* .......7.. */
		"r9 = r8;"			/* ........8. */
		"r0 = r9;"			/* .........9 */
		"exit;"				/* 0......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_arithmetics(void)
{
	asm volatile (
		"r1 = 7;"			/* .......... */
		"r1 += 7;"			/* .1........ */
		"r2 = 7;"			/* .......... */
		"r3 = 42;"			/* ..2....... */
		"r2 += r3;"			/* ..23...... */
		"r0 = 0;"			/* .......... */
		"exit;"				/* 0......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_store(void)
{
	asm volatile (
		"r1 = r10;"			/* .......... */
		"r1 += -8;"			/* .1........ */
		"*(u64 *)(r1 +0) = 7;"		/* .1........ */
		"r2 = 42;"			/* .1........ */
		"*(u64 *)(r1 +0) = r2;"		/* .12....... */
		"*(u64 *)(r1 +0) = r2;"		/* .12....... */
		"r0 = 0;"			/* .......... */
		"exit;"				/* 0......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_load(void)
{
	asm volatile (
		"r4 = r10;"			/* .......... */
		"r4 += -8;"			/* ....4..... */
		"r5 = *(u64 *)(r4 +0);"		/* ....4..... */
		"r4 += -8;"			/* ....45.... */
		"r0 = r5;"			/* .....5.... */
		"exit;"				/* 0......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_endian(void)
{
	asm volatile (
		"r2 = *(u32 *)(r1 +0);"		/* .1........ */
		"r2 = le64 r2;"			/* ..2....... */
		"r0 = r2;"			/* ..2....... */
		"exit;"				/* 0......... */
		: :: __clobber_all);
}

SEC("?socket")
__naked void lv_atomic(void)
{
	asm volatile (
		"r2 = r10;"			/* ...345.... */
		"r2 += -8;"			/* ..2345.... */
		"r1 = 0;"			/* ..2345.... */
		"*(u64 *)(r2 +0) = r1;"		/* .12345.... */
		"r1 = %[test_map] ll;"		/* ..2345.... */
		"call %[bpf_map_lookup_elem];"	/* .12345.... */
		"if r0 == 0 goto 1f;"		/* 0......... */
		"r1 = 1;"			/* 0......... */
		"r1 = atomic_fetch_add((u64 *)(r0 +0), r1);" /* 01........ */
		"lock *(u32 *)(r0 +0) += r1;"	/* 01........ */
		"r1 = xchg_64(r0 + 0, r1);"	/* 01........ */
		"r2 = r0;"			/* 01........ */
		"r0 = r1;"			/* .12....... */
		"r0 = cmpxchg_64(r2 + 0, r0, r1);" /* 012....... */
		"1: exit;"			/* 0......... */
		:
		: __imm(bpf_map_lookup_elem),
		  __imm_addr(test_map)
		: __clobber_all);
}

SEC("?socket")
__naked void lv_regular_call(void)
{
	asm volatile (
		"r7 = 1;"			/* ...345.... */
		"r1 = r10;"			/* ...345.7.. */
		"r1 += -8;"			/* .1.345.7.. */
		"*(u8 *)(r1 +0) = 0;"		/* .1.345.7.. */
		"r2 = 1;"			/* .1.345.7.. */
		"call %[bpf_trace_printk];"	/* .12345.7.. */
		"r0 += r7;"			/* 0......7.. */
		"exit;"				/* 0......... */
		:
		: __imm(bpf_trace_printk)
		: __clobber_all);
}

SEC("?socket")
__naked void lv_if1(void)
{
	asm volatile (
		"r0 = 1;"			/* .1........ */
		"r2 = 2;"			/* 01........ */
		"if r1 > 0x7 goto +1;"		/* 012....... */
		"r0 = r2;"			/* ..2....... */
		"exit;"				/* 0......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_if2(void)
{
	asm volatile (
		"r0 = 1;"			/* .1........ */
		"r2 = 2;"			/* 01........ */
		"r3 = 7;"			/* 012....... */
		"if r1 > r3 goto +1;"		/* 0123...... */
		"r0 = r2;"			/* ..2....... */
		"exit;"				/* 0......... */
		::: __clobber_all);
}

SEC("?socket")
__naked void lv_loop(void)
{
	asm volatile (
		"r1 = 0;"			/* .......... */
		"r2 = 7;"			/* .1........ */
		"if r1 > 0x7 goto +4;"		/* .12....... */
		"r1 += 1;"			/* .12....... */
		"r2 *= 2;"			/* .12....... */
		"goto +0;"			/* .12....... */
		"goto -5;"			/* .12....... */
		"r0 = 0;"			/* .......... */
		"exit;"				/* 0......... */
		:
		: __imm(bpf_trace_printk)
		: __clobber_all);
}

#ifdef CAN_USE_GOTOL
SEC("?socket")
__naked void lv_gotol(void)
{
	asm volatile (
		"r2 = 42;"			/* .1........ */
		"r3 = 24;"			/* .12....... */
		"if r1 > 0x7 goto +2;"		/* .123...... */
		"r0 = r2;"			/* ..2....... */
		"gotol +1;"			/* 0......... */
		"r0 = r3;"			/* ...3...... */
		"exit;"				/* 0......... */
		:
		: __imm(bpf_trace_printk)
		: __clobber_all);
}
#endif

SEC("?socket")
__naked void lv_ldimm64(void)
{
	asm volatile (
		"r0 = 0;"			/* .......... */
		"r2 = 0x7 ll;"			/* 0......... */
		"r0 += r2;"			/* 0.2....... */
		"exit;"				/* 0......... */
		:
		:: __clobber_all);
}

/* No rules specific for LD_ABS/LD_IND, default behaviour kicks in */
SEC("?socket")
__naked void lv_ldabs(void)
{
	asm volatile (
		"r6 = r1;"			/* 012345..89 */
		"r7 = 0;"			/* 0123456.89 */
		"r0 = *(u8 *)skb[42];"		/* 0123456789 */
		"r7 += r0;"			/* 012.456789 */
		"r3 = 42;"			/* 012.456789 */
		"r0 = *(u8 *)skb[r3];"		/* 0123456789 */
		"r7 += r0;"			/* 0......7.. */
		"r0 = r7;"			/* .......7.. */
		"exit;"				/* 0......... */
		:
		:: __clobber_all);
}


#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__naked void lv_arena(void)
{
	asm volatile (
		"r1 = %[arena] ll;"		/* .......... */
		"r2 = 0;"			/* .1........ */
		"r3 = 1;"			/* .12....... */
		"r4 = 0;"			/* .123...... */
		"r5 = 0;"			/* .1234..... */
		"call %[bpf_arena_alloc_pages];"  /* .12345.... */
		"r1 = addr_space_cast(r0, 0, 1);" /* 0......... */
		"r2 = 42;"			/* .1........ */
		"*(u64 *)(r1 +0) = r2;"		/* .12....... */
		"r0 = 0;"			/* .......... */
		"exit;"				/* 0......... */
		:
		: __imm(bpf_arena_alloc_pages),
		  __imm_addr(arena)
		: __clobber_all);
}
#endif /* __BPF_FEATURE_ADDR_SPACE_CAST */

/* to retain debug info for BTF generation */
void kfunc_root(void)
{
	bpf_arena_alloc_pages(0, 0, 0, 0, 0);
}

char _license[] SEC("license") = "GPL";
