// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} enter_id SEC(".maps");

#define	IFNAMSIZ 16

int ifindex, ingress_ifindex;
char name[IFNAMSIZ];
unsigned int inum;
unsigned int meta_len, frag0_len, kskb_len, kskb2_len;

SEC("?xdp")
int md_xdp(struct xdp_md *ctx)
{
	struct xdp_buff *kctx = bpf_cast_to_kern_ctx(ctx);
	struct net_device *dev;

	dev = kctx->rxq->dev;
	ifindex = dev->ifindex;
	inum = dev->nd_net.net->ns.inum;
	__builtin_memcpy(name, dev->name, IFNAMSIZ);
	ingress_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}

SEC("?tc")
int md_skb(struct __sk_buff *skb)
{
	struct sk_buff *kskb = bpf_cast_to_kern_ctx(skb);
	struct skb_shared_info *shared_info;
	struct sk_buff *kskb2;

	kskb_len = kskb->len;

	/* Simulate the following kernel macro:
	 *   #define skb_shinfo(SKB) ((struct skb_shared_info *)(skb_end_pointer(SKB)))
	 */
	shared_info = bpf_core_cast(kskb->head + kskb->end, struct skb_shared_info);
	meta_len = shared_info->meta_len;
	frag0_len = shared_info->frag_list->len;

	/* kskb2 should be equal to kskb */
	kskb2 = bpf_core_cast(kskb, typeof(*kskb2));
	kskb2_len = kskb2->len;
	return 0;
}

SEC("?tp_btf/sys_enter")
int BPF_PROG(untrusted_ptr, struct pt_regs *regs, long id)
{
	struct task_struct *task, *task_dup;

	task = bpf_get_current_task_btf();
	task_dup = bpf_core_cast(task, struct task_struct);
	(void)bpf_task_storage_get(&enter_id, task_dup, 0, 0);
	return 0;
}

SEC("?tracepoint/syscalls/sys_enter_nanosleep")
int kctx_u64(void *ctx)
{
	u64 *kctx = bpf_core_cast(ctx, u64);

	(void)kctx;
	return 0;
}

long ZERO = 0, ONE = 1, MINUS_ONE = -1;
int my_pid;

char filename_glob[32];
int filename_glob_match;

#define E2BIG 7
#define EINVAL 22

/* Non-recursive glob matching logic, adapted from:
 *
 * https://github.com/torvalds/linux/blob/master/lib/glob.c
 */
__noinline __weak int glob_match(const void *pat_addr, const void *str_addr)
{
	const char *pat = bpf_rdonly_cast((void *)pat_addr, 0);
	const char *str = bpf_rdonly_cast((void *)pat_addr, 0);
	ssize_t backtrack_pi = MINUS_ONE, backtrack_si = MINUS_ONE;
	size_t pi = ZERO, si = ZERO;

	bpf_repeat(1000000) {
		unsigned char p = pat[pi];
		unsigned char s = str[si];

		pi += ONE;
		si += ONE;

		switch (p) {
		case '?':
			/* single char wildcard matches anything but zero terminator */
			if (s == '\0')
				return 0; /* no match */
			break;
		case '*':
			/* any-length widlcard, matched lazily (the least amount
			 * of characters that is enough to satisfy the
			 * pattern), which permits never needing to backtrack
			 * more than one level (though it's not that obvious)
			 */
			if (pat[pi] == '\0')
				return 1; /* match: trailing '*' matches anything */
			backtrack_pi = pi;
			backtrack_si = si - ONE; /* allow zero-length match */
			si -= ONE; /* "unconsume" last string character */
			break;
		default:
			if (p == '\\') {
				p = pat[pi];
				pi += ONE;
			}
			/* literal character match */
			if (p == s) {
				if (p == '\0')
					return 1; /* full match */
				break;
			}

			if (s == '\0' || backtrack_pi < 0)
				return 0; /* no match and no backtracking left */

			/* backtrack to last * wildcard and consume one character */
			backtrack_si += ONE;
			pi = backtrack_pi;
			si = backtrack_si;
			break;
		}
	}

	return -E2BIG;
}

SEC("?tp_btf/sys_enter")
int BPF_PROG(mem_cast_glob)
{
	const struct task_struct *task;
	const char *filename;

	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	task = bpf_get_current_task_btf();

	filename = (void *)task->mm->exe_file->f_path.dentry->d_name.name;
	filename_glob_match = glob_match(filename_glob, filename);
	bpf_printk("FILENAME = '%s' MATCH=%d", filename, filename_glob_match);

	return 0;
}

char btf_type_name[32];
int btf_type_id;

#define BTF_INFO_KIND(info) (((info) >> 24) & 0x1f)
#define BTF_INFO_VLEN(info) ((info) & 0xffff)

static int btf_type_size(const struct btf_type *t)
{
	const int base_size = sizeof(struct btf_type);
	u32 vlen = BTF_INFO_VLEN(t->info);
	u32 kind = BTF_INFO_KIND(t->info);

	switch (kind) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(__u32);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ENUM64:
		return base_size + vlen * sizeof(struct btf_enum64);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	case BTF_KIND_VAR:
		return base_size + sizeof(struct btf_var);
	case BTF_KIND_DATASEC:
		return base_size + vlen * sizeof(struct btf_var_secinfo);
	case BTF_KIND_DECL_TAG:
		return base_size + sizeof(struct btf_decl_tag);
	default:
		return -EINVAL;
	}
}

extern void __start_BTF __ksym __weak;

SEC("?raw_tp/sys_enter")
int BPF_PROG(mem_cast_btf)
{
	if ((bpf_get_current_pid_tgid() >> 32) != my_pid)
		return 0;

	struct btf_header *hdr = bpf_rdonly_cast(&__start_BTF, 0);
	const void *types = (void *)hdr + hdr->hdr_len + hdr->type_off;
	const char *strings = (void *)hdr + hdr->hdr_len + hdr->str_off;

	const struct btf_type *t = (void *)types;
	int i = 0;
	bpf_for(i, 1, 1000000) {
		int sz = btf_type_size(t);
		if (sz < 0)
			return 1;

		if (i == btf_type_id)
			break;

		t = (void *)t + sz;
	}

	bpf_printk("TYPE ID %d NAME '%s'", i, strings + t->name_off);

	__builtin_memcpy(btf_type_name, strings + t->name_off, sizeof(btf_type_name));

	return 0;
}

char _license[] SEC("license") = "GPL";
