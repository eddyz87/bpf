// SPDX-License-Identifier: GPL-2.0
#include "bpf_experimental.h"
#include "arena_simple_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1u << 24); /* max_entries * value_size == size of mmap() region */
	__uint(map_extra, 2ull << 44); /* start of mmap() region */
	__type(key, __u64);
	__type(value, __u64);
} arena SEC(".maps");

struct data __arena *shared;

SEC("syscall")
int kernel_to_user(void *ctx)
{
	shared = bpf_arena_alloc_pages(&arena, 1, -1, 0);
	shared->val = 42;
	shared->ptr = &shared->val;
	shared->pptr = &shared->ptr;
	return 0;
}

SEC("syscall")
int user_to_kernel(void *ctx)
{
	if (!shared) {
		shared = bpf_arena_alloc_pages(&arena, 1, -1, 0);
		return 0;
	}
	bpf_printk("=================================", shared);
	bpf_printk("shared         = %px", (void *)shared);
	bpf_printk("shared->ptr    = %px", (void *)shared->ptr);
	bpf_printk("shared->pptr   = %px", (void *)shared->pptr);
	bpf_printk("---------------------------------");
	bpf_printk("shared->val    = %d", shared->val);
	bpf_printk("*shared->ptr   = %d", *shared->ptr);
	bpf_printk("**shared->pptr = %d", **shared->pptr);
	bpf_printk("=================================", shared);
	return shared->val + *shared->ptr + **shared->pptr;
}

char _license[] SEC("license") = "GPL";
