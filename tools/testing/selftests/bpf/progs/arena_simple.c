// SPDX-License-Identifier: GPL-2.0
#include "bpf_experimental.h"
#include "arena_simple_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
	__uint(map_extra, 2ull << 44);
} my_arena SEC(".maps");

struct data __arena *shared;

/* Uncomment the line below to trigger bug */
int __arena * __arena bar;

SEC("syscall")
int kernel_to_user(void *ctx)
{
	shared = bpf_arena_alloc_pages(&my_arena, NULL, 1, -1, 0);
	shared->val = 42;
	return 0;
}

char _license[] SEC("license") = "GPL";
