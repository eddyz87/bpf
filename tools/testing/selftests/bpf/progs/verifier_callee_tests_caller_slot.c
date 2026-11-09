// SPDX-License-Identifier: GPL-2.0
/*
 * A bpf_loop() callback appends names to a buffer in an 8192-byte map value. Its context is a
 * struct on the stack of the caller: the object the names are read from, the buffer and the number
 * of bytes used so far (len). The callback loads len and returns if a 256-byte name would not fit,
 * reads the name pointer with a helper call, then loads len again to form the destination buf + len
 * of bpf_probe_read_kernel_str(): after a call clang reloads the fields of *ctx. That is safe: on
 * every path to the second load len is at most 8192 - 256.
 *
 * The verifier runs the callback until the state at the bpf_loop() call stops changing. Every
 * iteration adds 0..256 to len; after a few the slot (fp-8 of the caller, +16 from the context
 * pointer that the callback keeps in r6) is widened to [0, 0x7fffffff]. In the callback the jump
 * bounds the loaded register, the slot stays as it is and the second load gets the widened range:
 *
 *	from 44 to 19: widened
 *	24: (79) r1 = *(u64 *)(r6 +16)
 *	    ; R1=scalar(smin=smin32=0,smax=umax=umax32=0x7fffffff,var_off=(0x0; 0x7fffffff))
 *	25: (25) if r1 > 0x1f00 goto pc+17
 *	    ; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=7936,var_off=(0x0; 0x1fff))
 *	30: (85) call bpf_probe_read_kernel#113
 *	32: (79) r2 = *(u64 *)(r6 +16)
 *	    ; R2=scalar(smin=smin32=0,smax=umax=umax32=0x7fffffff,var_off=(0x0; 0x7fffffff))
 *	34: (0f) r1 += r2
 *	    ; R1=map_value(map=buf_map,ks=4,vs=8192,smin=smin32=0,smax=umax=umax32=0x7fffffff,...)
 *	37: (85) call bpf_probe_read_kernel_str#115
 *	R1 unbounded memory access, make sure to bounds check any such access
 *
 * A conditional jump refines the registers and stack slots of its own frame that scalar evolution
 * links to the tested register, and scalar evolution knows a stack slot only through r10: a load
 * through r6 is a value of its own, so neither the slot in the frame of the caller nor the second
 * load is linked to r1. Scalar ids used to link the slot and the register at the fill, in any
 * frame, and sync_linked_regs() refined the slot together with the register.
 *
 * The callback as compiled (insns 22-44 of the program; insns 0-21 look the map value up, set
 * len = 0 at fp-8 and call bpf_loop(32, callback, fp-24, 0)):
 *	22: r6 = r2
 *	23: r7 = 0x1
 *	24: r1 = *(u64 *)(r6 + 0x10)      <- len
 *	25: if r1 > 0x1f00 goto 43        <- return 1 if a name would not fit: bounds r1 only
 *	26: r3 = *(u64 *)(r6 + 0x0)
 *	27: r1 = r10
 *	28: r1 += -0x8
 *	29: w2 = 0x8
 *	30: call bpf_probe_read_kernel    <- the name pointer; clang reloads *ctx after the call
 *	31: if r0 != 0x0 goto 43
 *	32: r2 = *(u64 *)(r6 + 0x10)      <- len again, not refined
 *	33: r1 = *(u64 *)(r6 + 0x8)       <- buf
 *	34: r1 += r2
 *	35: r3 = *(u64 *)(r10 - 0x8)
 *	36: w2 = 0x100
 *	37: call bpf_probe_read_kernel_str <- rejected: len is up to 0x7fffffff here
 *	38: if r0 s< 0x0 goto 43
 *	39: r1 = *(u64 *)(r6 + 0x10)
 *	40: r1 += r0
 *	41: *(u64 *)(r6 + 0x10) = r1      <- len += n
 *	42: r7 = 0x0
 *	43: r0 = r7
 *	44: exit
 * The test depends on the bound being checked on a copy of len loaded from the frame of the caller
 * and on the call between the check and the second load, which makes clang load len again instead
 * of reusing the tested register.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define BUF_SIZE 8192
#define NAME_MAX 256

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[BUF_SIZE]);
} buf_map SEC(".maps");

struct path_ctx {
	const void *node;	/* the object the names are read from */
	char *buf;		/* BUF_SIZE bytes of map value */
	__u64 len;		/* bytes of buf used so far */
};

static long append_name(__u32 index, void *data)
{
	struct path_ctx *ctx = data;
	const char *name;
	long n;

	if (ctx->len > BUF_SIZE - NAME_MAX)
		return 1;
	/* A call between the check and the use: clang loads ctx->len again after it. */
	if (bpf_probe_read_kernel(&name, sizeof(name), ctx->node))
		return 1;
	n = bpf_probe_read_kernel_str(ctx->buf + ctx->len, NAME_MAX, name);
	if (n < 0)
		return 1;
	ctx->len += n;
	return 0;
}

SEC("socket")
__success
int len_in_callers_frame(void *ctx)
{
	struct path_ctx path;
	__u32 key = 0;

	path.buf = bpf_map_lookup_elem(&buf_map, &key);
	if (!path.buf)
		return 0;
	path.node = (void *)bpf_get_current_task();
	path.len = 0;
	bpf_loop(32, append_name, &path, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
