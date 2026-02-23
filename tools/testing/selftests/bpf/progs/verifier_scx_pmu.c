#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

__u64 arr[2];

SEC("raw_tp")
__flag(BPF_F_TEST_REG_INVARIANTS)
/*
 * __msg("verifier bug: REG INVARIANTS VIOLATION (false_reg1): "
 *       "range bounds violation u64=[0x0, 0x1] s64=[0x0, 0x1] u32=[0x3, 0x1] s32=[0x0, 0x1] "
 *       "var_off=(0x0, 0x1)")
 * __failure
 */
int test_alloc_free_cpumask(const __u64 *ctx)
{
	int i;

	bpf_for(i, 0, 3) {}
	if (i < 0 || i >= 2)
		return -3;
	if (i)
		return 42;
	return 0;
}
