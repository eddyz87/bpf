// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "arena_simple.skel.h"
#include "arena_simple_common.h"

void test_arena_simple(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_simple *skel;
	struct data *shared;
	int ret, prog_fd;

	skel = arena_simple__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	prog_fd = bpf_program__fd(skel->progs.kernel_to_user);
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts");
	shared = skel->bss->shared;
	if (!ASSERT_OK_PTR(shared, "skel->bss->shared"))
		goto out;
	ASSERT_EQ(shared->val, 42, "shared->val");

out:
	arena_simple__destroy(skel);
}
