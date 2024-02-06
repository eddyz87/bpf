// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "arena_simple.skel.h"
#include "arena_simple_common.h"

static void test_kernel_to_user(void)
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
	ASSERT_EQ(shared->val, 42, "shared->val");
	ASSERT_EQ(*shared->ptr, 42, "shared->ptr");
	ASSERT_EQ(**shared->pptr, 42, "shared->pptr");
	arena_simple__destroy(skel);
}

static void test_user_to_kernel(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_simple *skel;
	struct data *shared;
	int ret, prog_fd;

	skel = arena_simple__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	prog_fd = bpf_program__fd(skel->progs.user_to_kernel);
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts #1");
	ASSERT_EQ(opts.retval, 0, "opts.retval");
	shared = skel->bss->shared;
	shared->val = 7;
	shared->ptr = &shared->val;
	shared->pptr = &shared->ptr;
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts #2");
	ASSERT_EQ(opts.retval, 21, "opts.retval");
	shared->val = 8;
	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts #3");
	ASSERT_EQ(opts.retval, 24, "opts.retval");
	arena_simple__destroy(skel);
}

void test_arena_simple(void)
{
	if (test__start_subtest("kernel_to_user"))
		test_kernel_to_user();
	if (test__start_subtest("user_to_kernel"))
		test_user_to_kernel();
}
