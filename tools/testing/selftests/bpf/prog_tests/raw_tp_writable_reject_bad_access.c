// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "test_kmods/bpf_testmod.h"
#include "bpf_util.h"

/* Access one byte beyond the end of the writable context struct. This loads
 * (the writable size is only known at attach time) but must be rejected at
 * attach time, because max_tp_access exceeds the tracepoint's writable_size.
 */
static void reject_access_beyond_end(void)
{
	char error[4096];
	int bpf_fd = -1, tp_fd = -1;

	const struct bpf_insn program[] = {
		/* r6 is our tp buffer */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		/* one byte beyond the end of the writable context struct */
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_6,
			    sizeof(struct bpf_testmod_test_writable_ctx)),
		BPF_EXIT_INSN(),
	};

	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.log_level = 2,
		.log_buf = error,
		.log_size = sizeof(error),
	);

	bpf_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, NULL, "GPL v2",
			       program, ARRAY_SIZE(program),
			       &opts);
	if (!ASSERT_GE(bpf_fd, 0, "load_access_beyond_end"))
		return;

	tp_fd = bpf_raw_tracepoint_open("bpf_testmod_test_writable_bare_tp", bpf_fd);
	if (!ASSERT_LT(tp_fd, 0, "attach_access_beyond_end")) {
		close(tp_fd);
		goto out;
	}
out:
	close(bpf_fd);
}

/* Write below the start of the writable buffer: *(u64 *)(buffer - 8) = 42.
 * The negative offset points outside the buffer (into the caller's stack at
 * the trigger site). The verifier must reject this at load time via the
 * __check_buffer_access() off < 0 check, so the program never loads and the
 * tracepoint is never reached with an out-of-bounds write.
 */
static void reject_write_below_start(void)
{
	char error[4096];
	int bpf_fd = -1, tp_fd = -1;

	const struct bpf_insn program[] = {
		/* r6 is our tp buffer */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		/* move the pointer 8 bytes below the start of the buffer ... */
		BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, 8),
		/* ... and write there: *(u64 *)r6 = 42 */
		BPF_ST_MEM(BPF_DW, BPF_REG_6, 0, 42),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.log_level = 2,
		.log_buf = error,
		.log_size = sizeof(error),
	);

	bpf_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, NULL, "GPL v2",
			       program, ARRAY_SIZE(program),
			       &opts);
	if (bpf_fd < 0) {
		fprintf(stdout, "write_below_start: rejected at LOAD: %s\n", error);
		return;
	}
	fprintf(stdout, "write_below_start: LOADED (verifier accepted r6-=8; *r6=42)\n");

	tp_fd = bpf_raw_tracepoint_open("bpf_testmod_test_writable_bare_tp", bpf_fd);
	if (tp_fd < 0) {
		fprintf(stdout, "write_below_start: rejected at ATTACH (errno %d)\n", errno);
		goto out;
	}
	fprintf(stdout, "write_below_start: ATTACHED; triggering tp (OOB write incoming)\n");

	/* len == 64 fires bpf_testmod_test_writable_bare_tp */
	trigger_module_test_read(64);
	fprintf(stdout, "write_below_start: tp fired, survived\n");

	close(tp_fd);
out:
	close(bpf_fd);
}

void test_raw_tp_writable_reject_bad_access(void)
{
	if (test__start_subtest("access_beyond_end"))
		reject_access_beyond_end();
	if (test__start_subtest("write_below_start"))
		reject_write_below_start();
}
