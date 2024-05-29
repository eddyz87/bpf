// SPDX-License-Identifier: GPL-2.0

#include "test_progs.h"
#include "disasm_helpers.h"
#include "patch_nocsr.skel.h"

static const char *expected_program_text =
	"*(u64 *)(r10 -8) = 5\n"
	"r1 = 7\n"
	"r2 = 35\n"
	"*(u64 *)(r10 -16) = r1\n"
	"*(u64 *)(r10 -24) = r2\n"
	/* At the moment program is disassembled,
	 * helpers are areplaced by addresses.
	 */
	"call unknown\n"
	"r1 = *(u64 *)(r10 -16)\n"
	"r2 = *(u64 *)(r10 -24)\n"
	"r3 = r1\n"
	"r3 += r2\n"
	"*(u64 *)(r10 -16) = r3\n"
	"call unknown\n"
	"r3 = *(u64 *)(r10 -16)\n"
	"r0 = r3\n"
	"exit\n";

char *get_xlated_program_text(int prog_fd)
{
	struct bpf_insn *insns = NULL;
	__u32 insns_cnt = 0, i;
	size_t text_sz = 0;
	char *text = NULL;
	char buf[64];
	FILE *out;
	int err;

	err = get_xlated_program(prog_fd, &insns, &insns_cnt);
	if (!ASSERT_OK(err, "get_xlated_program"))
		goto out;
	out = open_memstream(&text, &text_sz);
	if (!ASSERT_OK_PTR(out, "open_memstream"))
		goto out;
	for (i = 0; i < insns_cnt;) {
		i += disasm_insn(insns + i, buf, sizeof(buf));
		fprintf(out, "%s\n", buf);
	}
	fflush(out);

out:
	free(insns);
	fclose(out);
	if (err) {
		free(text);
		errno = err;
	}
	return text;
}

/* The goal of this test is to check that verifier adds register
 * spills/fills around the call to a helper, when helper is marked as
 * no_caller_saved_registers and is not jited.
 *
 * For this:
 * - use kprobe to override return value of the
 *   verifier.c:bpf_jit_inlines_helper_call() to force verifier never
 *   inline helpers;
 * - load a test program with nocsr helper calls and check that verifier
 *   rewrites it in the expected way.
 *
 * See progs/patch_nocsr.c for the code of both kprobe and test program.
 */
void serial_test_patch_nocsr(void)
{
	/* Use 'test_skel' to load test program,
	 * use 'skel' to load kprobe.
	 */
	struct patch_nocsr *test_skel = NULL;
	struct patch_nocsr *skel = NULL;
	struct bpf_program *prog = NULL;
	char *text = NULL;
	int err;

	skel = patch_nocsr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel = patch_nocsr__open_and_load"))
		goto out;
	err = patch_nocsr__attach(skel);
	if (!ASSERT_OK(err, "patch_nocsr__attach(skel)"))
		goto out;
	/* at this point kprobe is installed, time to load test program */
	test_skel = patch_nocsr__open();
	if (!ASSERT_OK_PTR(skel, "test_skel = patch_nocsr__open"))
		goto out;
	/* both kprobe and test program share object file,
	 * make sure kprobe is loaded.
	 */
	bpf_object__for_each_program(prog, test_skel->obj)
		bpf_program__set_autoload(prog, false);
	prog = test_skel->progs.get_current_task_no_csr_patched;
	bpf_program__set_autoload(prog, true);
	err = patch_nocsr__load(test_skel);
	if (!ASSERT_OK(err, "patch_nocsr__load(test_skel)"))
		goto out;
	/* get the program after verifier rewrites and compare it
	 * to the expected program form.
	 */
	text = get_xlated_program_text(bpf_program__fd(prog));
	if (!ASSERT_OK_PTR(text, "get_xlated_program_text"))
		goto out;
	if (env.verbosity >= VERBOSE_SUPER)
		printf("xlated program:\n%s", text);
	diff_assert_streq(expected_program_text, text, "patch_nocsr");
	/* also run the program and check return value,
	 * just because we can
	 */
	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &run_opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		goto out;
	ASSERT_EQ(run_opts.retval, 42, "program retval");

out:
	free(text);
	if (skel)
		patch_nocsr__detach(skel);
	patch_nocsr__destroy(test_skel);
	patch_nocsr__destroy(skel);
}
