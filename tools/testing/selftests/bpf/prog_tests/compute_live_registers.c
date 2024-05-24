// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>

#include "bpf/libbpf.h"
#include "compute_live_registers.skel.h"
#include "test_progs.h"
#include "disasm_helpers.h"

#define MAX_TEST_CASES	64
#define MAX_INSN	128
#define NAME_LEN	16

struct log_entry {
	__u32 prog_len;
	struct bpf_insn insns[MAX_INSN];
	__u16 live_regs[MAX_INSN];
};

static void normalize_insn_str(char *buf)
{
	char *p;

	/* goto pc+3 -> goto +3 */
	while ((p = strstr(buf, " pc+")) || (p = strstr(buf, " pc-"))) {
		++p;
		memmove(p, p + 2, strlen(buf) - (p - buf) - 1);
	}
	/* r2 = 0x7 ll -> r2 = 0x7 */
	while ((p = strstr(buf, " ll"))) {
		memmove(p, p + 3, strlen(buf) - (p + 3 - buf));
	}
}

static void print_log_entry(FILE *f, struct log_entry *e)
{
	struct bpf_insn *insn, *end;
	char buf[64];
	int i;

	insn = e->insns;
	end = insn + e->prog_len;
	while (insn < end) {
		i = insn - e->insns;
		for (int r = 0; r < 10; ++r) {
			if (e->live_regs[i] & (1u << r))
				fprintf(f, "%d", r);
			else
				fprintf(f, ".");
		}
		insn = disasm_insn(&e->insns[i], buf, sizeof(buf));
		normalize_insn_str(buf);
		fprintf(f, " %s\n", buf);
	}
}

struct test_case {
	char name[NAME_LEN];
	size_t text_sz;
	char *text;
};

static struct test_case cases[MAX_TEST_CASES];
static int cases_num;

static void free_test_cases(void)
{
	while (cases_num > 0) {
		--cases_num;
		free(cases[cases_num].text);
		bzero(&cases[cases_num], sizeof(*cases));
	}
}

static int read_test_cases(const char *path)
{
	struct test_case *tc;
	char comment[64] = {};
	char insn[64] = {};
	char name[17] = {};
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	FILE *f = NULL;
	FILE *c = NULL;

	f = fopen(path, "r");
	if (!ASSERT_OK_PTR(f, "fopen test cases"))
		return -errno;
	while ((nread = getline(&line, &len, f)) != -1) {
		if (sscanf(line, "__naked void %16[0-9a-z_]", name) == 1) {
			if (c)
				fclose(c);
			if (!ASSERT_TRUE(cases_num < MAX_TEST_CASES, "max test cases"))
				break;
			tc = &cases[cases_num++];
			strcpy(tc->name, name);
			c = open_memstream(&tc->text, &tc->text_sz);
			continue;
		}
		normalize_insn_str(line);
		if (sscanf(line, " \"call %%[%63[^]]];\" /* %63[0-9.] */", insn, comment) == 2) {
			if (!c)
				continue;
			fprintf(c, "%-10s call %s\n", comment, insn);
		} else if (sscanf(line, " \"%63[^;];\" /* %63[0-9.] */", insn, comment) == 2) {
			if (!c)
				continue;
			fprintf(c, "%-10s %s\n", comment, insn);
		}
	}
	if (c)
		fclose(c);
	free(line);
	fclose(f);
	return 0;
}

static void do_one_test(struct test_case *tc)
{
	struct compute_live_registers *probe = NULL;
	struct compute_live_registers *skel = NULL;
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_program *prog = NULL;
	struct log_entry log_entry;
	__u32 log_sz = 1024 * 1024;
	char *log = NULL;
	size_t result_text_sz = 0;
	char *result_text = NULL;
	FILE *f = NULL;
	int err;

	if (env.verbosity >= VERBOSE_SUPER) {
		log = malloc(log_sz);
		if (!ASSERT_OK_PTR(log, "log = malloc"))
			goto out;
		opts.kernel_log_buf = log;
		opts.kernel_log_size = log_sz;
		opts.kernel_log_level = 1 | 2 | 4;
	}

	probe = compute_live_registers__open_and_load();
	if (!ASSERT_OK_PTR(probe, "probe = compute_live_registers__open_and_load"))
		goto out;
	err = compute_live_registers__attach(probe);
	if (!ASSERT_OK(err, "compute_live_registers__attach(probe)"))
		goto out;
	skel = compute_live_registers__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "skel = compute_live_registers__open"))
		goto out;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, strcmp(tc->name, bpf_program__name(prog)) == 0);
	err = compute_live_registers__load(skel);
	if (env.verbosity >= VERBOSE_SUPER) {
		printf("--------- VERIFIER LOG ---------\n");
		printf("%s", log);
		printf("----------- END LOG ------------\n");
	}
	if (!ASSERT_OK(err, "compute_live_registers__load(skel)"))
		goto out;

	err = bpf_map__lookup_elem(probe->maps.log_map, tc->name, NAME_LEN,
				   &log_entry, sizeof(log_entry), 0);
	if (err) {
		PRINT_FAIL("no log entry for program '%s'\n", tc->name);
		return;
	}
	f = open_memstream(&result_text, &result_text_sz);
	if (!ASSERT_OK_PTR(f, "open_memstream(do_one_test)"))
		return;
	print_log_entry(f, &log_entry);
	fclose(f);
	if (env.verbosity >= VERBOSE_SUPER)
		printf("Computed live regs for '%s':\n%s\n",
		       tc->name, result_text);
	diff_assert_streq(tc->text, result_text, tc->name);

out:
	if (probe)
		compute_live_registers__detach(probe);
	compute_live_registers__destroy(skel);
	compute_live_registers__destroy(probe);
	free(result_text);
	free(log);
}

void serial_test_compute_live_registers(void)
{
	int i;

	if (read_test_cases("progs/compute_live_registers.c") != 0)
		goto out;
	for (i = 0; i < cases_num; ++i) {
		if (!test__start_subtest(cases[i].name))
			continue;
		fprintf(stderr, "test case: %s\n", cases[i].name);
		do_one_test(&cases[i]);
	}

out:
	free_test_cases();
}
