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
}

static void print_log_entry(FILE *f, struct log_entry *e)
{
	char buf[64];

	for (int i = 0; i < e->prog_len;) {
		fprintf(f, "[%02d] ", i);
		for (int r = 0; r < 10; ++r) {
			if (e->live_regs[i] & (1u << r))
				fprintf(f, "%d", r);
			else
				fprintf(f, ".");
		}
		i += disasm_insn(&e->insns[i], buf, sizeof(buf));
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
	int idx;

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
			idx = 0;
		}
		if (sscanf(line, " \"call %%[%63[^]]];\" /* %63[0-9.] */", insn, comment) == 2) {
			if (!c)
				continue;
			fprintf(c, "[%02d] %-10s call %s\n", idx, comment, insn);
			idx++;
		} else if (sscanf(line, " \"%63[^;];\" /* %63[0-9.] */", insn, comment) == 2) {
			if (!c)
				continue;
			fprintf(c, "[%02d] %-10s %s\n", idx, comment, insn);
			idx++;
		}
	}
	if (c)
		fclose(c);
	free(line);
	fclose(f);
	return 0;
}

static void do_one_test(struct test_case *tc, struct bpf_map *log_map)
{
	struct log_entry log_entry;
	size_t result_text_sz = 0;
	char *result_text = NULL;
	FILE *f = NULL;
	int err;

	err = bpf_map__lookup_elem(log_map, tc->name, NAME_LEN,
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
	free(result_text);
}

void serial_test_compute_live_registers(void)
{
	struct compute_live_registers *test_skel = NULL;
	struct compute_live_registers *skel = NULL;
	struct bpf_program *prog = NULL;
	int err, i;

	if (read_test_cases("progs/compute_live_registers.c") != 0)
		goto out;
	skel = compute_live_registers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel = compute_live_registers__open_and_load"))
		goto out;
	test_skel = compute_live_registers__open();
	if (!ASSERT_OK_PTR(test_skel, "test_skel = compute_live_registers__open"))
		goto out;
	bpf_object__for_each_program(prog, test_skel->obj) {
		if (strncmp("lv_", bpf_program__name(prog), 3) == 0)
			bpf_program__set_autoload(prog, true);
	}
	err = compute_live_registers__attach(skel);
	if (!ASSERT_OK(err, "compute_live_registers__attach(skel)"))
		goto out;
	err = compute_live_registers__load(test_skel);
	if (!ASSERT_OK(err, "compute_live_registers__load(test_skel)"))
		goto out;
	compute_live_registers__detach(skel);
	for (i = 0; i < cases_num; ++i) {
		if (!test__start_subtest(cases[i].name))
			continue;
		fprintf(stderr, "test case: %s\n", cases[i].name);
		do_one_test(&cases[i], skel->maps.log_map);
	}

out:
	if (skel)
		compute_live_registers__detach(skel);
	compute_live_registers__destroy(test_skel);
	compute_live_registers__destroy(skel);
	free_test_cases();
}
