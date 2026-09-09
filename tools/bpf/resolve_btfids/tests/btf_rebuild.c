// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/kernel.h>
#include <bpf/libbpf_internal.h>
#include "../btf_colors.h"

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #cond); \
		exit(1); \
	} \
} while (0)

static struct btf *new_btf(struct btf *base, bool layout, enum btf_endianness endian)
{
	LIBBPF_OPTS(btf_new_opts, opts, .base_btf = base, .add_layout = layout);
	struct btf *btf = btf__new_empty_opts(&opts);

	CHECK(btf);
	CHECK(!btf__set_endianness(btf, endian));
	return btf;
}

static struct btf *roundtrip(struct btf *btf, struct btf *base)
{
	const void *raw;
	struct btf *copy;
	__u32 size;

	raw = btf__raw_data(btf, &size);
	CHECK(raw);
	copy = btf__new_split(raw, size, base);
	CHECK(!libbpf_get_error(copy));
	CHECK(btf__endianness(copy) == btf__endianness(btf));
	CHECK(btf_header(copy)->layout_len == btf_header(btf)->layout_len);
	return copy;
}

static void test_split_by_color(bool split, bool layout, enum btf_endianness endian)
{
	struct btf *base = NULL, *src, *main_btf, *inline_btf, *main_copy, *inline_copy;
	__u32 count, start_id, int_id, shared, proto, func, lp, locproto;
	__u8 *colors;
	const struct btf_type *t;
	const struct btf_loc *loc;
	const void *raw;
	void *snapshot;
	__u32 raw_size, size;
	int id, mode;

	if (split) {
		base = new_btf(NULL, layout, endian);
		CHECK(btf__add_int(base, "int", 4, BTF_INT_SIGNED) == 1);
	}
	src = new_btf(base, layout, endian);
	int_id = split ? 1 : btf__add_int(src, "int", 4, BTF_INT_SIGNED);
	proto = btf__add_func_proto(src, int_id);
	CHECK(btf__add_func_param(src, "arg", int_id) == 0);
	func = btf__add_func(src, "inline_only", BTF_FUNC_STATIC, proto);
	shared = btf__add_struct(src, "shared", 4);
	lp = btf__add_loc_param(src, 4, BTF_LOC_PARAM_REG);
	CHECK(btf__add_loc_param_value(src, 5) == 0);
	locproto = btf__add_loc_proto(src);
	CHECK(btf__add_loc_proto_param(src, lp) == 0);
	CHECK(btf__add_locsec(src, ".text") > 0);
	CHECK(btf__add_locsec_loc(src, func, locproto, 128) == 0);
	CHECK(btf__add_locsec_loc(src, func, locproto, 0) == 0);
	id = btf__add_func(src, "shared", BTF_FUNC_STATIC, proto);
	CHECK(id > 0);
	count = btf__type_cnt(src);
	start_id = base ? btf__type_cnt(base) : 1;
	colors = malloc(count);
	CHECK(colors);
	memset(colors, BTF_COLOR_LOC, count);
	colors[int_id] = BTF_COLOR_SHARED;
	colors[shared] = BTF_COLOR_MAIN;
	raw = btf__raw_data(src, &raw_size);
	CHECK(raw);
	snapshot = malloc(raw_size);
	CHECK(snapshot);
	memcpy(snapshot, raw, raw_size);

	CHECK(!btf_split_by_color(src, colors, &main_btf, &inline_btf));
	CHECK(btf__base_btf(main_btf) == base && btf__base_btf(inline_btf) == main_btf);
	CHECK(btf__find_str(main_btf, "inline_only") == -ENOENT);
	id = btf__find_by_name_kind(inline_btf, "shared", BTF_KIND_FUNC);
	CHECK(id > 0);
	CHECK(btf__type_by_id(inline_btf, id)->name_off == btf__find_str(main_btf, "shared"));
	id = btf__find_by_name_kind(inline_btf, "inline_only", BTF_KIND_FUNC);
	CHECK(id > 0);
	t = btf__type_by_id(inline_btf, btf__type_by_id(inline_btf, id)->type);
	CHECK(btf_is_func_proto(t) && t->type == 1);
	CHECK(btf_params(t)->type == t->type);
	id = btf__find_by_name_kind(inline_btf, ".text", BTF_KIND_LOCSEC);
	CHECK(id > 0);
	loc = btf_locsec_locs(btf__type_by_id(inline_btf, id));
	CHECK(loc[0].offset == 0 && loc[1].offset == 128);
	t = btf__type_by_id(inline_btf, loc[0].loc_proto);
	CHECK(btf_is_loc_proto(t));
	t = btf__type_by_id(inline_btf, *btf_loc_proto_params(t));
	CHECK(btf_is_loc_param(t) && btf_loc_param(t)->flags == BTF_LOC_PARAM_REG);
	CHECK(*(__u32 *)(btf_loc_param(t) + 1) == 5);
	main_copy = roundtrip(main_btf, base);
	inline_copy = roundtrip(inline_btf, main_copy);
	btf__free(inline_copy);
	btf__free(main_copy);
	btf__free(inline_btf);
	btf__free(main_btf);

	/* Exercise both an empty main partition and an empty inline partition. */
	for (mode = 0; mode < 2; mode++) {
		memset(colors, mode ? BTF_COLOR_MAIN : BTF_COLOR_LOC, count);
		CHECK(!btf_split_by_color(src, colors, &main_btf, &inline_btf));
		CHECK(btf__base_btf(inline_btf) == main_btf);
		CHECK(btf__type_cnt(inline_btf) - btf__type_cnt(main_btf) ==
		      (mode ? 0 : count - start_id));
		btf__free(inline_btf);
		btf__free(main_btf);
	}
	raw = btf__raw_data(src, &size);
	CHECK(raw && size == raw_size && !memcmp(raw, snapshot, size));
	free(snapshot);
	free(colors);
	btf__free(src);
	btf__free(base);
}

static void test_colors(void)
{
	struct btf *base = new_btf(NULL, false, BTF_LITTLE_ENDIAN), *btf;
	__u32 root, count, i, *worklist;
	__u8 *colors;

	CHECK(btf__add_int(base, "int", 4, BTF_INT_SIGNED) == 1);
	btf = new_btf(base, false, BTF_LITTLE_ENDIAN);
	CHECK(btf__add_struct(btf, "cycle", 16) == 2);
	CHECK(!btf__add_field(btf, "first", 3, 0, 0));
	CHECK(!btf__add_field(btf, "second", 3, 64, 0));
	CHECK(btf__add_ptr(btf, 2) == 3);
	root = 3;
	/* A recursive walk would consume the C stack on this chain. */
	for (i = 0; i < 50000; i++)
		root = btf__add_ptr(btf, root);
	CHECK(root == 50003);
	count = btf__type_cnt(btf);
	colors = calloc(count, sizeof(*colors));
	worklist = calloc(count - btf__type_cnt(base), sizeof(*worklist));
	CHECK(colors && worklist);
	btf_mark_reachable(btf, root, BTF_COLOR_LOC, colors, worklist);
	CHECK(colors[0] == BTF_COLOR_NONE && colors[1] == BTF_COLOR_NONE);
	for (i = 2; i <= root; i++)
		CHECK(colors[i] == BTF_COLOR_LOC);
	btf_mark_reachable(btf, 2, BTF_COLOR_MAIN, colors, worklist);
	CHECK(colors[2] == BTF_COLOR_SHARED && colors[3] == BTF_COLOR_SHARED);
	CHECK(colors[root] == BTF_COLOR_LOC);
	btf_mark_reachable(btf, root, BTF_COLOR_MAIN, colors, worklist);
	btf_mark_reachable(btf, root, BTF_COLOR_LOC, colors, worklist);
	for (i = 2; i <= root; i++)
		CHECK(colors[i] == BTF_COLOR_SHARED);
	btf_mark_reachable(btf, 0, BTF_COLOR_MAIN, colors, worklist);
	btf_mark_reachable(btf, 1, BTF_COLOR_LOC, colors, worklist);
	CHECK(colors[0] == BTF_COLOR_NONE && colors[1] == BTF_COLOR_NONE);
	free(worklist);
	free(colors);
	btf__free(btf);
	btf__free(base);
}

static void write_btf(struct btf *btf, const char *path)
{
	__u32 size;
	const void *raw = btf__raw_data(btf, &size);
	FILE *f = fopen(path, "wb");

	CHECK(raw && f);
	CHECK(fwrite(raw, 1, size, f) == size);
	CHECK(!fclose(f));
}

static void copy_file(const char *from, const char *to)
{
	FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
	char buf[4096];
	size_t n;

	CHECK(in && out);
	while ((n = fread(buf, 1, sizeof(buf), in)))
		CHECK(fwrite(buf, 1, n, out) == n);
	CHECK(!ferror(in));
	CHECK(!fclose(in) && !fclose(out));
}

static void check_name_order(struct btf *btf)
{
	const struct btf *base = btf__base_btf(btf);
	__u32 start_id = base ? btf__type_cnt(base) : 1, i;
	const char *prev = "";

	for (i = start_id; i < btf__type_cnt(btf); i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name = btf__name_by_offset(btf, t->name_off);

		CHECK(strcmp(prev, name) <= 0);
		prev = name;
	}
}

static void test_resolver(const char *resolver, const char *fixture, const char *dir,
			  bool split, bool distill, enum btf_endianness endian)
{
	struct btf *base = NULL, *src, *main_btf, *inline_btf;
	static const char * const names[] = { "inline_only", "tagged", "outlined", "id_user" };
	char input[PATH_MAX], elf[PATH_MAX - 32], path[PATH_MAX], basepath[PATH_MAX];
	__u32 funcs[4], int_id, result_id, proto, locproto, param;
	const struct btf_type *t;
	const struct btf_loc *loc;
	pid_t pid;
	int status, i, id, orphan_protos = 0, orphan_params = 0;

	i = snprintf(elf, sizeof(elf), "%s/case-%d-%d-%d.o", dir, split, distill, endian);
	CHECK(i > 0 && i < sizeof(elf));
	CHECK(snprintf(input, sizeof(input), "%s.input", elf) > 0);
	CHECK(snprintf(basepath, sizeof(basepath), "%s.base", elf) > 0);
	copy_file(fixture, elf);
	if (split) {
		base = new_btf(NULL, true, endian);
		CHECK(btf__add_int(base, "int", 4, BTF_INT_SIGNED) == 1);
		write_btf(base, basepath);
	}
	src = new_btf(base, true, endian);
	int_id = split ? 1 : btf__add_int(src, "int", 4, BTF_INT_SIGNED);
	result_id = btf__add_struct(src, "inline_result", 4);
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		proto = btf__add_func_proto(src, i ? int_id : result_id);
		funcs[i] = btf__add_func(src, names[i], BTF_FUNC_STATIC, proto);
	}
	CHECK(btf__add_ptr(src, proto) > 0); /* Shared prototype must remain in main. */
	CHECK(btf__add_decl_tag(src, "test_tag", funcs[1], -1) > 0);
	/* Orphan location types still belong to the inline output. */
	CHECK(btf__add_loc_param(src, 8, BTF_LOC_PARAM_CONST) > 0);
	CHECK(!btf__add_loc_param_value(src, 42));
	CHECK(btf__add_loc_proto(src) > 0);
	param = btf__add_loc_param(src, 4, BTF_LOC_PARAM_CONST);
	CHECK(btf__add_loc_param_value(src, 0x12345678) == 0);
	locproto = btf__add_loc_proto(src);
	CHECK(btf__add_loc_proto_param(src, param) == 0);
	CHECK(btf__add_loc_proto_param(src, 0) == 0);
	CHECK(btf__add_locsec(src, ".text") > 0);
	for (i = ARRAY_SIZE(names) - 1; i >= 0; i--) {
		CHECK(btf__add_locsec_loc(src, funcs[i], locproto, 128) == 0);
		CHECK(btf__add_locsec_loc(src, funcs[i], locproto, 0) == 0);
	}
	write_btf(src, input);
	btf__free(src);
	pid = fork();
	CHECK(pid >= 0);
	if (!pid) {
		if (split && distill)
			execl(resolver, resolver, "--inline", "--distill_base", "--btf_base", basepath,
			      "--btf", input, elf, NULL);
		else if (split)
			execl(resolver, resolver, "--inline", "--btf_base", basepath,
			      "--btf", input, elf, NULL);
		else
			execl(resolver, resolver, "--inline", "--btf", input, elf, NULL);
		_exit(127);
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
	if (distill) {
		btf__free(base);
		snprintf(path, sizeof(path), "%s.BTF.base", elf);
		base = btf__parse_raw(path);
		CHECK(!libbpf_get_error(base));
	}
	snprintf(path, sizeof(path), "%s.BTF", elf);
	main_btf = btf__parse_raw_split(path, base);
	CHECK(!libbpf_get_error(main_btf));
	snprintf(path, sizeof(path), "%s.BTF.inline", elf);
	inline_btf = btf__parse_raw_split(path, main_btf);
	CHECK(!libbpf_get_error(inline_btf));
	CHECK(btf__endianness(main_btf) == endian && btf__endianness(inline_btf) == endian);
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		id = btf__find_by_name_kind(main_btf, names[i], BTF_KIND_FUNC);
		CHECK(i ? id > 0 : id == -ENOENT);
		id = btf__find_by_name_kind(inline_btf, names[i], BTF_KIND_FUNC);
		CHECK(id > 0);
		t = btf__type_by_id(inline_btf, id);
		CHECK(i ? t->type < btf__type_cnt(main_btf) : t->type >= btf__type_cnt(main_btf));
	}
	check_name_order(main_btf);
	check_name_order(inline_btf);
	CHECK(btf__find_str(main_btf, "inline_only") == -ENOENT);
	CHECK(btf__find_by_name_kind(main_btf, "inline_result", BTF_KIND_STRUCT) > 0);
	for (id = 1; id < btf__type_cnt(inline_btf); id++) {
		t = btf__type_by_id(inline_btf, id);
		if (btf_is_loc_param(t) || btf_is_loc_proto(t) || btf_is_locsec(t))
			CHECK(id >= btf__type_cnt(main_btf));
		if (btf_is_loc_proto(t) && !btf_vlen(t))
			orphan_protos++;
		if (btf_is_loc_param(t) && t->size == 8 &&
		    *(__u32 *)(btf_loc_param(t) + 1) == 42)
			orphan_params++;
	}
	CHECK(orphan_protos == 1 && orphan_params == 1);
	id = btf__find_by_name_kind(inline_btf, ".text", BTF_KIND_LOCSEC);
	CHECK(id >= btf__type_cnt(main_btf));
	t = btf__type_by_id(inline_btf, id);
	loc = btf_locsec_locs(t);
	for (i = 1; i < btf_vlen(t); i++)
		CHECK(loc[i - 1].func < loc[i].func ||
		      (loc[i - 1].func == loc[i].func && loc[i - 1].offset < loc[i].offset));
	t = btf__type_by_id(inline_btf, loc[0].loc_proto);
	CHECK(btf_is_loc_proto(t) && btf_loc_proto_params(t)[1] == 0);
	t = btf__type_by_id(inline_btf, btf_loc_proto_params(t)[0]);
	CHECK(btf_is_loc_param(t) && btf_loc_param(t)->flags == BTF_LOC_PARAM_CONST);
	CHECK(*(__u32 *)(btf_loc_param(t) + 1) == 0x12345678);
	snprintf(path, sizeof(path), "%s.BTF_ids", elf);
	{
		FILE *f = fopen(path, "rb");
		__u32 resolved;

		CHECK(f && fread(&resolved, sizeof(resolved), 1, f) == 1);
		CHECK(!fclose(f));
		CHECK(resolved == btf__find_by_name_kind(main_btf, "id_user", BTF_KIND_FUNC));
	}
	btf__free(inline_btf);
	btf__free(main_btf);
	btf__free(base);
}

static void test_no_inline(const char *resolver, const char *fixture, const char *dir)
{
	char input[PATH_MAX], elf[PATH_MAX - 32], path[PATH_MAX];
	struct btf *btf = new_btf(NULL, true, BTF_LITTLE_ENDIAN);
	int proto, status;
	pid_t pid;

	CHECK(btf__add_int(btf, "int", 4, BTF_INT_SIGNED) == 1);
	proto = btf__add_func_proto(btf, 1);
	CHECK(btf__add_func(btf, "id_user", BTF_FUNC_STATIC, proto) > 0);
	snprintf(elf, sizeof(elf), "%s/no-inline.o", dir);
	snprintf(input, sizeof(input), "%s.input", elf);
	snprintf(path, sizeof(path), "%s.BTF.inline", elf);
	CHECK(!unlink(path) || errno == ENOENT);
	copy_file(fixture, elf);
	write_btf(btf, input);
	btf__free(btf);

	pid = fork();
	CHECK(pid >= 0);
	if (!pid) {
		execl(resolver, resolver, "--inline", "--btf", input, elf, NULL);
		_exit(1);
	}
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
	CHECK(access(path, F_OK) == -1 && errno == ENOENT);
	snprintf(path, sizeof(path), "%s.BTF", elf);
	btf = btf__parse_raw(path);
	CHECK(!libbpf_get_error(btf));
	CHECK(btf__type_cnt(btf) == 4);
	CHECK(btf__find_by_name_kind(btf, "id_user", BTF_KIND_FUNC) > 0);
	btf__free(btf);
}

int main(int argc, char **argv)
{
	struct btf *src, *main_btf, *inline_btf;
	int split, layout, endian;

	CHECK(argc == 4);
	test_colors();
	CHECK(!mkdir(argv[3], 0755) || errno == EEXIST);
	for (split = 0; split < 2; split++)
		for (layout = 0; layout < 2; layout++)
			for (endian = BTF_LITTLE_ENDIAN; endian <= BTF_BIG_ENDIAN; endian++)
				test_split_by_color(split, layout, endian);
	src = new_btf(NULL, false, BTF_LITTLE_ENDIAN);
	CHECK(!btf_split_by_color(src, NULL, &main_btf, &inline_btf));
	CHECK(btf__type_cnt(main_btf) == 1 && btf__type_cnt(inline_btf) == 1);
	CHECK(btf__base_btf(inline_btf) == main_btf);
	btf__free(inline_btf);
	btf__free(main_btf);
	btf__free(src);
	for (endian = BTF_LITTLE_ENDIAN; endian <= BTF_BIG_ENDIAN; endian++) {
		test_resolver(argv[1], argv[2], argv[3], false, false, endian);
		test_resolver(argv[1], argv[2], argv[3], true, false, endian);
		test_resolver(argv[1], argv[2], argv[3], true, true, endian);
	}
	test_no_inline(argv[1], argv[2], argv[3]);
	puts("BTF reconstruction and resolver tests passed");
	return 0;
}
