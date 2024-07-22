// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <test_progs.h>

int get_jited_program_text(int fd, char *text, size_t text_sz)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	FILE *bpftool_out = NULL;
	FILE *text_in = NULL;
	char buf[512];
	int err = 0;

	text_in = fmemopen(text, text_sz, "w");
	if (!ASSERT_OK_PTR(text_in, "open_memstream")) {
		err = -1;
		goto out;
	}

	err = bpf_prog_get_info_by_fd(fd, &info, &info_len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd"))
		goto out;

	snprintf(buf, sizeof(buf),
		 "./tools/build/bpftool/bpftool prog dump jited id %d", info.id);
	bpftool_out = popen(buf, "r");
	if (!ASSERT_OK_PTR(bpftool_out, "popen bpftool")) {
		err = -1;
		goto out;
	}

	while (fgets(buf, sizeof(buf), bpftool_out)) {
		err = fputs(buf, text_in);
		if (err < 0) {
			PRINT_FAIL("fputs() text_in err = %d\n", err);
			goto out;
		}
	}
	err = ferror(bpftool_out);
	ASSERT_OK(err, "ferror() bpftool");

out:
	if (bpftool_out)
		pclose(bpftool_out);
	if (text_in)
		fclose(text_in);
	return err;
}
