// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf_verifier.h>
#include <linux/bsearch.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && !insn->off &&
	       insn->imm == bpf_unwind_resume_id[0];
}

int bpf_check_cleanup_insn(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = env->cur_state;
	u32 i = env->insn_idx;
	struct bpf_insn *insn = &env->prog->insnsi[i];
	struct bpf_call_summary cs;

	if (!state->unwinding)
		return 0;
	if (bpf_is_throw_kfunc(insn)) {
		verbose(env, "bpf_throw() while unwinding\n");
		return -EINVAL;
	}
	if (state->curframe != state->unwind_frameno)
		return 0;
	env->insn_aux_data[i].in_cleanup_pad = true;
	if (insn->code == (BPF_JMP | BPF_EXIT)) {
		verbose(env, "exception cleanup landing pad reaches BPF_EXIT\n");
		return -EINVAL;
	}
	/* TODO: Close the gap allowing pad callees to tail-call throwing programs. */
	if (bpf_helper_call(insn) && insn->imm == BPF_FUNC_tail_call) {
		verbose(env, "bpf_tail_call() in an exception cleanup landing pad\n");
		return -EINVAL;
	}
	if (BPF_CLASS(insn->code) == BPF_LD &&
	    (BPF_MODE(insn->code) == BPF_ABS || BPF_MODE(insn->code) == BPF_IND)) {
		verbose(env, "BPF_LD_[ABS|IND] in an exception cleanup landing pad\n");
		return -EINVAL;
	}
	if (is_stack_arg_st(insn) || is_stack_arg_stx(insn) ||
	    (bpf_get_call_summary(env, insn, &cs) && cs.arg_slot_cnt > MAX_BPF_FUNC_REG_ARGS)) {
		verbose(env, "on-stack call argument in an exception cleanup landing pad\n");
		return -EINVAL;
	}
	return 0;
}

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi;
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		struct bpf_subprog_info *sub;
		s64 target;

		if (bpf_is_ldimm64(&insns[i])) {
			i++;
			continue;
		}
		env->insn_aux_data[i].cleanup_throw_site = bpf_is_throw_kfunc(&insns[i]);
		env->insn_aux_data[i].cleanup_resume_site = bpf_is_unwind_resume_kfunc(&insns[i]);
		if (!bpf_is_unwind(&insns[i]))
			continue;
		env->has_cleanup = true;
		sub = bpf_find_containing_subprog(env, i);
		if (!i || i == sub->start || insns[i - 1].code != (BPF_JMP | BPF_CALL)) {
			verbose(env, "UNWIND at insn %u must immediately follow a call in its subprog\n",
				i);
			return -EINVAL;
		}
		if (bpf_is_unwind_resume_kfunc(&insns[i - 1])) {
			verbose(env, "UNWIND cannot follow bpf_unwind_resume()\n");
			return -EINVAL;
		}
		target = (s64)i + 1 + insns[i].off;
		if (target < sub->start || target >= (sub + 1)->start) {
			verbose(env, "UNWIND target must be in the same subprog\n");
			return -EINVAL;
		}
	}
	if (!env->has_cleanup)
		return 0;
	if (bpf_prog_is_offloaded(env->prog->aux) ||
	    !env->prog->jit_requested || !bpf_jit_supports_cleanup_pads()) {
		verbose(env, "exception cleanup needs a JIT that can dispatch landing pads\n");
		return -EOPNOTSUPP;
	}
	if (env->exception_callback_subprog) {
		verbose(env, "exception cleanup cannot be combined with an exception callback\n");
		return -EINVAL;
	}
	env->prog->jit_required = true;
	return 0;
}
/*
 * Every subprogram of a cleanup-carrying program spills the BPF callee-saved
 * registers, even one that never throws: a frame's spill holds its caller's
 * registers, and that is what the walker restores before running the caller's
 * pad. The exception callback does not, because it reuses the boundary frame
 * rather than building one of its own.
 */
bool bpf_cleanup_force_spill(const struct bpf_prog *prog)
{
	return prog->aux->exc && !prog->aux->exception_cb;
}

/*
 * The throw-site spill area, on the other hand, is only ever read for the
 * frame the walk starts in, so only a (sub)program that calls bpf_throw()
 * needs one.
 */
bool bpf_cleanup_needs_throw_spill(const struct bpf_prog *prog)
{
	return bpf_cleanup_force_spill(prog) && prog->aux->exc->nr_throw_at;
}

const struct bpf_cleanup_range *bpf_cleanup_pad_for_ip(const struct bpf_prog *prog, u64 ip)
{
	const struct bpf_exception_info *exc = prog->aux->exc;
	u32 l = 0, r = exc ? exc->nr_ranges : 0;

	while (l < r) {
		u32 m = l + (r - l) / 2;
		const struct bpf_cleanup_range *rec = &exc->ranges[m];

		if (ip <= rec->begin)
			r = m;
		else if (ip > rec->end)
			l = m + 1;
		else
			return rec;
	}
	return NULL;
}

static int cmp_u32(const void *a, const void *b)
{
	u32 x = *(const u32 *)a, y = *(const u32 *)b;

	return x < y ? -1 : x > y;
}

int bpf_cleanup_alloc_info(struct bpf_prog_aux *aux)
{
	if (aux->exc)
		return 0;
	aux->exc = kzalloc_obj(struct bpf_exception_info, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	return aux->exc ? 0 : -ENOMEM;
}

int bpf_cleanup_attach_info(struct bpf_prog_aux *aux, struct bpf_cleanup_info *recs, u32 cnt)
{
	struct bpf_exception_info *exc = aux->exc;
	struct bpf_cleanup_range *ranges;
	u32 i, n_at, *at;

	ranges = kvcalloc(cnt, sizeof(*ranges), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!ranges) {
		kvfree(recs);
		return -ENOMEM;
	}

	/* The pads on their own, sorted and deduplicated. */
	at = kvmalloc_array(cnt, sizeof(*at), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!at) {
		kvfree(ranges);
		kvfree(recs);
		return -ENOMEM;
	}
	for (i = 0; i < cnt; i++)
		at[i] = recs[i].landing_pad_off;
	sort(at, cnt, sizeof(*at), cmp_u32, NULL);
	for (i = 0, n_at = 0; i < cnt; i++)
		if (!n_at || at[n_at - 1] != at[i])
			at[n_at++] = at[i];

	exc->pad_at = at;
	exc->nr_pad_at = n_at;
	exc->info = recs;
	exc->nr_info = cnt;
	exc->ranges = ranges;
	/* Withheld until the JIT has filled the table in. */
	exc->nr_ranges = 0;
	return 0;
}

void bpf_cleanup_fill_native_ranges(struct bpf_prog *prog, u32 *addrs, void *image)
{
	struct bpf_exception_info *exc = prog->aux->exc;
	u32 i, n;

	if (!exc || !exc->nr_info || !exc->ranges)
		return;

	n = exc->nr_info;
	for (i = 0; i < n; i++) {
		const struct bpf_cleanup_info *rec = &exc->info[i];

		if (WARN_ON_ONCE(rec->begin_off >= prog->len ||
				 rec->end_off > prog->len ||
				 rec->landing_pad_off >= prog->len))
			return;
		exc->ranges[i].begin = (u64)(long)image + addrs[rec->begin_off];
		exc->ranges[i].end = (u64)(long)image + addrs[rec->end_off];
		exc->ranges[i].pad = (u64)(long)image + addrs[rec->landing_pad_off];
	}
	exc->nr_ranges = n;
}

void bpf_cleanup_free_info(struct bpf_prog_aux *aux)
{
	struct bpf_exception_info *exc = aux->exc;

	if (!exc)
		return;
	kvfree(exc->ranges);
	kvfree(exc->info);
	kvfree(exc->pad_at);
	kvfree(exc->throw_at);
	kvfree(exc->resume_at);
	kfree(exc);
	aux->exc = NULL;
}

/* Is @idx in the sorted array @at of @n instruction indices? */
static bool insn_idx_in(const u32 *at, u32 n, u32 idx)
{
	return bsearch(&idx, at, n, sizeof(*at), cmp_u32);
}

bool bpf_cleanup_insn_is_pad(const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_exception_info *exc = prog->aux->exc;

	return exc && insn_idx_in(exc->pad_at, exc->nr_pad_at, idx);
}

bool bpf_cleanup_insn_is_throw(const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_exception_info *exc = prog->aux->exc;

	return exc && insn_idx_in(exc->throw_at, exc->nr_throw_at, idx);
}

bool bpf_cleanup_insn_is_resume(const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_exception_info *exc = prog->aux->exc;

	return exc && insn_idx_in(exc->resume_at, exc->nr_resume_at, idx);
}

bool bpf_cleanup_insn_in_pad(const struct bpf_verifier_env *env,
			     const struct bpf_prog *prog, u32 idx)
{
	if (!env)
		return false;
	idx += prog->aux->subprog_start;
	return env->insn_aux_data[idx].in_cleanup_pad;
}
