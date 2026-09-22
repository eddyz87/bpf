// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf_verifier.h>
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
