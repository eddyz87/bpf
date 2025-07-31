// SPDX-License-Identifier: GPL-2.0-only

#include "linux/slab.h"
#include <linux/bpf_verifier.h>
#include <linux/rhashtable.h>

struct callchain {
	u32 callsites[MAX_CALL_FRAMES];
	u32 sp_starts[MAX_CALL_FRAMES];
	u32 curframe;
};

struct frame_liveness {
	u64 may_read;
	u64 must_write;
	u64 must_write_acc;
	u64 live_before;
	u64 old_live_before; // TODO: debug only, move to a separate array
	bool must_write_set; // TODO: move to a separate array
};

struct bpf_cc_liveness {
	struct rhash_head ht_node;
	struct callchain callchain;
	u32 insn_cnt;
	bool updated;
	struct frame_liveness insn_info[];
};

static const struct rhashtable_params cc_liveness_ht_prams = {
	.key_offset = offsetof(struct bpf_cc_liveness, callchain),
	.head_offset = offsetof(struct bpf_cc_liveness, ht_node),
	.key_len = sizeof(struct callchain),
};

static struct bpf_cc_liveness *__lookup_cc_liveness(struct bpf_verifier_env *env, struct callchain *cc)
{
	struct bpf_subprog_info *subprog;
	struct bpf_cc_liveness *result;
	struct rhashtable *ht;
	u32 subprog_sz, size;
	int err;

	ht = &env->callchain_liveness_ht;
	result = rhashtable_lookup_fast(ht, cc, cc_liveness_ht_prams);
	if (result)
		return result;

	subprog = bpf_find_containing_subprog(env, cc->sp_starts[cc->curframe]);
	subprog_sz = (subprog + 1)->start - subprog->start;
	size = sizeof(struct bpf_cc_liveness) +
	       (cc->curframe + 1) * subprog_sz * sizeof(struct frame_liveness);
	result = kvzalloc(size, GFP_KERNEL_ACCOUNT);
	if (!result)
		return ERR_PTR(-ENOMEM);

	memcpy(&result->callchain, cc, sizeof(*cc));
	result->insn_cnt = subprog_sz;
	err = rhashtable_insert_fast(ht, &result->ht_node, cc_liveness_ht_prams);
	if (err)
		return ERR_PTR(err);

	return result;
}

int bpf_stack_liveness_init(struct bpf_verifier_env *env)
{
	int err;

	err = rhashtable_init(&env->callchain_liveness_ht, &cc_liveness_ht_prams);
	if (err)
		return err;
	env->ccl_ht_init = true;
	return 0;
}

static void free_first_arg(void *a, void *b)
{
	kvfree(a);
}

void bpf_stack_liveness_free(struct bpf_verifier_env *env)
{
	if (!env->ccl_ht_init)
		return;

	rhashtable_free_and_destroy(&env->callchain_liveness_ht, free_first_arg, NULL);
	env->ccl_ht_init = false;
}

static struct frame_liveness *get_insn_liveness(struct bpf_cc_liveness *ccl, u32 frame, u32 insn_idx)
{
	struct callchain *cc = &ccl->callchain;
	u32 relative_idx;

	relative_idx = insn_idx - cc->sp_starts[cc->curframe];
	return &ccl->insn_info[ccl->insn_cnt * frame + relative_idx]; // TODO: pack by insn, not by frame
}

static void compute_callchain(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			      struct callchain *cc, u32 frameno)
{
	struct bpf_subprog_info *subprog_info = env->subprog_info;
	u32 i;

	memset(cc, 0, sizeof(*cc));
	for (i = 0; i <= frameno; i++) {
		cc->sp_starts[i] = subprog_info[st->frame[i]->subprogno].start;
		if (i < st->curframe)
			cc->callsites[i] = st->frame[i + 1]->callsite;
	}
	cc->curframe = frameno;
	cc->callsites[cc->curframe] = cc->sp_starts[cc->curframe];
}

static void callchain_frame_up(struct bpf_verifier_env *env, struct callchain *cc)
{
	cc->callsites[cc->curframe] = 0;
	cc->sp_starts[cc->curframe] = 0;
	cc->curframe--;
	cc->callsites[cc->curframe] = cc->sp_starts[cc->curframe];
}

static void log_stack_mask(struct bpf_verifier_env *env, struct callchain *cc, char *pfx,
			   u32 frame, u32 insn_idx, u64 mask);

static void __mark_stack_read(struct bpf_verifier_env *env, struct bpf_cc_liveness *ccl, u32 frame, u32 insn_idx, u64 mask)
{
	struct frame_liveness *il;

	il = get_insn_liveness(ccl, frame, insn_idx);
	if ((il->may_read | mask) != il->may_read)
		ccl->updated = true;
	il->may_read |= mask;
}

static void __mark_stack_write(struct bpf_verifier_env *env,
			       struct bpf_cc_liveness *ccl, u32 frame, u32 insn_idx, u64 mask)
{
	struct frame_liveness *il;
	bool reset_must;
	u32 i;

	reset_must = false;
	for (i = 0; i < ccl->callchain.curframe; i++) {
		il = get_insn_liveness(ccl, i, insn_idx);
		if (il->must_write_set && i != frame)
			reset_must = true;
	}
	if (reset_must) {
		for (i = 0; i < ccl->callchain.curframe; i++) {
			il = get_insn_liveness(ccl, i, insn_idx);
			il->must_write_set = true;
			il->must_write = 0;
		}
		ccl->updated = true;
	} else {
		il = get_insn_liveness(ccl, frame, insn_idx);
		if (il->must_write_set) {
			if ((mask & il->must_write) != il->must_write)
				ccl->updated = true;
			il->must_write &= mask;
		} else {
			il->must_write = mask;
			il->must_write_set = true;
			ccl->updated = true;
		}
	}
}

static char *fmt_callchain(struct bpf_verifier_env *env, struct callchain *cc)
{
	char *buf_end = env->tmp_str_buf + sizeof(env->tmp_str_buf);
	char *buf = env->tmp_str_buf;
	int i;

	buf += snprintf(buf, buf_end - buf, "(");
	for (i = 0; i <= cc->curframe; i++)
		buf += snprintf(buf, buf_end - buf, "%s%d", i ? "," : "", cc->callsites[i]);
	snprintf(buf, buf_end - buf, ")");
	return env->tmp_str_buf;
}

char *bpf_fmt_ccl(struct bpf_verifier_env *env, struct bpf_cc_liveness *ccl)
{
	return fmt_callchain(env, &ccl->callchain);
}

static void log_stack_mask(struct bpf_verifier_env *env, struct callchain *cc, char *pfx,
				 u32 frame, u32 insn_idx, u64 mask)
{
	bpf_log(&env->log, "%s ", fmt_callchain(env, cc));
	bpf_fmt_stack_mask(env->tmp_str_buf, sizeof(env->tmp_str_buf), mask);
	bpf_log(&env->log, "frame %d insn %d, %s: %s\n", frame, insn_idx, pfx, env->tmp_str_buf);
}

static void log_live_before_changes(struct bpf_verifier_env *env, struct bpf_cc_liveness *ccl)
{
	struct callchain *cc = &ccl->callchain;
	u32 i, frame, this_subprog_start;

	this_subprog_start = cc->sp_starts[cc->curframe];
	for (i = 0; i < ccl->insn_cnt; i++) {
		for (frame = 0; frame <= cc->curframe; frame++) {
			u64 new_bits, new_live, new_dead;
			struct frame_liveness *insn;
			u32 insn_idx;

			insn_idx = this_subprog_start + i;
			insn = get_insn_liveness(ccl, frame, insn_idx);
			if (insn->old_live_before == insn->live_before)
				continue;
			new_bits = insn->live_before ^ insn->old_live_before;
			new_live = insn->live_before & new_bits;
			new_dead = new_bits & ~new_live;
			if (new_live)
				log_stack_mask(env, cc, "new live", frame, insn_idx, new_live);
			if (new_dead)
				log_stack_mask(env, cc, "new dead", frame, insn_idx, new_dead);
			if (insn->may_read)
				log_stack_mask(env, cc, "may read", frame, insn_idx, insn->may_read);
			if (insn->must_write)
				log_stack_mask(env, cc, "must write", frame, insn_idx, insn->must_write);
		}
	}
}

static void log_marks_transfer(struct bpf_verifier_env *env,
			       struct bpf_cc_liveness *ccl,
			       struct bpf_cc_liveness *outer_ccl,
			       u32 frame, u64 mask, char *mask_name)
{
	if (!mask)
		return;
	bpf_log(&env->log, "%s -> ", fmt_callchain(env, &ccl->callchain));
	bpf_log(&env->log, "%s ", fmt_callchain(env, &outer_ccl->callchain));
	bpf_fmt_stack_mask(env->tmp_str_buf, sizeof(env->tmp_str_buf), mask);
	bpf_log(&env->log, "frame %d %s: %s\n", frame, mask_name, env->tmp_str_buf);
}

static void propagate_to_outer_ccl(struct bpf_verifier_env *env, struct bpf_cc_liveness *ccl)
{
	u32 this_subprog_start, callsite, frame;
	struct callchain *cc = &ccl->callchain;
	struct bpf_cc_liveness *outer_ccl;
	struct frame_liveness *insn;
	struct callchain outer_cc;

	this_subprog_start = cc->sp_starts[cc->curframe];
	outer_cc = *cc;
	callchain_frame_up(env, &outer_cc);
	outer_ccl = __lookup_cc_liveness(env, &outer_cc);
	callsite = cc->callsites[cc->curframe - 1];
	for (frame = 0; frame < cc->curframe; frame++) {
		insn = get_insn_liveness(ccl, frame, this_subprog_start);
		__mark_stack_write(env, outer_ccl, frame, callsite, insn->must_write_acc);
		__mark_stack_read(env, outer_ccl, frame, callsite, insn->live_before);
		if (env->log.level & BPF_LOG_LEVEL2) {
			log_marks_transfer(env, ccl, outer_ccl, frame, insn->must_write_acc,
					   "callsite must_write");
			log_marks_transfer(env, ccl, outer_ccl, frame, insn->live_before,
					   "callsite may_read");
		}
	}
}

static void __update_stack_liveness(struct bpf_verifier_env *env, struct bpf_cc_liveness *ccl)
{
	/* update liveness for a subprog corresponding to ccl->callchain */
	u32 i, frame, po_start, po_end, cnt, this_subprog_start;
	int *insn_postorder = env->cfg.insn_postorder;
	struct callchain *cc = &ccl->callchain;
	struct bpf_subprog_info *subprog;
	bool changed;

	this_subprog_start = cc->sp_starts[cc->curframe];
	for (frame = 0; frame <= cc->curframe; frame++) {
		for (i = 0; i < ccl->insn_cnt; i++) {
			struct frame_liveness *insn;

			insn = get_insn_liveness(ccl, frame, this_subprog_start + i);
			insn->old_live_before = insn->live_before;
			insn->live_before = 0;
			insn->must_write_acc = 0;
		}
	}

	subprog = bpf_find_containing_subprog(env, this_subprog_start);
	po_start = subprog->postorder_start;
	po_end = (subprog + 1)->postorder_start;
	cnt = 0;
	/* repeat until fixed point is reached */
	do {
		cnt++;
		changed = false;
		for (i = po_start; i < po_end; i++) {
			struct frame_liveness *insn, *succ_insn;
			u64 new_before, new_after, must_write_acc;
			u32 succ_num, s, succ[2];

			succ_num = bpf_insn_successors(env->prog, insn_postorder[i], succ);
			/* for each frame in current callchain */
			for (frame = 0; frame <= ccl->callchain.curframe; frame++) {
				insn = get_insn_liveness(ccl, frame, insn_postorder[i]);
				new_before = 0;
				new_after = 0;
				must_write_acc = 0;
				for (s = 0; s < succ_num; ++s) {
					succ_insn = get_insn_liveness(ccl, frame, succ[s]);
					new_after |= succ_insn->live_before;
					if (s == 0)
						must_write_acc = succ_insn->must_write;
					else
						must_write_acc &= succ_insn->must_write;
				}
				must_write_acc |= insn->must_write;
				new_before = (new_after & ~insn->must_write) | insn->may_read;
				if (new_before != insn->live_before) {
					insn->live_before = new_before;
					changed = true;
				}
				if (must_write_acc != insn->must_write_acc) {
					insn->must_write_acc = must_write_acc;
					changed = true;
				}
			}

		}
	} while (changed);

	if (env->log.level & BPF_LOG_LEVEL2)
		log_live_before_changes(env, ccl);

	/* transfer outer stack marks to outer frame */
	if (cc->curframe > 0)
		propagate_to_outer_ccl(env, ccl);
}

struct bpf_cc_liveness *bpf_lookup_cc_liveness(struct bpf_verifier_env *env,
					       struct bpf_verifier_state *st,
					       u32 frameno)
{
	struct callchain cc;

	compute_callchain(env, st, &cc, frameno);
	return __lookup_cc_liveness(env, &cc);
}

int bpf_mark_stack_write(struct bpf_verifier_env *env, u32 frame, u32 insn_idx, u64 mask)
{
	struct bpf_cc_liveness *ccl;

	ccl = bpf_lookup_cc_liveness(env, env->cur_state, env->cur_state->curframe);
	if (IS_ERR(ccl))
		return PTR_ERR(ccl);

	__mark_stack_write(env, ccl, frame, insn_idx, mask);
	return 0;
}

int bpf_mark_stack_read(struct bpf_verifier_env *env, u32 frame, u32 insn_idx, u64 mask)
{
	struct bpf_cc_liveness *ccl;

	ccl = bpf_lookup_cc_liveness(env, env->cur_state, env->cur_state->curframe);
	if (IS_ERR(ccl))
		return PTR_ERR(ccl);

	__mark_stack_read(env, ccl, frame, insn_idx, mask);
	return 0;
}

int bpf_update_live_stack(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_cc_liveness *ccl;
	int frame;

	for (frame = st->curframe; frame >= 0; --frame) {
		ccl = bpf_lookup_cc_liveness(env, env->cur_state, frame);
		if (IS_ERR(ccl))
			return PTR_ERR(ccl);

		if (!ccl->updated)
			break;

		__update_stack_liveness(env, ccl);
		ccl->updated = false;
	}
	return 0;
}

bool bpf_stack_can_be_read(struct bpf_verifier_env *env,
			   struct bpf_cc_liveness *ccl, u32 insn_idx, u32 spi)
{
	struct frame_liveness *il;

	il = get_insn_liveness(ccl, ccl->callchain.curframe, insn_idx);
	return il->live_before & BIT(spi);
}
