#include <linux/slab.h>
#include <linux/bpf_verifier.h>

#define iarray_for_each(item, arr)						\
	for (int ___idx = 0;							\
	     ___idx < (arr)->cnt && ({ item = (arr)->items[___idx]; 1; });	\
	     ___idx++)

static struct bpf_iarray **compute_predecessors(struct bpf_verifier_env *env)
{
	struct bpf_iarray *succ, *preds, **result;
	struct bpf_prog *prog = env->prog;
	u32 *num_preds, i, s, sz, len = prog->len;
	struct bpf_insn *insn;
	void *tmp;

	num_preds = kvcalloc(prog->len, sizeof(u32), GFP_KERNEL_ACCOUNT);
	if (!num_preds)
		return NULL;

	/*
	 * 'result' layout:
	 *  - array of pointers (struct bpf_iarray *)[len]
	 *  - struct bpf_iarray one after another
	 */
	sz = sizeof(struct bpf_iarray) * len;
	sz += sizeof(struct bpf_iarray *) * len;
	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		sz += sizeof(u32) * succ->cnt;
		iarray_for_each(s, succ) {
			num_preds[s]++;
		}
		if (bpf_is_ldimm64(insn))
			i++;
	}

	result = kvzalloc(sz, GFP_KERNEL_ACCOUNT);
	if (!result) {
		kfree(num_preds);
		return NULL;
	}

	tmp = (void *)&result[len];
	for (i = 0; i < len; i++) {
		result[i] = tmp;
		tmp += sizeof(struct bpf_iarray);
		tmp += sizeof(u32) * num_preds[i];
	}

	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		iarray_for_each(s, succ) {
			preds = result[s];
			preds->items[preds->cnt++] = i;
		}
		if (bpf_is_ldimm64(insn))
			i++;
	}

	kfree(num_preds);
	return result;
}

static int idoms_intersect(struct bpf_verifier_env *env, int a, int b)
{
	int *postorder_nums = env->cfg.postorder_nums;
	int *idoms = env->idoms;

	while (a != b) {
		while (postorder_nums[a] < postorder_nums[b]) {
			a = idoms[a];
		}
		while (postorder_nums[b] < postorder_nums[a]) {
			b = idoms[b];
		}
	}
	return a;
}

/* See "A Simple, Fast Dominance Algorithm" by Cooper et al. for details. */
static void compute_subprog_idoms(struct bpf_verifier_env *env, struct bpf_iarray **preds, int subprog_idx)
{
	struct bpf_subprog_info *subprog = &env->subprog_info[subprog_idx];
	int start = subprog->start;
	int po_first = subprog->postorder_start;
	int po_last = (subprog + 1)->postorder_start - 1;
	int *idoms = env->idoms;
	int po_num, pred;
	bool changed;

	idoms[start] = 0;
	changed = true;
	do {
		changed = false;
		/* iterate in reverse postorder */
		for (po_num = po_last; po_num >= po_first; po_num--) {
			int idx = env->cfg.insn_postorder[po_num];
			int new_idom = -1;

			iarray_for_each(pred, preds[idx]) {
				/*
				 * fprintf(stderr, "compute_subprog_idoms: idx=%d, idoms[%d]=%d, new_idom=%d\n",
				 * 	idx, pred, idoms[pred], new_idom);
				 */
				if (idoms[pred] == -1)
					continue;
				if (new_idom == -1)
					new_idom = pred;
				else
					new_idom = idoms_intersect(env, pred, new_idom);
			}
			if (new_idom != -1 && idoms[idx] != new_idom) {
				/*
				 * fprintf(stderr, "compute_subprog_idoms: idoms[%d] = %d\n", idx, new_idom);
				 */
				idoms[idx] = new_idom;
				changed = true;
			}
		}
	} while (changed);
	idoms[start] = -1;
}

int bpf_compute_idoms(struct bpf_verifier_env *env)
{
	struct bpf_iarray **preds;
	u32 len = env->prog->len;
	int *idoms, i;

	preds = compute_predecessors(env);
	if (!preds)
		return -ENOMEM;

	idoms = kvcalloc(len, sizeof(*idoms), GFP_KERNEL_ACCOUNT);
	if (!idoms) {
		kfree(preds);
		return -ENOMEM;
	}

	env->idoms = idoms;
	for (i = 0; i < len; i++)
		idoms[i] = -1;

	for (i = 0; i < env->subprog_cnt; i++)
		compute_subprog_idoms(env, preds, i);

	kfree(preds);
	return 0;
}
