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

struct dfs_state {
	u32 traversed:1;
	u32 next_succ:31;
};

struct loops_dfs {
	struct dfs_state *state;
	int *dfs_pos;
	int *stack;
};

static void mark_irreducible(struct bpf_verifier_env *env, int h)
{
	env->insn_aux_data[h].loop->irreducible = true;
}

static void add_backedge(struct bpf_verifier_env *env, int from, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop = aux[h].loop;
	int cnt = loop->backedges_cnt;

	if (cnt == MAX_BACKEDGES) {
		loop->backedges_overflow = true;
		return;
	}
	loop->backedges[cnt].from = from;
	loop->backedges[cnt].latch = -1;
	loop->backedges_cnt++;
}

static int mark_header(struct bpf_verifier_env *env, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;

	if (!aux[h].loop) {
		aux[h].loop = kvzalloc(sizeof(struct bpf_loop), GFP_KERNEL_ACCOUNT);
		if (!aux[h].loop)
			return -ENOMEM;
	}
	return 0;
}

static int assign_header(struct bpf_verifier_env *env, struct loops_dfs *dfs, int n, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int *dfs_pos = dfs->dfs_pos;
	int err, nh;

	/*
	 * printf("assign_header(n=%d, h=%d)\n", n, h);
	 */
	err = mark_header(env, h);
	if (err)
		return err;

	/* Don't encode self-loops, otherwise can't reflect loops nesting structure. */
	if (n == h)
		return 0;

	/* Make sure that loop headers up the chain are sorted by dfs_pos. */
	while (aux[n].loop_header != -1) {
		nh = aux[n].loop_header;
		if (nh == h)
			return 0;
		if (dfs_pos[nh] < dfs_pos[h]) {
			aux[n].loop_header = h;
			n = h;
			h = nh;
		} else {
			n = nh;
		}
	}
	aux[n].loop_header = h;
	return 0;
}

static bool is_cond_jmp_insn(struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);
	u8 opcode = BPF_OP(insn->code);

	if (class != BPF_JMP && class != BPF_JMP32)
		return false;

	switch (opcode) {
	case BPF_JEQ:
	case BPF_JGE:
	case BPF_JGT:
	case BPF_JLE:
	case BPF_JLT:
	case BPF_JNE:
	case BPF_JSET:
	case BPF_JSGE:
	case BPF_JSGT:
	case BPF_JSLE:
	case BPF_JSLT:
		return true;
	default:
		return false;
	}
}

int bpf_loop_at_index(struct bpf_verifier_env *env, u32 idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;

	return aux[idx].loop ? idx : aux[idx].loop_header;
}

static int find_dominating_condition(struct bpf_verifier_env *env, int n, int top)
{
	struct bpf_insn *insns = env->prog->insnsi;
	int *idoms = env->idoms;
	int common_dom, nloop;

	nloop = bpf_loop_at_index(env, n);
	common_dom = idoms_intersect(env, n, top);
	if (common_dom != top)
		return -1;
	while (n >= 0) {
		if (is_cond_jmp_insn(&insns[n]) && bpf_loop_at_index(env, n) == nloop)
			return n;
		if (n == top)
			break;
		n = idoms[n];
	}
	return -1;
}

/*
 * As described in "A New Algorithm for Identifying Loops in Decompilation" by Wei et al,
 * adapted to be non-recursive.
 */
static int compute_loops_in_subprog(struct bpf_verifier_env *env, struct loops_dfs *dfs, int subprog_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct dfs_state *state = dfs->state;
	int *dfs_pos = dfs->dfs_pos;
	int *stack = dfs->stack;
	int err, s, h, cur, stack_sz;
	struct bpf_iarray *succ;

	stack[0] = env->subprog_info[subprog_idx].start;
	state[0].traversed = true;
	state[0].next_succ = 0;
	dfs_pos[0] = 1;
	stack_sz = 1;
	do {
		cur = stack[stack_sz - 1];
		/*
		 * printf("cur=%d, next_succ=%d\n", cur, state[cur].next_succ);
		 */
		succ = bpf_insn_successors(env, cur);
		if (state[cur].next_succ == succ->cnt) {
			dfs_pos[cur] = 0;
			stack_sz--;
			/*
			 * printf("cur=%d, pop\n", cur);
			 */
			continue;
		}
		s = succ->items[state[cur].next_succ];
		if (!state[s].traversed) {
			/* Case A:  start -> ... -> cur -> s [unxplored] */
			/*
			 * printf("push %d\n", s);
			 */
			state[s].traversed = true;
			state[s].next_succ = 0;
			stack[stack_sz] = s;
			dfs_pos[s] = stack_sz + 1;
			stack_sz++;
			continue;
		}
		/* 's' is fully explored at this point */
		if (dfs_pos[s]) {
			/*
			 * start -> ... -> s -> cur --.
			 *                 ^          |
			 *                 '----------'
			 * Case B: 's' is in the current DFS path.
			 */
			err = assign_header(env, dfs, cur, s);
			if (err)
				return err;
			add_backedge(env, cur, s);
		} else if (aux[s].loop_header == -1) {
			/*
			 * start -> ... -> ... -> s -> ... -> end
			 *           |            ^
			 *           '---> cur ---'
			 * Case C: 's' is explored, not in the current DFS path,
			 * and not a part of any loop.
			 */
		} else if (dfs_pos[aux[s].loop_header]) {
			/*
			 *                 .----------------------.
			 *                 v                      |
			 * start -> ... -> h -> ... -> ... -> s --'
			 *                       |            ^
			 *	                 '---> cur ---'
			 * Case D: 's' is explored, not in current DFS path,
			 * but it's innermost loop header is.
			 */
			err = assign_header(env, dfs, cur, aux[s].loop_header);
			if (err)
				return err;
		} else {
			// case E
			h = aux[s].loop_header;
			mark_irreducible(env, h);
			/* can also mark 's' as reentry, but no need for now */
			while (aux[h].loop_header != -1) {
				h = aux[h].loop_header;
				if (dfs_pos[h]) {
					err = assign_header(env, dfs, cur, h);
					if (err)
						return err;
					break;
				}
				mark_irreducible(env, h);
			}
		}
		state[cur].next_succ++;
	} while (stack_sz);

	return 0;
}

int bpf_compute_loops(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, j, err = 0, len = env->prog->len;
	struct bpf_backedge *backedge;
	struct loops_dfs dfs = {};
	struct bpf_loop *loop;

	dfs.dfs_pos = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	dfs.state = kvcalloc(len, sizeof(struct dfs_state), GFP_KERNEL_ACCOUNT);
	dfs.stack = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!dfs.dfs_pos || !dfs.state || !dfs.stack) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < len; i++)
		aux[i].loop_header = -1;
	for (i = 0; i < env->subprog_cnt; i++) {
		err = compute_loops_in_subprog(env, &dfs, i);
		if (err)
			goto out;
	}
	/* find latches */
	for (i = 0; i < len; i++) {
		loop = aux[i].loop;
		if (!loop)
			continue;
		for (j = 0; j < loop->backedges_cnt; j++) {
			backedge = &loop->backedges[j];
			backedge->latch = find_dominating_condition(env, backedge->from, i);
		}
	}

out:
	kfree(dfs.dfs_pos);
	kfree(dfs.stack);
	kfree(dfs.state);
	return err;
}
