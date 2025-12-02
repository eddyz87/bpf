// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf_verifier.h>
#include <linux/jhash.h>
#include <linux/bug.h>

#define REGS_NUM (MAX_BPF_REG + 64)
#define UNKNOWN_EXPR_ID 0

// TODO: An alternative is to use bpf_insn as a whole, hijack the illegal opcode
//         { .code = (BPF_LD | BPF_W | BPF_IMM), .imm = <custom-opcode> }
//       for custom operations.
/*
 * BPF instructions use 'code', 'src_reg', 'off' and 'imm' fields for instruction encoding.
 * For scalar evolution purpose we want to reuse most of the opcode definitions,
 * but also add a few custom operations (REG and IMM).
 * To simplify matching instructions use a 2-byte representation:
 * - 1st byte for standard opcodes (bpf_insn->code field);
 * - 2nd byte for custom opcodes and opcodes that require additional 'bpf_insn' fields for encoding.
 * For now, only represent BPF_ALU{,64} class instructions and represent all operations
 * as having BPF_K source.
 */
enum expr_op {
	/* leave range 0..255 for standard bpf opcodes */
	UNKNOWN = 1 << 8, /* start custom opcodes from the second byte */
	REG     = 2 << 8,
	IMM     = 3 << 8,
	SDIV    = 4 << 8,
	SMOD    = 5 << 8,
	SEXT8   = 6 << 8,
	SEXT16  = 7 << 8,
	SEXT32  = 8 << 8,
	ZEXT32  = 9 << 8,
	BSWAP16 = 10 << 8,
	BSWAP32 = 11 << 8,
	BSWAP64 = 12 << 8,
	/*
	 * SCEV expression corresponding to linear equation 'param[0] + param[1] * k',
	 * where k is a loop iteration number. Loop here refers to innermost loop
	 * containing instruction associated with this expression, as returned by
	 * bpf_loop_at_index().
	 */
	LINEAR_SCEV = 13 << 8,
	/* This is like unknown, keep it separate for debugging purposes. */
	CYCLIC_SCEV = 14 << 8,
};

struct expr {
	u32 op;
	union {
		u32 params[2];
		s64 imm;
	};
};

struct expr_bucket {
	u32 cnt;
	u32 cap;
	u32 ids[];
};

struct env {
	bool empty;
	u32 reg2expr[REGS_NUM];
	u32 reg2scev[REGS_NUM]; // TODO: tracking up to 2 registers here should be sufficient
};

#define NUM_BUCKETS 256
#define EXPR_STACK_DEPTH 64

struct expr_stack_elt {
	u32 id:28;
	u32 pre:1;
	u32 next_param:2;
	u32 rewritten_params[2];
};

struct scev {
	/*
	 * Expressions are identified by id, exprs_ht ensures that
         * each expression exists as a unique instance.
	 * This allows for fast equivalence check: id1 === id2.
	 */
	struct expr_bucket *exprs_ht[NUM_BUCKETS]; // Don't want to add struct hlist_node to expr
	struct bpf_min_heap worklist;
	struct env **envs;
	struct expr *exprs;
	bool *discovered;
	int exprs_cnt;
	int exprs_cap;
	int envs_cnt;
	int stack_sz;
	struct expr_stack_elt expr_stack[EXPR_STACK_DEPTH];
	bool reg_on_stack[REGS_NUM];
	bool reg_discovered[REGS_NUM];
	u8 reg_postorder[REGS_NUM];
	int reg_postorder_cnt;
};

static void log_reg(struct bpf_verifier_env *env, u32 reg)
{
	if (reg < MAX_BPF_REG)
		bpf_log(&env->log, "r%d", reg);
	else
		bpf_log(&env->log, "sp%d", (MAX_BPF_REG - reg - 1) * 8);
}

static const char *op_str(u32 op)
{
	switch (op) {
	case BPF_ADD:  return "+";
	case BPF_SUB:  return "-";
	case BPF_MUL:  return "*";
	case BPF_DIV:  return "/";
	case SDIV:     return "s/";
	case BPF_OR:   return "|";
	case BPF_AND:  return "&";
	case BPF_LSH:  return "<<";
	case BPF_RSH:  return ">>";
	case BPF_NEG:  return "-";
	case BPF_MOD:  return "%";
	case SMOD:     return "s%";
	case BPF_XOR:  return "^";
	case BPF_ARSH: return "s>>";
	case SEXT8:    return "sext8";
	case SEXT16:   return "sext16";
	case SEXT32:   return "sext32";
	case ZEXT32:   return "zext32";
	case BSWAP16:  return "bswap16";
	case BSWAP32:  return "bswap32";
	case BSWAP64:  return "bswap64";
	}
	return NULL;
}

static u32 op_params_num(u32 op)
{
	switch (op) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_MUL:
	case BPF_DIV:
	case BPF_MOD:
	case BPF_OR:
	case BPF_XOR:
	case BPF_AND:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
	case SDIV:
	case SMOD:
		return 2;
	case BPF_NEG:
	case SEXT8:
	case SEXT16:
	case SEXT32:
	case ZEXT32:
	case BSWAP16:
	case BSWAP32:
	case BSWAP64:
		return 1;
	case REG:
	case IMM:
		return 0;
	default:
		return 0;
	}
}

static bool expr_stack_push(struct scev *scev, u32 id)
{
	if (scev->stack_sz >= EXPR_STACK_DEPTH)
		return false;
	scev->expr_stack[scev->stack_sz].id = id;
	scev->expr_stack[scev->stack_sz].pre = true;
	scev->expr_stack[scev->stack_sz].next_param = 0;
	scev->stack_sz++;
	return true;
}

enum {
	PRE = BIT(1), POST = BIT(2), DEPTH_LIMIT = BIT(3)
};

static bool expr_next(struct scev *scev, u32 *id, u32 *order)
{
	struct expr_stack_elt *elt;
	struct expr *expr;
	u32 num_params;

	if (scev->stack_sz == 0)
		return false;

	elt = &scev->expr_stack[scev->stack_sz - 1];
	*id = elt->id;
	*order = 0;
	expr = &scev->exprs[elt->id];
	num_params = op_params_num(expr->op);
	if (elt->pre) {
		elt->pre = false;
		*order = PRE;
		return true;
	}
	if (elt->next_param == num_params) {
		*order = POST;
		scev->stack_sz--;
		return true;
	}
	if (scev->stack_sz == EXPR_STACK_DEPTH) {
		*order = POST | DEPTH_LIMIT;
		scev->stack_sz--;
		return true;
	}
	expr_stack_push(scev, expr->params[elt->next_param]);
 	elt->next_param++;
	return expr_next(scev, id, order);
}

static void log_expr(struct bpf_verifier_env *env, u32 id)
{
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct expr *expr;
	const char *str;
	u32 order;

	scev->stack_sz = 0;
	expr_stack_push(scev, id);
	while (expr_next(scev, &id, &order)) {
		bpf_log(log, " ");
		expr = &scev->exprs[id];
		switch(expr->op) {
		case UNKNOWN:
			if (order & PRE)
				bpf_log(log, "?");
			break;
		case REG:
			if (order & PRE)
				log_reg(env, expr->params[0]);
			break;
		case IMM:
			if (order & PRE)
				bpf_log(log, "%lld", expr->imm);
			break;
		default:
			if (order & PRE) {
				str = op_str(expr->op);
				bpf_log(log, "(");
				if (str)
					bpf_log(log, "%s", str);
				else
					bpf_log(log, "bad-expr-op %x", expr->op);
			}
			if (order & DEPTH_LIMIT)
				bpf_log(log, "...");
			if (order & POST)
				bpf_log(log, ")");
		}
	}
}

static void print_env(struct bpf_verifier_env *env, struct env *e)
{
	struct bpf_verifier_log *log = &env->log;
	int i, num_unknown;

	if (e->empty) {
		bpf_log(log, " <empty>\n");
		return;
	}

	num_unknown = 0;
	for (i = 0; i < REGS_NUM; i++) {
		if (e->reg2expr[i] == UNKNOWN_EXPR_ID) {
			num_unknown++;
			continue;
		}
		bpf_log(log, " ");
		log_reg(env, i);
		bpf_log(log, "=");
		log_expr(env, e->reg2expr[i]);
	}
	if (num_unknown == REGS_NUM)
		bpf_log(log, " <all regs unknown>");
	bpf_log(log, "\n");
}

static u32 expr_hash(struct expr *e)
{
	return jhash_3words(e->op, e->params[0], e->params[1], 0);
}

static int expr_eq(struct expr *a, struct expr *b)
{
	return a->op == b->op && a->imm == b->imm;
}

static int add_expr(struct scev *scev, struct expr e)
{
	struct expr_bucket *bucket;
	u32 i, id, hash, new_cap;
	void *tmp;

	hash = expr_hash(&e) % NUM_BUCKETS;
	bucket = scev->exprs_ht[hash];

	if (bucket) {
		for (i = 0; i < bucket->cnt; i++) {
			id = bucket->ids[i];
			if (expr_eq(&e, &scev->exprs[id]))
				return id;
		}
	}

	if (!bucket || bucket->cap == bucket->cnt) {
		new_cap = bucket ? bucket->cap * 2 : 32; // TODO: small step? kvrealloc?
		bucket = krealloc(bucket, sizeof(*bucket) + sizeof(u32) * new_cap, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!bucket)
			return -ENOMEM;
		scev->exprs_ht[hash] = bucket;
		bucket->cap = new_cap;
	}

	if (scev->exprs_cnt == scev->exprs_cap) {
		new_cap = scev->exprs_cap + 256;
		tmp = kvrealloc(scev->exprs, sizeof(struct expr) * new_cap, GFP_KERNEL_ACCOUNT);
		if (!tmp)
			return -ENOMEM;
		scev->exprs = tmp;
		scev->exprs_cap = new_cap;
	}

	id = scev->exprs_cnt++;
	scev->exprs[id] = e;
	bucket->ids[bucket->cnt++] = id;
	return id;
}

static int expr2(struct scev *scev, u32 op, int a, int b)
{
	if (a < 0)
		return a;
	if (b < 0)
		return b;
	return add_expr(scev, (struct expr){ .op = op, .params = {a, b} });
}

static int expr1(struct scev *scev, u32 op, int a)
{
	if (a < 0)
		return a;
	return expr2(scev, op, a, 0);
}

static int expr0(struct scev *scev, u32 op)
{
	return expr2(scev, op, 0, 0);
}

static bool is_expr1(struct expr *expr, u32 op, int a)
{
	return expr->op == op && expr->params[0] == a;
}

static int imm_expr(struct scev *scev, s64 value)
{
	return add_expr(scev, (struct expr){ .op = IMM, .imm = value });
}

static bool same_exprs(struct scev *scev, int id_a, int id_b)
{
	return id_a == id_b;
}

static struct env *get_loop_env(struct scev *scev, int insn_idx)
{
	struct env *e;

	if (scev->envs[insn_idx])
		return scev->envs[insn_idx];

	e = kzalloc(sizeof(struct env), GFP_KERNEL_ACCOUNT);
	if (!e)
		return NULL;

	e->empty = true;
	scev->envs[insn_idx] = e;
	return e;
}

static void setup_initial_loop_env(struct bpf_verifier_env *env, struct env *e, int insn_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct scev *scev = env->scev;
	u64 live_spills_before = aux[insn_idx].live_spills_before;
	u16 live_regs_before = aux[insn_idx].live_regs_before;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (live_regs_before & BIT(i))
			e->reg2expr[i] = expr1(scev, REG, i);
	for (i = 0; i < 64; i++)
		if (live_spills_before & BIT(i))
			e->reg2expr[MAX_BPF_REG + i] = expr1(scev, REG, MAX_BPF_REG + i);
}

static int replace_reg(struct scev *scev, struct env *e, u32 reg, int id)
{
	if (id < 0)
		return id;
	e->reg2expr[reg] = id;
	return 0;
}

static void forget_call_regs(struct env *e)
{
	int i;

	for (i = BPF_REG_0; i <= BPF_REG_5; i++)
		e->reg2expr[i] = UNKNOWN_EXPR_ID;
}

__attribute__((optimize("O1")))
static int transfer(struct bpf_verifier_env *env, struct env *e, int idx)
{
	const bool little_endian = htons(0x3412) == 0x1234;
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	struct scev *scev = env->scev;
	u32 *reg2expr = e->reg2expr;
	u8 class = BPF_CLASS(insn->code);
	u8 opcode = BPF_OP(insn->code);
	u8 mode = BPF_SRC(insn->code);
	u32 dst = insn->dst_reg;
	u32 src = insn->src_reg;
	u32 op, sext;
	int i, id;
	s64 imm;

	switch (class) {
	case BPF_ALU:
	case BPF_ALU64:
		switch (opcode) {
		case BPF_MOV:
			switch (insn->off) {
			case 0: sext = 0; break;
			case 8: sext = SEXT8; break;
			case 16: sext = SEXT16; break;
			case 32: sext = SEXT32; break;
			default:
				goto mark_dst_unknown; // TODO: this should nuke state instead.
			}

			if (mode == BPF_X && insn->imm == 0)
				id = reg2expr[src];
			else if (mode == BPF_K && src == 0 && insn->off == 0)
				id = imm_expr(scev, insn->imm);
			else
				goto mark_dst_unknown;

			if (sext)
				id = expr1(scev, sext, id);
			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_ADD:
		case BPF_SUB:
		case BPF_MUL:
		case BPF_DIV:
		case BPF_MOD:
		case BPF_OR:
		case BPF_XOR:
		case BPF_AND:
		case BPF_LSH:
		case BPF_RSH:
		case BPF_ARSH:
			if (opcode == BPF_DIV && insn->off == 1)
				op = SDIV;
			else if (opcode == BPF_MOD && insn->off == 1)
				op = SMOD;
			else if (insn->off == 0)
				op = opcode;
			else
				goto mark_dst_unknown;

			if (mode == BPF_X && insn->imm == 0)
				id = reg2expr[src];
			else if (mode == BPF_K && src == 0)
				id = imm_expr(scev, insn->imm);
			else
				goto mark_dst_unknown;

			id = expr2(scev, op, reg2expr[dst], id);

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_NEG:
			if (src == 0 && insn->off == 0 && insn->imm == 0)
				id = expr1(scev, BPF_NEG, reg2expr[dst]);
			else
				goto mark_dst_unknown;

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, id);

			return replace_reg(scev, e, dst, id);

		case BPF_END:
			switch (insn->imm) {
			case 16: op = BSWAP16; break;
			case 32: op = BSWAP32; break;
			case 64: op = BSWAP64; break;
			default:
				goto mark_dst_unknown;
			}

			if (class == BPF_ALU && src == 0 && insn->off == 0 && little_endian)
				op = 0; /* little-endian to little-endian is noop */
			else if (class == BPF_ALU && src == 1 && insn->off == 0 && !little_endian)
				op = 0; /* big-endian to big-endian is noop */
			else if (class == BPF_ALU64 && src == 0 && insn->off == 0)
				/* always swap */;
			else
				goto mark_dst_unknown;

			id = reg2expr[dst];
			if (op)
				id = expr1(scev, op, reg2expr[dst]);

			if (class == BPF_ALU)
				id = expr1(scev, ZEXT32, reg2expr[dst]);

			return replace_reg(scev, e, dst, id);
		default:
			goto mark_dst_unknown;
		}
		break;
	case BPF_LDX:
		if (bpf_is_spill_base_ldx(insn)) {
			src = bpf_spill_base_idx(insn) + MAX_BPF_REG;
			return replace_reg(scev, e, dst, reg2expr[src]);
		}
		goto mark_dst_unknown;
	case BPF_STX:
		if (bpf_is_spill_base_stx(insn)) {
			dst = bpf_spill_base_idx(insn) + MAX_BPF_REG;
			return replace_reg(scev, e, dst, reg2expr[src]);
		}
		switch (BPF_MODE(insn->code)) {
		case BPF_MEM:
			/* no changes */
			break;
		case BPF_ATOMIC:
			switch (insn->imm) {
			case BPF_CMPXCHG:
				return replace_reg(scev, e, BPF_REG_0, UNKNOWN_EXPR_ID);
			case BPF_LOAD_ACQ:
				goto mark_dst_unknown;
			case BPF_STORE_REL:
				/* no changes */
				break;
			default:
				if (insn->imm & BPF_FETCH)
					return replace_reg(scev, e, src, UNKNOWN_EXPR_ID); // TODO: double-check
				break;
			}
			break;
		}
		break;
	case BPF_ST:
		/* no changes in register states */
		break;
	case BPF_JMP:
	case BPF_JMP32:
		if (opcode == BPF_CALL)
			forget_call_regs(e);
		/* for non-CALL there are no changes in register states */
		break;
	case BPF_LD:
		switch (mode) {
		case BPF_IMM:
			if (BPF_SIZE(insn->code) == BPF_DW) {
				imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
				return replace_reg(scev, e, dst, imm_expr(scev, imm));
			}
			goto mark_dst_unknown;
		case BPF_LD | BPF_ABS:
		case BPF_LD | BPF_IND:
			forget_call_regs(e); // TODO: double check
			break;
		default:
			goto mark_dst_unknown;
		}
		break;
	default:
		// unknown instruction, nuke state
		for (i = 0; i < REGS_NUM; i++)
			reg2expr[i] = UNKNOWN_EXPR_ID;
		break;
	}
	return 0;

mark_dst_unknown:
	reg2expr[dst] = UNKNOWN_EXPR_ID;
	return 0;
}

__attribute__((optimize("O1")))
static void join(struct scev *scev, struct env *acc, struct env *cur)
{
	int i;

	if (acc->empty) {
		memcpy(acc, cur, sizeof(*acc));
		acc->empty = false;
		return;
	}

	for (i = 0; i < REGS_NUM; i++) {
		if (!same_exprs(scev, acc->reg2expr[i], cur->reg2expr[i]))
			acc->reg2expr[i] = UNKNOWN_EXPR_ID;
	}
}

/* Mark any register modified in 'header_env' as unknown in 'acc'. */
__attribute__((optimize("O1")))
static void forget_non_invariants(struct scev *scev, struct env *acc, struct env *header_env)
{
	struct expr *header_expr;
	int i;

	if (acc->empty)
		acc->empty = false;

	for (i = 0; i < REGS_NUM; i++) {
		header_expr = &scev->exprs[header_env->reg2expr[i]];
		if (is_expr1(header_expr, REG, i))
			continue;
		acc->reg2expr[i] = UNKNOWN_EXPR_ID;
	}
}

static int worklist_push(struct scev *scev, int idx)
{
	int err;

	if (scev->discovered[idx])
		return 0;

	err = bpf_min_heap_push(&scev->worklist, idx);
	if (err)
		return err;

	scev->discovered[idx] = true;
	return 0;
}

__attribute__((optimize("O1")))
static int compute_scev_for_loop(struct bpf_verifier_env *env, int cur_header)
{
	struct env *cur_env, *succ_env, *before_env, *to_env, *nested_header_env;
	struct bpf_min_heap *worklist = &env->scev->worklist;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_verifier_log *log = &env->log;
	struct scev *scev = env->scev;
	struct bpf_loop_exit *exit;
	struct bpf_loop *nested_loop;
	struct bpf_iarray *succ;
	int s, e, err, idx, succ_idx;
	bool first;

	cur_env = kzalloc(sizeof(*cur_env), GFP_KERNEL_ACCOUNT);
	if (!cur_env) {
		err = -ENOMEM;
		goto out;
	}

	before_env = get_loop_env(scev, cur_header);
	if (!before_env) {
		err = -ENOMEM;
		goto out;
	}
	setup_initial_loop_env(env, before_env, cur_header);
	err = worklist_push(scev, cur_header);
	if (err)
		goto out;

	first = true;
	for (;;) {
		if (!bpf_min_heap_pop(worklist, &idx))
			break;

		before_env = get_loop_env(scev, idx);
		if (!before_env) {
			err = -ENOMEM;
			goto out;
		}

		if (log->level & BPF_LOG_LEVEL2) {
			bpf_log(log, "scev expr %d:", idx);
			print_env(env, before_env);
		}

		/* Iterate instructions within a single basic block starting at 'idx' mutating 'cur_env'. */
		memcpy(cur_env, scev->envs[idx], sizeof(*cur_env));
		for (;;) {
			err = transfer(env, cur_env, idx);
			if (err)
				goto out;
			succ = bpf_insn_successors(env, idx);
			if (succ->cnt != 1)
				break;
			succ_idx = succ->items[0];
			if (aux[idx].bb_end || aux[succ_idx].need_scev)
				break;
			idx = succ_idx;
		}

		succ = bpf_insn_successors(env, idx);
		for (s = 0; s < succ->cnt; s++) {
			succ_idx = succ->items[s];
			succ_env = get_loop_env(scev, succ_idx);
			if (!succ_env)
				goto nomem;
			/*
			 * For successors belonging to the same loop,
			 * do join(state at succ_idx, state at idx)
			 * and schedule furhter traversal.
			 */
			if (bpf_loop_at_index(env, succ_idx) == cur_header) {
				join(scev, succ_env, cur_env);
				err = worklist_push(scev, succ_idx);
				if (err)
					goto out;
				continue;
			}
			/*
			 * For edges to a nested loop:
			 * - assume whole nested loop to be a set of edges 'idx -> exit',
			 *   where 'exit' is a nested loop exit to_'cur_loop';
			 * - join state at 'exit' with state at 'idx';
			 * - at 'exit' forget anything non-invariant in the nested loop;
			 * - schedule traversal from 'exit'.
			 */
			// TODO: this check won't work for irreducible loops, instead:
			//       - check for bpf_is_nested_loop(aux[succ_idx].loop_header, cur_loop)
			//       - get topmost nested loop header for aux[succ_idx].loop_header
			//       - proceed with it as 'nested_loop'.
			if (aux[succ_idx].loop_header == cur_header) {
				nested_loop = aux[succ_idx].loop;
				nested_header_env = get_loop_env(scev, succ_idx);
				if (!nested_header_env)
					goto nomem;
				for (e = 0; e < nested_loop->exits_cnt; e++) {
					exit = &nested_loop->exits[e];
					// TODO: double-check, inner loop can't exit to our header, right?
					if (aux[exit->to].loop_header != cur_header)
						continue;
					to_env = get_loop_env(scev, exit->to);
					if (!to_env)
						goto nomem;
					join(scev, to_env, cur_env);
					forget_non_invariants(scev, to_env, nested_header_env);
					err = worklist_push(scev, exit->to);
					if (err)
						goto out;
				}
				continue;
			}
		}
	}

	if (log->level & (BPF_LOG_LEVEL2 | BPF_LOG_STATS)) {
		struct bpf_loop *loop = aux[cur_header].loop;
		int i, latch;

		bpf_log(log, "scev at header %d:", cur_header);
		print_env(env, scev->envs[cur_header]);
		for (i = 0; i < loop->backedges_cnt; i++) {
			latch = loop->backedges[i].latch;
			if (latch < 0)
				continue;
			bpf_log(log, " scev at latch %d:", latch);
			print_env(env, scev->envs[latch]);
			bpf_log(log, "      latch at %d: ", latch);
			bpf_verbose_insn(env, &env->prog->insnsi[latch]);
		}
	}

	err = 0;
out:
	kfree(cur_env);
	return err;
nomem:
	err = -ENOMEM;
	goto out;
}

static void mark_latches(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop;
	int len = env->prog->len;
	int i, j, latch;

	for (i = 0; i < len; i++) {
		loop = aux[i].loop;
		if (!loop)
			continue;
		for (j = 0; j < loop->backedges_cnt; j++) {
			latch = loop->backedges[j].latch;
			if (latch >= 0)
				aux[latch].need_scev = true;
		}
	}
}

static int compute_regs_postorder(struct bpf_verifier_env *env, struct env *header_env)
{
	u32 *reg2scev = header_env->reg2scev;
	struct scev *scev = env->scev;
	struct expr *expr;
	int i, j, r, id, order;

	scev->reg_postorder_cnt = 0;
	memset(scev->reg_on_stack, 0, REGS_NUM);
	memset(scev->reg_discovered, 0, REGS_NUM);
	for (i = 0; i < REGS_NUM; i++) {
		if (header_env->reg2expr[i] == UNKNOWN_EXPR_ID)
			continue;
		if (!scev->reg_discovered[i])
			continue;
		scev->stack_sz = 0;
		expr_stack_push(scev, header_env->reg2expr[i]);
		scev->reg_discovered[i] = true;
		scev->reg_on_stack[i] = true;
		while (expr_next(scev, &id, &order)) {
			expr = &scev->exprs[id];
			if (expr->op != REG)
				continue;
			r = expr->params[0];
			if ((order & PRE) && !scev->reg_discovered[r]) {
				expr_stack_push(scev, header_env->reg2expr[r]); // TODO: error case
				scev->reg_discovered[r] = true;
				continue;
			}
			if ((order & PRE) && scev->reg_on_stack[r]) {
				for (j = scev->stack_sz - 1; j >= 0; j--) {
					expr = &scev->exprs[scev->expr_stack[j].id];
					if (expr->op != REG)
						continue;
					reg2scev[expr->params[0]] = CYCLIC_SCEV;
					if (expr->params[0] == r)
						break;
				}
				continue;
			}
			if ((order & POST) && reg2scev[r] != CYCLIC_SCEV) {
				scev->reg_postorder[scev->reg_postorder_cnt++] = r;
				continue;
			}
			// TODO: what about depth limit?
		}
		scev->reg_on_stack[i] = false;
	}
	return 0;
}

static int transform_expr(struct scev *scev, u32 root,
			  int (*fn)(struct scev *scev, u32 id))
{
	int id, id1, order, num_params, rstack_cap, rstack_cnt;
	int *tmp, *rstack;
	struct expr *expr;

	// TODO: put this to scev and add a reasonable bound, e.g. EXPR_STACK_DEPTH * 2, avoid realloc.
	rstack_cnt = 0;
	rstack_cap = EXPR_STACK_DEPTH;
	rstack = kcalloc(EXPR_STACK_DEPTH, sizeof(*rstack), GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!rstack)
		return -ENOMEM;

	scev->stack_sz = 0;
	expr_stack_push(scev, root);
	while (expr_next(scev, &id, &order)) {
		if (!(order & POST))
			continue;

		expr = &scev->exprs[id];
		num_params = op_params_num(expr->op);
		switch (num_params) {
		case 0:
			break;
		case 1:
			id1 = expr1(scev, expr->op, rstack[rstack_cnt - 1]);
			break;
		case 2:
			id1 = expr2(scev, expr->op, rstack[rstack_cnt - 2], rstack[rstack_cnt - 1]);
			break;
		default:
			WARN_ONCE(1, "num_params == %d\n", num_params);
			id1 = -EFAULT;
			break;
		}
		id1 = id1 < 0 ?: fn(scev, id1);
		if (id1 < 0)
			goto out;
		rstack_cnt -= num_params;
		if (rstack_cnt == rstack_cap) {
			rstack_cap += EXPR_STACK_DEPTH;
			tmp = krealloc(rstack, sizeof(*rstack) * rstack_cap,
				       GFP_KERNEL_ACCOUNT | __GFP_ZERO);
			if (!tmp) {
				id1 = -ENOMEM;
				goto out;
			}
			rstack = tmp;
		}
		rstack[rstack_cnt++] = id1;
	}
	id1 = rstack[0];
out:
	kfree(rstack);
	return id1;
}

static int compute_header_scevs(struct bpf_verifier_env *env, struct env *header_env)
{
	struct scev *scev = env->scev;
	struct expr *a, *b, *expr, *exprs;
	int i, id, reg, err, a_id, b_id;

	exprs = scev->exprs;
	err = compute_regs_postorder(env, header_env);
	for (i = 0; i < scev->reg_postorder_cnt; i++) {
		reg = scev->reg_postorder[i];
		expr = &scev->exprs[header_env->reg2expr[reg]];
		a_id = expr->params[0];
		b_id = expr->params[1];
		a = &scev->exprs[a_id];
		b = &scev->exprs[b_id];
		/* rA = (+ rA IMM) */
		if (expr->op == BPF_ADD && a->op == REG && b->op == IMM && a->params[0] == reg) {
			id = expr2(scev, LINEAR_SCEV, a_id, b_id);
			if (id < 0)
				return id;
			header_env->reg2scev[reg] = id;
			continue;
		}
	}
	return 0;
}

static int compute_insn_scevs(struct bpf_verifier_env *env,
			      struct env *header_env,
			      struct env *insn_env)
{
	return 0;
}

int bpf_compute_scev(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct scev *scev = env->scev;
	int *postorder = env->cfg.insn_postorder;
	int cnt = env->cfg.cur_postorder;
	int i, idx, err, header;

	mark_latches(env);
	/*
	 * Visit loop headers in postorder, to guarantee that scevs
         * for innermost loops are computed first.
	 */
	for (i = 0; i < cnt; i++) {
		idx = postorder[i];
		if (!aux[idx].loop)
			continue;
		err = compute_scev_for_loop(env, idx);
		if (err)
			return err;
	}

	/*
	 * Compute scevs from exprs collected on a previous step. Iterate instructions in
	 * reverse post-order so that each loop header is processed before instructions
	 * reachable from it.
	 */
	for (i = cnt - 1; i >= 0; i--) {
		idx = postorder[i];
		header = bpf_loop_at_index(env, idx);
		if (header < 0)
			continue;

		err = header == i
		      ? compute_header_scevs(env, scev->envs[i])
		      : compute_insn_scevs(env, scev->envs[header], scev->envs[i]);
		if (err)
			return err;
	}

	return 0;
}

static int reverse_ranked_compare(int a, int b, void *arg)
{
	int *rank = arg;

	return rank[b] - rank[a];
}

void bpf_free_scev(struct bpf_verifier_env *env)
{
	struct scev *scev = env->scev;
	int i;

	if (!scev)
		return;
	for (i = 0; i < scev->envs_cnt; i++)
		kfree(scev->envs[i]);
	for (i = 0; i < ARRAY_SIZE(scev->exprs_ht); i++)
		kfree(scev->exprs_ht[i]);
	kvfree(scev->envs);
	kvfree(scev->exprs);
	kvfree(scev->discovered);
	kfree(scev);
	env->scev = NULL;
}

int bpf_init_scev(struct bpf_verifier_env *env)
{
	struct scev *scev;

	scev = kzalloc(sizeof(struct scev), GFP_KERNEL_ACCOUNT);
	if (!scev)
		return -ENOMEM;
	env->scev = scev;
	/* Order worklist in reverse post-order. */
	bpf_min_heap_init(&scev->worklist, reverse_ranked_compare, env->cfg.postorder_nums);
	if (expr0(scev, UNKNOWN) < 0)
		goto nomem;
	/*
	 * Remember original program length, in case bpf_free_scev()
         * is called after bpf program rewrites that increase program
         * length.
	 */
	scev->envs_cnt = env->prog->len;
	scev->envs = kvcalloc(env->prog->len, sizeof(*scev->envs), GFP_KERNEL_ACCOUNT);
	scev->discovered = kvcalloc(env->prog->len, sizeof(*scev->discovered), GFP_KERNEL_ACCOUNT);
	if (!scev->envs || !scev->discovered)
		goto nomem;
	return 0;
nomem:
	bpf_free_scev(env);
	return -ENOMEM;
}
