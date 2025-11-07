#include <linux/bpf_verifier.h>

/*
 * - assign preorder numbers to instructions
 * - worklist (heap):
 *   - sort by loop level (maximal first)
 *   - sort by preorder (minimal first)
 * - cached states:
 *   - hash table (call string, insn-idx) -> acc-state
 *   - acc-state for each insn with multiple predecessors
 *   - join function for acc-state
 *   - widening function for backedges
 * - main iteration loop.
 */
struct item {
	struct bpf_verifier_state *state;
	u32 preorder_num;
	u16 loop_level;
	u16 curframe;
};

/* A binary min-heap */
struct bpf_worklist {
	struct item *items;
	int capacity;
	int count;
};

static int left_child(int i) { return 2 * i + 1; }
static int right_child(int i) { return 2 * i + 2; }
static int parent(int i) { return (i - 1) / 2; }

static int get_loop_level(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int level;

	level = 0;
	if (aux[idx].loop)
		level += 1;
	while (aux[idx].loop_header != -1) {
		idx = aux[idx].loop_header;
		level++;
	}
	return level;
}

static struct item item_from_state(struct bpf_verifier_env *env, struct bpf_verifier_state *state)
{
	int insn_idx = state->insn_idx;

	return (struct item) {
		.state = state,
		.preorder_num = env->cfg.preorder_nums[insn_idx],
		/* TODO: handle loop-like helper calls, e.g. bpf_loop(). */
		.loop_level = get_loop_level(env, insn_idx),
		.curframe = state->curframe,
	};
}

/*
 * For min-heap 'rhs' will have priority over 'lhs' if 'lhs > rhs'.
 * Basically, return true if 'rhs' has priority.
 */
static bool gt(struct item *lhs, struct item *rhs)
{
	/*
	 * Mimick Bourdoncle components iteration order w/o explicitly
         * recording the sequence:
	 * - finish innermost loops first;
	 * - within a same loop level, traverse in preorder.
	 *
	 * See "Efficient chaotic iteration strategies with widenings.", by F. Bourdoncle.
	 *
	 * TODO: borrow example from https://pages.cs.wisc.edu/~elder/stuff/bourdoncle.pdf .
	 */
	if (rhs->curframe > lhs->curframe)
		return true;
	if (rhs->curframe == lhs->curframe &&
	    rhs->loop_level > lhs->loop_level)
		return true;
	if (rhs->curframe == lhs->curframe &&
	    rhs->loop_level == lhs->loop_level &&
	    rhs->preorder_num < lhs->preorder_num)
		return true;
	return false;
}

static void sink_root(struct bpf_worklist *wl)
{
	struct item *items = wl->items;
	int i = 0;

	for (;;) {
		int left_gt_parent  = left_child(i)  < wl->count && gt(&items[i], &items[left_child(i)]);
		int right_gt_parent = right_child(i) < wl->count && gt(&items[i], &items[right_child(i)]);
		int sink_left;


		if (!left_gt_parent && !right_gt_parent)
			break;

		if (left_gt_parent && !right_gt_parent) {
			/* left > parent > right */
			sink_left = 1;
		} else if (!left_gt_parent && right_gt_parent) {
			/* left < parent < right */
			sink_left = 0;
		} else {
			/* left > parent && right > parent */
			if (gt(&items[right_child(i)], &items[left_child(i)]))
				sink_left = 1;
			else
				sink_left = 0;
		}

		if (sink_left) {
			swap(items[i], items[left_child(i)]);
			i = left_child(i);
		} else {
			swap(items[i], items[right_child(i)]);
			i = right_child(i);
		}

	}
}

struct bpf_verifier_state *bpf_worklist_pop(struct bpf_worklist *wl)
{
	struct bpf_verifier_state *result;
	struct item *items = wl->items;

	if (wl->count == 0)
		return NULL;

	result = items[0].state;
	items[0] = items[--wl->count];
	if (wl->count > 0)
		sink_root(wl);
	return result;
}

int bpf_worklist_push(struct bpf_verifier_env *env, struct bpf_worklist *wl, struct bpf_verifier_state *state)
{
	int i, new_capacity;
	struct item *items;
	void *tmp;

	if (wl->count == wl->capacity) {
		new_capacity = (wl->capacity * 2) ?: 32;
		tmp = kvrealloc(wl->items, new_capacity, GFP_KERNEL_ACCOUNT);
		if (!tmp)
			return -ENOMEM;
		wl->items = tmp;
		wl->capacity = new_capacity;
	}

	i = wl->count;
	items = wl->items;
	items[i] = item_from_state(env, state);
	wl->count++;
	while (i != 0 && gt(&items[parent(i)], &items[i])) {
		swap(items[i], items[parent(i)]);
		i = parent(i);
	}
	return 0;
}

struct bpf_worklist *bpf_worklist_new(void)
{
	return kzalloc(sizeof(struct bpf_worklist), GFP_KERNEL_ACCOUNT);
}

void bpf_worklist_free(struct bpf_worklist *wl)
{
	kfree(wl->items);
	kfree(wl);
}
