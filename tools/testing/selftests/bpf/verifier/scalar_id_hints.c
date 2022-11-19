/* Test cases for verifier.c:compute_id_gen_hints */

#include "linux/bpf.h"
#include "linux/filter.h"

/*
 * Use a map lookup as a way to get a pointer to some valid memory
 * location with size known to verifier.
 */
#define MAKE_POINTER_TO_48_BYTES(reg)			\
	BPF_MOV64_IMM(BPF_REG_0, 0),			\
	BPF_LD_MAP_FD(BPF_REG_1, 0),			\
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),		\
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),		\
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),		\
	BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),	\
	BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),		\
	BPF_EXIT_INSN(),				\
	BPF_MOV64_REG((reg), BPF_REG_0)

/* Produce some u64 value, exactly how is immaterial to the below tests. */
#define SET_R0_TO_UNKNOWN_U64() \
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns)

#define UNPRIV_REJECT_REASON "register with unbounded min value"

/*
 * Verify that id is assigned to a stack spill:
 * - get a block of memory of a known size (map entry);
 * - assign a random value to a register;
 * - spill a register to stack;
 * - do a comparison to get register range;
 * - read the spill to another register;
 * - use the second register to access memory, if id was assigned
 *   to spill the read would be marked safe.
 */
{
	"scalar stack spill ids: spill/register link",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.result = ACCEPT,
},
/*
 * Same as above, but the link between spill and register is broken by
 * a write to a register:
 * - get a block of memory of a known size (map entry);
 * - assign a random value to a register;
 * - spill a register to stack;
 * - reassign the register;
 * - do a comparison to get register range;
 * - read the spill to another register;
 * - use the second register to access memory, if id was assigned
 *   to spill the read would be marked safe.
 */
{
	"scalar stack spill ids: break spill/register link writing to reg",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Same as above, but the link between spill and register is broken by
 * a write to stack:
 * - get a block of memory of a known size (map entry);
 * - assign a random value to a register;
 * - spill a register to stack;
 * - reassign the stack;
 * - do a comparison to get register range;
 * - read the spill to another register;
 * - use the second register to access memory, if id was assigned
 *   to spill the read would be marked safe.
 */
{
	"scalar stack spill ids: break spill/register link writing to stack",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Verify that id is assigned to a stack spill in a chain of assignments:
 * - get a block of memory of a known size (map entry);
 * - r0 = a random value;
 * - fp[-8] = r0;
 * - r1 = fp[-8]
 * - fp[-16] = r1
 * - r2 = fp[-16]
 * - verify range for r1
 * - memory access via r0, r2 should be safe.
 */
{
	"scalar stack spill ids: spill/register chain shares same range",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	/* setup chain */
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -16),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -16),
	/* verify range */
	BPF_JMP_IMM(BPF_JLT, BPF_REG_1, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	/* access mem using r0 as an offset */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_0),
	BPF_ST_MEM(BPF_DW, BPF_REG_8, 0, 42),
	/* access mem using r1 as an offset */
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_2),
	BPF_ST_MEM(BPF_DW, BPF_REG_7, 0, 42),
	/* exit 0 */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.result = ACCEPT,
},
/*
 * Verify that link is established for two register spills in parallel:
 * - get a block of memory of a known size (map entry);
 * - r6 = a random value;
 * - r7 = a random value;
 * - fp[-8] = r6;
 * - fp[-16] = r7;
 * - r1 = fp[-8];
 * - r2 = fp[-16];
 * - verify range for r6, r7;
 * - memory access via r1, r2 should be safe.
 */
{
	"scalar stack spill ids: two spill/register links",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16),

	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -16),

	/* verify range */
	BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_7, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* access mem using r1 as an offset */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_1),
	BPF_ST_MEM(BPF_DW, BPF_REG_8, 0, 42),
	/* access mem using r2 as an offset */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_2),
	BPF_ST_MEM(BPF_DW, BPF_REG_8, 0, 42),
	/* exit 0 */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.result = ACCEPT,
},
/*
 * Same as above, but skip the last range check to force an error.
 */
{
	"scalar stack spill ids: two spill/register links, skip one range check",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	SET_R0_TO_UNKNOWN_U64(),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16),

	BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -16),

	/* verify range */
	BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),

	/* access mem using r1 as an offset */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_1),
	BPF_ST_MEM(BPF_DW, BPF_REG_8, 0, 42),
	/* access mem using r2 as an offset */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_9),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_8, BPF_REG_2),
	BPF_ST_MEM(BPF_DW, BPF_REG_8, 0, 42),
	/* exit 0 */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = UNPRIV_REJECT_REASON,
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Verify that STACK_MISC in the old state is considered equivalent to
 * STACK_SPILL of unbound scalar in the new state by verifier.c:stacksafe.
 *
 *   r0 = ktime_get_ns()       ; mark r0 as unbound scalar;
 *   fp[-8] = r0               ; mark fp[-8] as STACK_SPILL;
 *   r0 = ktime_get_ns()       ; get another random value;
 *   if r0 > 7 goto skip_probe ; create a branch;
 *   r1 = r10
 *   r1 -= 8                   ; pass a pointer to fp[-8] as a first param,
 *   r2 = 8		       ; this forces verifier.c:check_helper_call to mark
 *   r3 = 0		       ; fp[-8] as STACK_MISC;
 *   call bpf_probe_read_user
 * skip_probe:                 ; two execution paths converge here,
 *   r5 = fp[-8] ;*            ; 1st with fp[-8] marked MISC, 2nd with fp[-8] marked SPILL,
 *   r0 = 0                    ; verify that these paths are considered equivalent
 *   exit                      ; by checking verbose execution log.
 *
 * *r5 = fp[-8] is need to mark fp[-8] live.
 */
{
	"scalar stack spill ids: MISC equivalent to SPILL for unbound scalars",
	.insns = {
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_0, 7, 5),

	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_2, 8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),

	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, -8),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
        .errstr_unpriv = "unknown func bpf_probe_read_kernel",
	.result_unpriv = REJECT,
	.errstr = "from 3 to 9: safe",
	.result = VERBOSE_ACCEPT,
},
/*
 * Verify that STACK_SPILL for unbound scalars is rewritten to
 * STACK_MISC for branch-less states that reached exit.
 * See verifier.c:scratch_spilled_unbound_scalars.
 *
 *   r1 = r10
 *   r1 -= 8                   ; pass a pointer to fp[-8] as a first param,
 *   r2 = 8		       ; this forces verifier.c:check_helper_call to mark
 *   r3 = 0		       ; fp[-8] as STACK_MISC;
 *   call bpf_probe_read_user
 *   r0 = ktime_get_ns()       ; mark r0 as unbound scalar;
 *   if r0 > 7 goto skip_write ; create a branch;
 *   r0 = ktime_get_ns()       ; get another unbound value;
 *   fp[-8] = r0               ; mark fp[-8] as STACK_SPILL;
 *   ... noops ...             ; needed because of the cutoff in verifier.c:is_state_visited;
 * skip_write:                 ; two execution paths converge here,
 *   r5 = fp[-8] ;*            ; 1st with fp[-8] marked MISC, 2nd with fp[-8] marked SPILL,
 *   r0 = 0                    ; verify that these paths are considered equivalent
 *   exit                      ; by checking verbose execution log.
 *
 * *r5 = fp[-8] is need to mark fp[-8] live.
 *
 * Note, that the first path to reach r5 has fp[-8] marked as STACK_SPILL,
 * however verifier.c:scratch_spilled_unbound_scalars changes this mark to
 * STACK_MISC when 'exit' instruction is reached.
 */
{
	"scalar stack spill ids: MISC equivalent to SPILL for unbound scalars",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_2, 8),
	BPF_MOV64_IMM(BPF_REG_3, 0),
	BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),

	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_JMP_IMM(BPF_JGT, BPF_REG_0, 7, 10),        /* 6, jump to 17 */

	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),

	/* 6 noops and 2 jumps to force new state */
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_0, 0),
	BPF_JMP_REG(BPF_JGT, BPF_REG_0, BPF_REG_0, 0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),

	/* read fp[-8] to mark it live */
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, -8), /* 17 */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
        .errstr_unpriv = "unknown func bpf_probe_read_kernel",
	.result_unpriv = REJECT,
	.errstr = "from 6 to 17: safe",
	.result = VERBOSE_ACCEPT,
},

#undef MAKE_POINTER_TO_48_BYTES
#undef SET_R0_TO_UNKNOWN_U64
#undef UNPRIV_REJECT_REASON
