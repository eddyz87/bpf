/* Test cases for verifier.c:find_equal_scalars() and Co */

/* Use a map lookup as a way to get a pointer to some valid memory
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

/* Verify that check_ids() is used by regsafe() for scalars.
 *
 * r9 = ... some pointer with range X ...
 * r6 = ... unbound scalar ID=a ...
 * r7 = ... unbound scalar ID=b ...
 * if (r6 > r7) goto +1
 * r6 = r7
 * if (r6 > X) goto exit
 * r9 += r7
 * *(u64 *)r9 = Y
 */
{
	"scalar ids: ID mapping in regsafe()",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	/* r7 = ktime_get_ns() */
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/* r6 = ktime_get_ns() */
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/* if r6 > r7 goto +1 */
	BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 1),
	/* r6 = r7 */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_7),
	/* a noop to get to add new parent state */
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_0),
	/* if r6 >= 10 exit(0) */
	BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 10, 2),
	/* r9[r7] = 42 */
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_7),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	/* exit(0) */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Check that range information is propagated through a stack spill.
 *
 * r9 = ptr to 48 bytes   ; get some memory;
 * r0 = unknown u64       ; get some value with unknown range;
 * fp[-8] = r0            ; r0 range is unknown, thus no id link here
 * r5 = fp[-8]            ; r5 is compared down the flow, so an id link
 *                        ; between r5 and fp[-8] should be established;
 * if r5 > 40 exit        ; this clarifies range for both r5 and fp[-8];
 * r4 = fp[-8]
 * r9 += r4
 * *r9 = 42               ; safe because r4 range comes from fp[-8].
 * exit 0
 */
{
	"gen_id_hints: range info through a stack spill",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, -8),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_5, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.result = ACCEPT,
},
/*
 * Same as above, but range info is not propagated because
 * r5 is modified after read from stack.
 *
 * r9 = ptr to 48 bytes   ; get some memory;
 * r0 = unknown u64       ; get some value with unknown range;
 * fp[-8] = r0            ; r0 range is unknown, thus no id link here
 * r5 = fp[-8]            ; r5 is compared down the flow, but is modified
 * r5 -= 1                ; before that, thus no id link between r5 and fp[-8];
 * if r5 > 40 exit        ; this clarifies the range of r5 but not fp[-8];
 * r4 = fp[-8]
 * r9 += r4
 * *r9 = 42               ; unsafe because r4 range is unknown.
 * exit 0
 */
{
	"gen_id_hints: id link broken by reg modification",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, -8),
	BPF_ALU64_IMM(BPF_SUB, BPF_REG_5, 1),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_5, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Same as above, but range info is not propagated because
 * stack spill is modified.
 *
 * r9 = ptr to 48 bytes   ; get some memory;
 * r0 = unknown u64       ; get some value with unknown range;
 * fp[-8] = r0            ; r0 range is unknown, thus no id link here
 * r5 = fp[-8]            ; r0 is compared down the flow, thus
 *                        ; id link between r0 and fp[-8] is established;
 * if r5 > 40 exit        ; this clarifies the range of r0 but not fp[-8];
 * *fp[-8] = 777          ; modify fp[-8], thus breaking the link to r5
 * r4 = fp[-8]
 * r9 += r4
 * *r9 = 42               ; unsafe because r4 is out of range.
 * exit 0
 */
{
	"gen_id_hints: id link broken by stack modification",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_10, -8),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_5, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 777),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/*
 * Verify that stack spill range info is "non-sticky", e.g. could be
 * present for some branch and absent for another.
 *
 *  r9 = ptr to 48 bytes   ; get some memory;
 *  r0 = unknown u64       ; get some value with unknown range;
 *  fp[-8] = r0            ; r0 range is unknown, thus no id link here
 *  r6 = fp[-8]            ; r6 is compared down the flow, so an id link
 *                         ; between r6 and fp[-8] should be established;
 *  call ktime_get_ns
 *  if r0 < 7  goto foo    ; jump over r6 check
 *  if r6 > 40 exit        ; this clarifies range for both r6 and fp[-8];
 * foo:
 *  r4 = fp[-8]
 *  r9 += r4
 *  *r9 = 42               ; unsafe because fp[-8] range is not known
 *                         ; for some possible paths.
 *  exit 0
 */
{
	"gen_id_hints: absent range info for some execution paths",
	.insns = {
	MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
	BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, -8),
	BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 7, 3),
	BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 40, 2),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_4),
	BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.fixup_map_hash_48b = { 1 },
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/* Check that verifier.c:stacksafe() considers old and cur states not
 * identical when:
 * a. old state has STACK_SPILL mark with unbound scalar with ID
 *    used in find_equal_scalars();
 * b. new state has STACK_MISC  mark at the same position.
 *
 * Use fp[-8] for marks, use ktime_get_ns() to get unbound scalar,
 * use probe_read_kernel(&fp[-8], ...) to get STACK_MISC.
 * This example has two verification paths:
 * - 0-28, verified first, STACK_SPILL at fp[-8];
 * - 0-14,23-28,15-22, verified second, STACK_MISC at fp[-8].
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (19).
 * In case if verifier does not distinguish between (a) and (b)
 * the second path would be considered safe upon jump to (19)
 * because of the checkpoint.
 */
{
	"scalar ids: unbound scalar with used id vs STACK_MISC",
	.insns = {
	/* 0-8 */ MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	/*        r7 = ktime_get_ns()				*/
	/*  9: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/* 10: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/* 11: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/* 12: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/* 13: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <23>				*/
	/* 14: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 8),
	/*        fp[-8] = r6					*/
	/* 15: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        r7 = fp[-8]					*/
	/* 16: */ BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_FP, -8),
	/*        ; for path #1 set r6.id = r7.id = fp[-8].id	*/
	/*        r6 = fp[-8]					*/
	/* 17: */ BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_FP, -8),
	/*        ; for path #1 establish range for r6 & r7	*/
	/*        ; for path #2 establish range only for r6	*/
	/*        if r6 >= 10 exit(0)				*/
	/* 18: */ BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 10, 2),
	/*        ; safe for first path				*/
	/*        ; unsafe for second path			*/
	/*        r9[r7] = 42					*/
	/* 19: */ BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_7),
	/* 20: */ BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	/*        exit(0)					*/
	/* 21: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 22: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_MISC			*/
	/*        call probe_read_kernel(&fp[-8], 8, 0)		*/
	/* 23: */ BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	/* 24: */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	/* 25: */ BPF_MOV64_IMM(BPF_REG_2, 8),
	/* 26: */ BPF_MOV64_IMM(BPF_REG_3, 0),
	/* 27: */ BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	/*        goto <17>					*/
	/* 28: */ BPF_JMP_A(-12),

	},
	.fixup_map_hash_48b = { 1 },
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/* Check that verifier.c:stacksafe() considers old and cur states not
 * identical when:
 * a. old state has STACK_SPILL mark with unbound scalar with ID
 *    used in find_equal_scalars();
 * b. new state has STACK_ZERO mark at the same position.
 *
 * Use fp[-8] for marks.
 * This example has two verification paths:
 * - 0-28, verified first, STACK_SPILL at fp[-8];
 * - 0-14,23-25,15-22, verified second, STACK_ZERO at fp[-8].
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (17).
 * In case if verifier does not distinguish between (a) and (b)
 * the second path would be considered safe upon jump to (17)
 * because of the checkpoint.
 */
{
	"scalar ids: unbound scalar with used id vs STACK_ZERO",
	.insns = {
	/* 0-8 */ MAKE_POINTER_TO_48_BYTES(BPF_REG_9),
	/*        r7 = ktime_get_ns()				*/
	/*  9: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/* 10: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/* 11: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/* 12: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/* 13: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <23>				*/
	/* 14: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 8),
	/*        fp[-8] = r6					*/
	/* 15: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        r7 = fp[-8]					*/
	/* 16: */ BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_FP, -8),
	/*        ; for path #1 set r6.id = r7.id = fp[-8].id	*/
	/*        r6 = fp[-8]					*/
	/* 17: */ BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_FP, -8),
	/*        ; for path #1 establish range for r6 & r7	*/
	/*        ; for path #2 establish range only for r6	*/
	/*        if r6 >= 10 exit(0)				*/
	/* 18: */ BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 10, 2),
	/*        ; safe for first path				*/
	/*        ; unsafe for second path			*/
	/*        r9[r7] = 42					*/
	/* 19: */ BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_7),
	/* 20: */ BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 42),
	/*        exit(0)					*/
	/* 21: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 22: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_ZERO			*/
	/*        r1 = 0					*/
	/*        fp[-8] = r1					*/
	/* 23: */ BPF_MOV64_IMM(BPF_REG_1, 0),
	/* 24: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, -8),
	/*        goto <17>					*/
	/* 25: */ BPF_JMP_A(-9),

	},
	.fixup_map_hash_48b = { 1 },
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr = "register with unbounded min value",
	.result = REJECT,
},
/* Check that verifier.c:stacksafe() considers old and cur states
 * identical when:
 * a. old state has STACK_SPILL mark with unbound scalar with ID
 *    *not* used in find_equal_scalars();
 * b. new state has STACK_MISC  mark at the same position.
 *
 * Use fp[-8] for marks, use ktime_get_ns() to get unbound scalar,
 * use probe_read_kernel(&fp[-8], ...) to get STACK_MISC.
 * This example has two verification paths:
 * - 0-9, verified first, STACK_SPILL at fp[-8];
 * - 0-5,10-15,7-9, verified second, STACK_MISC at fp[-8].
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (7).
 * If verifier considers (a) and (b) identical the second path would
 * be considered safe upon jump to (7) because of the checkpoint.
 */
{
	"scalar ids: unbound scalar with unused id vs STACK_MISC",
	.insns = {
	/*        r7 = ktime_get_ns()				*/
	/*  0: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  1: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/*  2: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  3: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/*  4: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <10>				*/
	/*  5: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 4),
	/*        ; set fp[-8] to STACK_SPILL			*/
	/*        fp[-8] = r6					*/
	/*  6: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        ; read fp[-8] to make sure it is preserved	*/
	/*        ; in the checkpoint.				*/
	/*        r6 = fp[-8]					*/
	/*  7: */ BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_FP, -8),
	/*        exit(0)					*/
	/*  8: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/*  9: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_MISC			*/
	/*        call probe_read_kernel(&fp[-8], 8, 0)		*/
	/* 10: */ BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	/* 11: */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	/* 12: */ BPF_MOV64_IMM(BPF_REG_2, 8),
	/* 13: */ BPF_MOV64_IMM(BPF_REG_3, 0),
	/* 14: */ BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	/*        goto <7>					*/
	/* 15: */ BPF_JMP_A(-9),

	},
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr_unpriv = "unknown func bpf_probe_read_kernel",
	.result_unpriv = REJECT,
	.errstr = "7: safe",
	.result = VERBOSE_ACCEPT,
},
/* Check that verifier.c:stacksafe() considers old and cur states
 * identical when:
 * a. old state has STACK_MISC  mark;
 * b. new state has STACK_SPILL mark with unbound scalar.
 *
 * Use fp[-8] for marks, use ktime_get_ns() to get unbound scalar,
 * use probe_read_kernel(&fp[-8], ...) to get STACK_MISC.
 * - 0-13, verified first, STACK_MISC at fp[-8];
 * - 0-5,14-15,11-13, verified second, STACK_SPILL at fp[-8].
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (7).
 * If verifier considers (a) and (b) identical the second path would
 * be considered safe upon jump to (7) because of the checkpoint.
 */
{
	"scalar ids: STACK_MISC vs unbound scalar",
	.insns = {
	/*        r7 = ktime_get_ns()				*/
	/*  0: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  1: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/*  2: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  3: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/*  4: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <14>				*/
	/*  5: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 8),
	/*        ; set fp[-8] to STACK_MISC			*/
	/*        call probe_read_kernel(&fp[-8], 8, 0)		*/
	/*  6: */ BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	/*  7: */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	/*  8: */ BPF_MOV64_IMM(BPF_REG_2, 8),
	/*  9: */ BPF_MOV64_IMM(BPF_REG_3, 0),
	/* 10: */ BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),
	/*        ; read fp[-8] to make sure it is preserved	*/
	/*        ; in the checkpoint.				*/
	/*        r6 = fp[-8]					*/
	/* 11: */ BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_FP, -8),
	/*        exit(0)					*/
	/* 12: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 13: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_SPILL			*/
	/*        fp[-8] = r6					*/
	/* 14: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        goto <6>					*/
	/* 15: */ BPF_JMP_A(-5),

	},
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr_unpriv = "unknown func bpf_probe_read_kernel",
	.result_unpriv = REJECT,
	.errstr = "11: safe",
	.result = VERBOSE_ACCEPT,
},
/* Check that verifier.c:stacksafe() considers old and cur states
 * identical when:
 * a. old state has STACK_SPILL mark for precise 0;
 * b. new state has STACK_ZERO mark.
 *
 * To implant a scalar 0 as a stack spill first spill a register to
 * stack, then verify that this register is 0. The range would be
 * transferred to stack spill via find_equal_scalars().
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (8).
 * If verifier considers (a) and (b) identical the second path would
 * be considered safe upon jump to (8) because of the checkpoint.
 */
{
	"scalar ids: STACK_SPILL 0P vs STACK_ZERO",
	.insns = {
	/*        r7 = ktime_get_ns()				*/
	/*  0: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  1: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/*  2: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  3: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/*  4: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <15>				*/
	/*  5: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 9),
	/*        ; set fp[-8] to STACK_SPILL			*/
	/*        fp[-8] = r6					*/
	/*  6: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        ; propagate fp[-8] == r6 == 0			*/
	/*        if r6 != 0 goto +exit				*/
	/*  7: */ BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 5),
	/*        ; use value from fp[-8] as an offset in mem 	*/
	/*        ; access to mark it precise.			*/
	/*        ; This point is reached either from 7 or 17,	*/
	/*        ; both states should be considered identical.	*/
	/*        r1 = r10					*/
	/*        r2 = fp[-8]					*/
	/*        r1 += r2					*/
	/*        r1 += -8					*/
	/*        r3 = *(u64*) r1				*/
	/*  8: */ BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	/*  9: */ BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_FP, -8),
	/* 10: */ BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	/* 11: */ BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
	/* 12: */ BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1, 0),
	/*        exit(0)					*/
	/* 13: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 14: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_ZERO and goto to <8>	*/
	/* 15: */ BPF_MOV64_IMM(BPF_REG_6, 0),
	/* 16: */ BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
	/* 17: */ BPF_JMP_A(-10),

	},
	.flags = BPF_F_TEST_STATE_FREQ,
	.errstr_unpriv = "register with unbounded min value",
	.result_unpriv = REJECT,
	.errstr = "8: safe",
	.result = VERBOSE_ACCEPT,
},
/* Check that verifier.c:stacksafe() considers old and cur states
 * identical when:
 * a. old state has STACK_SPILL mark for imprecise SCALAR_VALUE;
 * b. new state has STACK_ZERO mark.
 *
 * To implant a scalar 0 as a stack spill first spill a register to
 * stack, then verify that this register is 0. The range would be
 * transferred to stack spill via find_equal_scalars().
 * BPF_F_TEST_STATE_FREQ forces a checkpoint at (8).
 * If verifier considers (a) and (b) identical the second path would
 * be considered safe upon jump to (8) because of the checkpoint.
 */
{
	"scalar ids: STACK_SPILL imprecise SCALAR_VALUE vs STACK_ZERO",
	.insns = {
	/*        r7 = ktime_get_ns()				*/
	/*  0: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  1: */ BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
	/*        r6 = ktime_get_ns()				*/
	/*  2: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*  3: */ BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),
	/*        r0 = unbound scalar				*/
	/*  4: */ BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
	/*        ; both r6 & r7 are unbound => jump can't be	*/
	/*        ; predicted and generated verifier states are	*/
	/*        ; indistinguishable.				*/
	/*        if r6 > r7 goto <11>				*/
	/*  5: */ BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 5),
	/*        ; set fp[-8] to STACK_SPILL			*/
	/*        fp[-8] = r6					*/
	/*  6: */ BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_6, -8),
	/*        ; propagate fp[-8] == r6 == 42		*/
	/*        ; never mark r6 precise ignoring the value	*/
	/*        if r6 != 42 goto <9>				*/
	/*  7: */ BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 42, 1),
	/*        ; mark fp[-8] read				*/
	/*  8: */ BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_FP, -8),
	/*        exit(0)					*/
	/*  9: */ BPF_MOV64_IMM(BPF_REG_0, 0),
	/* 10: */ BPF_EXIT_INSN(),
	/*        ; set fp[-8] to STACK_ZERO and goto to <8>	*/
	/* 11: */ BPF_MOV64_IMM(BPF_REG_6, 0),
	/* 12: */ BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -8),
	/*        ; goto <8>					*/
	/* 13: */ BPF_JMP_A(-6),

	},
	.flags = BPF_F_TEST_STATE_FREQ,
	/* BPF_F_TEST_STATE_FREQ has no effect in unpriv mode	*/
	.errstr_unpriv = "",
	.errstr = "8: safe",
	.result = VERBOSE_ACCEPT,
},

#undef MAKE_POINTER_TO_48_BYTES
