.. SPDX-License-Identifier: GPL-2.0

Postfix exception cleanups
=========================

An exception cleanup is attached to a call by the immediately following
instruction::

        call foo
        unwind cleanup
        ... normal continuation ...

UNWIND is an eight-byte instruction with code BPF_JMP | BPF_UNWIND | BPF_X
(0xfd). The X bit distinguishes it from the kernel's internal tail-call
instruction; it does not select a register operand. The register fields
and imm must be zero. Its signed 16-bit off selects instruction PC + 1 + off,
in eight-byte slots, within the same subprogram.

On normal return the modifier falls through. On exceptional return its
target runs with the owning frame's stack and callee-saved registers. The
cleanup ends with bpf_unwind_resume(), which continues unwinding outward.
A call without a modifier has no local cleanup, but may still throw.

The modifier is a static association, not a dynamically installed handler.
The verifier checks cleanup execution as part of its normal state exploration.
The kernel retains modifiers through instruction rewriting, extracts native
cleanup metadata before JIT compilation, and emits no runtime conditional
branch for UNWIND. Programs using cleanup require a supporting JIT.
