"""Check that the two-trace verifier rejects plausible but wrong merges (synthetic ASTs, no trace replay)."""
from pathlib import Path
import unittest

from triton import ARCH, Instruction, TritonContext

import merge

SPEC = merge.SAMPLES["sample5"]
BASE = 0x7FFFFFFFE090


class MergeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.ctx = TritonContext(ARCH.X86_64)
        self.variables = [self.ctx.symbolizeRegister(self.ctx.registers.edi, "x"),
                          self.ctx.symbolizeRegister(self.ctx.registers.esi, "y")]
        self.ast = self.ctx.getAstContext()
        self.x, self.y = (self.ast.variable(v) for v in self.variables)
        # A VMProtect-style virtual branch: the next VIP is loaded from one of two stack slots.
        self.lea = self.ast.ite(self.x + self.y == 1001, self.ast.bv(BASE, 64), self.ast.bv(BASE + 8, 64))

    def path(self, name, inputs, result, lea=None):
        lea = self.lea if lea is None else lea
        merge.evaluate(self.ctx, self.variables, lea, *inputs)
        site = merge.Site(100, 0x85BBBE, "mov rax, qword ptr ss:[rdx]", lea,
                          merge.evaluate(self.ctx, self.variables, lea, *inputs))
        return merge.PathResult(Path(name), inputs, 1, result, [site])

    def verify(self, path1, path2):
        return merge.merge_and_verify(self.ctx, self.variables, path1, path2,
                                      SPEC["oracle"], SPEC["reference"], SPEC["edges"])

    def correct_paths(self):
        return (self.path("t1", (4, 5), self.y - 1), self.path("t2", (1000, 1), self.x + 1))

    def test_correct_merge_passes(self):
        _, lines = self.verify(*self.correct_paths())
        self.assertIn("SMT: merged != C source is UNSAT, for 32-bit x/y", lines)

    def test_swapped_path_results_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "differs from the C source"):
            self.verify(self.path("t1", (4, 5), self.x + 1), self.path("t2", (1000, 1), self.y - 1))

    def test_two_traces_on_the_same_side_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "complement"):
            self.verify(self.path("t1", (4, 5), self.y - 1), self.path("t2", (7, 8), self.y - 1))

    def test_three_way_dispatch_needs_more_traces(self):
        three = self.ast.ite(self.x == 0, self.ast.bv(BASE + 16, 64), self.lea)
        with self.assertRaisesRegex(ValueError, "more than two values"):
            self.verify(self.path("t1", (4, 5), self.y - 1, three), self.path("t2", (1000, 1), self.x + 1, three))

    def test_missing_or_extra_branch_sites_are_rejected(self):
        path1, path2 = self.correct_paths()
        path1.sites = []
        with self.assertRaisesRegex(ValueError, "exactly one virtual branch"):
            self.verify(path1, path2)
        path1, path2 = self.correct_paths()
        path2.sites.append(path2.sites[0])
        with self.assertRaisesRegex(ValueError, "exactly one virtual branch"):
            self.verify(path1, path2)

    def test_condition_must_hold_for_the_traces_own_inputs(self):
        path1, path2 = self.correct_paths()
        path1.sites[0].value = BASE  # claims trace 1 took the other slot
        with self.assertRaisesRegex(ValueError, "do not satisfy"):
            self.verify(path1, path2)

    def test_different_branch_instructions_are_rejected(self):
        path1, path2 = self.correct_paths()
        path2.sites[0].address = 0x123456
        with self.assertRaisesRegex(ValueError, "Virtual branch differs"):
            self.verify(path1, path2)


class TritonApiAssumptionTests(unittest.TestCase):
    """Pin the triton-library behaviours the replayer depends on (the sample4 root cause)."""

    def setUp(self):
        self.ctx = TritonContext(ARCH.X86_64)
        self.ast = self.ctx.getAstContext()
        self.x = self.ast.variable(self.ctx.newSymbolicVariable(64, "x"))
        from triton import MemoryAccess
        self.cell = MemoryAccess(0x1000, 8)
        self.ctx.assignSymbolicExpressionToMemory(self.ctx.newSymbolicExpression(self.x | 0x202), self.cell)

    def test_set_concrete_memory_discards_the_ast(self):
        self.ctx.setConcreteMemoryValue(self.cell, 0x202)
        self.assertFalse(self.ctx.getMemoryAst(self.cell).isSymbolized())

    def test_assign_after_set_keeps_the_corrected_ast(self):
        # The replayer's order: concrete value first, then the corrected expression.
        self.ctx.setConcreteMemoryValue(self.cell, 0x202)
        corrected = self.ast.bvand(self.x | 0x202, self.ast.bv(~0x10 & (2**64 - 1), 64))
        self.ctx.assignSymbolicExpressionToMemory(self.ctx.newSymbolicExpression(corrected), self.cell)
        self.assertTrue(self.ctx.getMemoryAst(self.cell).isSymbolized())

    def test_register_ast_is_the_reliable_dependency_test(self):
        from triton import Instruction
        self.ctx.setConcreteRegisterValue(self.ctx.registers.rbx, 0x1000)
        self.ctx.processing(Instruction(0x2000, bytes.fromhex("488B03")))  # mov rax, [rbx]
        self.assertTrue(merge.depends_on_input(self.ctx.getRegisterAst(self.ctx.registers.rax)))


class UndefinedFlagTableTests(unittest.TestCase):
    def flags(self, opcode, count=1):
        ctx = TritonContext(ARCH.X86_64)
        instruction = Instruction(0x1000, bytes.fromhex(opcode))
        ctx.disassembly(instruction)
        return merge.undefined_flags(instruction, count)

    def test_sdm_undefined_flags(self):
        bits = merge.FLAG_BITS
        self.assertEqual(self.flags("4885C0"), bits["af"])                       # test rax, rax
        self.assertEqual(self.flags("4839C8"), 0)                                # cmp rax, rcx: all defined
        self.assertEqual(self.flags("48D1E0", 1), bits["af"])                    # shl rax, 1
        self.assertEqual(self.flags("48C1E004", 4), bits["af"] | bits["of"])     # shl rax, 4
        self.assertEqual(self.flags("48C1E000", 0), 0)                           # shl rax, 0: no flag change
        self.assertEqual(self.flags("480FA3C8"),                                 # bt rax, rcx
                         bits["of"] | bits["sf"] | bits["af"] | bits["pf"])


if __name__ == "__main__":
    unittest.main()
