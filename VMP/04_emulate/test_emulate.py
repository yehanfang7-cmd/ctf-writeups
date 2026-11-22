"""Unit 04 checks: flag rules, the heap-key rule, and that the verifier rejects wrong or incomplete results."""
from pathlib import Path
import random
import unittest

from triton import ARCH, Instruction, TritonContext

import emulate

INPUTS = Path(__file__).resolve().parent / "inputs"


def have(*names):
    return all((INPUTS / n).exists() for n in names)


class FlagRuleTests(unittest.TestCase):
    def machine_for(self, code):
        env = emulate.Environment()
        machine = emulate.Machine.__new__(emulate.Machine)
        machine.ctx = TritonContext(ARCH.X86_64)
        machine.env, machine.written, machine.segments = env, set(), []
        machine.ctx.setConcreteMemoryAreaValue(0x1000, code)
        return machine

    def test_logical_instruction_clears_af(self):
        m = self.machine_for(bytes.fromhex("4885C0"))  # test rax, rax
        m.ctx.setConcreteRegisterValue(m.ctx.registers.af, 1)
        m.step(0x1000)
        self.assertEqual(m.ctx.getConcreteRegisterValue(m.ctx.registers.af), 0)

    def test_multiply_flags_follow_the_low_half(self):
        m = self.machine_for(bytes.fromhex("F7EA"))  # imul edx
        ctx = m.ctx
        ctx.setConcreteRegisterValue(ctx.registers.eax, 0x10000)
        ctx.setConcreteRegisterValue(ctx.registers.edx, 0x10000)  # product 2^32: eax = 0
        ctx.setConcreteRegisterValue(ctx.registers.zf, 0)
        m.step(0x1000)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.zf), 1)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.pf), 1)
        self.assertEqual(ctx.getConcreteRegisterValue(ctx.registers.sf), 0)

    def test_multiply_flags_stay_symbolic(self):
        m = self.machine_for(bytes.fromhex("0FAFC2"))  # imul eax, edx
        ctx = m.ctx
        ctx.symbolizeRegister(ctx.registers.eax, "x")
        ctx.setConcreteRegisterValue(ctx.registers.edx, 3)
        m.step(0x1000)
        self.assertTrue(ctx.getRegisterAst(ctx.registers.zf).isSymbolized())


@unittest.skipUnless(have("sample4.vmp.bin", "sample4.vmp.trace.1", "sample4.vmp.trace.2",
                          "sample6.vmp.bin", "sample6.vmp.trace.1", "sample6.vmp.trace.2"),
                     "run python VMP/04_emulate/emulate.py once to fetch inputs")
class EnvironmentTests(unittest.TestCase):
    def test_keyed_heap_dword_is_pointer_xor_constant(self):
        for name in ("sample4", "sample6"):
            a = emulate.learn_environment(INPUTS / f"{name}.vmp.bin", INPUTS / f"{name}.vmp.trace.1")
            b = emulate.learn_environment(INPUTS / f"{name}.vmp.bin", INPUTS / f"{name}.vmp.trace.2")
            self.assertNotEqual(a.heap_pointer(), b.heap_pointer())
            self.assertEqual(len(emulate.keyed_offsets(a, b)), 1, name)

    def test_unkeyed_relocation_is_rejected(self):
        a = emulate.learn_environment(INPUTS / "sample6.vmp.bin", INPUTS / "sample6.vmp.trace.1")
        b = emulate.learn_environment(INPUTS / "sample6.vmp.bin", INPUTS / "sample6.vmp.trace.2")
        moved = emulate.relocate_heap(a, b.heap_pointer(), keyed_offsets=[])  # forget to re-key
        with self.assertRaises(ValueError):
            emulate.reproduce(INPUTS / "sample6.vmp.bin", moved, INPUTS / "sample6.vmp.trace.2")

    def test_trace_with_wrong_entry_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not start"):
            emulate.read_trace(INPUTS / "sample4.vmp.trace.1", entry=0x401000)


@unittest.skipUnless(have("sample5.vmp.bin", "sample5.vmp.trace.1"), "inputs missing")
class VerifierRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = emulate.learn_environment(INPUTS / "sample5.vmp.bin", INPUTS / "sample5.vmp.trace.1")
        cls.explorer = emulate.Explorer(INPUTS / "sample5.vmp.bin", env, 32)
        cls.paths = cls.explorer.explore((1, 2))

    def test_both_paths_are_found_automatically(self):
        self.assertEqual(len(self.paths), 2)

    def test_complete_exploration_verifies(self):
        emulate.verify(self.explorer, self.paths, emulate.SAMPLES["sample5"], random.Random(1))

    def test_missing_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "do not cover"):
            emulate.verify(self.explorer, self.paths[:1], emulate.SAMPLES["sample5"], random.Random(1))

    def test_wrong_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "differs from the C source"):
            emulate.verify(self.explorer, self.paths, emulate.SAMPLES["sample6"], random.Random(1))

    def test_path_must_satisfy_its_own_condition(self):
        bogus = emulate.Path_((0, 1001), self.paths[0].conditions, [], self.paths[0].result, 0)
        if self.explorer.holds(bogus.conditions, bogus.inputs):
            bogus = emulate.Path_((1, 2), self.paths[1].conditions, [], self.paths[1].result, 0)
        with self.assertRaisesRegex(ValueError, "own condition"):
            emulate.verify(self.explorer, [bogus] + self.paths, emulate.SAMPLES["sample5"], random.Random(1))


if __name__ == "__main__":
    unittest.main()
