"""Tests for unit 08.  Most of them check that a wrong model or a wrong input is rejected.

    cd VMP/08_tigress_hard; ../.venv/Scripts/python -m unittest test_hard -v      (about 3 minutes)
"""
import unittest

import fetch
import verify
import x86lift
from verify import devirt

fetch.fetch()
import solve0004                                                 # noqa: E402
import solve0005                                                 # noqa: E402
import solve0006                                                 # noqa: E402


class X86Lift(unittest.TestCase):
    def test_unhandled_instruction_is_rejected(self):
        with self.assertRaises(x86lift.LiftError):
            x86lift.lift(bytes.fromhex("0fa2c3"))                 # cpuid; ret

    def test_value_loaded_before_a_store_cannot_be_used_after_it(self):
        # mov rax,[rbp-0x10]; mov qword [rbp-0x18],5; mov [rbp-0x20],rax; ret
        code = bytes.fromhex("488b45f0" "48c745e805000000" "488945e0" "c3")
        with self.assertRaisesRegex(x86lift.LiftError, "loaded before a store"):
            x86lift.lift(code)

    def test_register_live_across_blocks_is_rejected(self):
        # jmp +0 ; mov [rbp-0x20],rax ; ret   -> rax is not defined in the second block
        code = bytes.fromhex("e900000000" "488945e0" "c3")
        with self.assertRaisesRegex(x86lift.LiftError, "read before it is written"):
            x86lift.lift(code)


class Paths(unittest.TestCase):
    IN = ("load", 8, 0, ("load", 8, 0, ("paddr", "in")))
    OUT = ("load", 8, 0, ("paddr", "out"))

    def blocks(self, cond):
        return {0: ([], ("br", cond, "nz", 64, 1, 2)),
                1: ([("store", 8, self.OUT, ("c", 1))], ("goto", 3)),
                2: ([("store", 8, self.OUT, ("c", 2))], ("goto", 3)),
                3: ([], ("ret",))}

    def test_equality_branch_is_solved(self):
        blocks = self.blocks(("eq", ("mul", self.IN, ("c", 3)), ("c", 0x123456789)))
        paths, undecided, visited = verify.explore_blocks(blocks)
        covered, dead, unknown = verify.coverage(blocks, paths, undecided, visited)
        self.assertEqual((covered, dead, unknown), ({0, 1, 2, 3}, set(), set()))
        self.assertTrue(any(p["input"] * 3 % 2**64 == 0x123456789 for p in paths))

    def test_unsatisfiable_side_is_reported_dead(self):
        blocks = self.blocks(("eq", ("and", self.IN, ("c", 1)), ("c", 2)))
        paths, undecided, visited = verify.explore_blocks(blocks)
        self.assertEqual(verify.coverage(blocks, paths, undecided, visited)[1:], ({1}, set()))

    def test_timeout_is_reported_as_undecided_not_as_dead(self):
        x = self.IN                                               # x*x*x*x + x*x == constant: z3 gives up in 1 ms
        hard = ("eq", ("add", ("mul", ("mul", x, x), ("mul", x, x)), ("mul", x, ("add", x, ("c", 77)))), ("c", 0x1234567890ABCDEF))
        blocks = self.blocks(hard)
        paths, undecided, visited = verify.explore_blocks(blocks, timeout_ms=1)
        covered, dead, unknown = verify.coverage(blocks, paths, undecided, visited)
        self.assertTrue(undecided)
        self.assertEqual(dead, set())                             # nothing may be called dead on a timeout,
        self.assertEqual(covered | unknown, set(blocks))          # including the blocks of an abandoned path


class Jit0006(unittest.TestCase):
    def test_challenge_1_end_to_end(self):
        r = solve0006.solve(1, n_random=100, n_whole=3)
        self.assertIn("a48[3] = ((input[0] * 0xb231279UL)", r["source"])

    def test_wrong_c_is_caught(self):
        j = solve0006.Jit(solve0006.HERE / "inputs" / "0006" / "challenge-1")
        base, code = j.bufs[1]
        src = x86lift.BlockLifter(x86lift.lift(code)).source().replace("0x1b3b54c4UL", "0x1b3b54c5UL")
        bad = verify.compare_c(src, "test-0006-1-wrong", lambda x: j.call(base, x), devirt.test_inputs(200))
        self.assertGreater(len(bad), 20)


class Vm0005(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mc = solve0005.JitMachine(solve0005.HERE / "inputs" / "0005" / "challenge-3")
        cls.isa, cls.insns = devirt.decode(cls.mc)

    def test_layout_is_found_by_observation(self):
        L = self.mc.L
        self.assertEqual((L["vpc"], L["vsp"], L["code"]), (-0x5e, -0x190, 0x65b180))
        self.assertGreaterEqual(L["handlers"], 20)

    def test_lockstep_accepts_the_model(self):
        self.assertGreater(devirt.lockstep(self.mc, self.insns, 0x1234), 300)

    def test_lockstep_rejects_a_swapped_operand_order(self):
        wrong = dict(self.insns)
        pc = next(p for p, i in wrong.items() if i[1][0] == "bin" and i[1][1] == "sub")
        op, sem, arg, n = wrong[pc]
        wrong[pc] = (op, ("bin", "sub", "st" if sem[2] == "ts" else "ts") + sem[3:], arg, n)
        with self.assertRaisesRegex(ValueError, "lockstep"):
            devirt.lockstep(self.mc, wrong, 0x1234)


class Nested0004(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mc = solve0004.NestedMachine(solve0004.HERE / "inputs" / "0004" / "challenge-1")
        cls.isa, cls.insns = solve0004.decode(cls.mc)

    def test_layout_is_found_by_observation(self):
        L = self.mc.L
        self.assertEqual((L["secret"], L["code"], L["vpc"], L["vsp"], L["ret"]), (0x400B03, 0x606080, -0x5E, -0x190, 0xD1))

    def test_measured_lengths_match_the_decoded_program(self):
        for pc, (op, sem, arg, n) in self.insns.items():
            self.assertEqual(self.mc.oplen(op), n - 1, f"opcode {op:#x} at pc {pc}")

    def test_trace_gate_accepts_the_model(self):
        self.assertGreater(solve0004.trace_gate(self.mc, self.insns, 0x1234), 200)

    def test_trace_gate_rejects_a_wrong_operation(self):
        wrong = dict(self.insns)
        pc = next(p for p, i in wrong.items() if i[1][0] == "bin" and i[1][1] == "add")
        op, sem, arg, n = wrong[pc]
        wrong[pc] = (op, ("bin", "sub") + sem[2:], arg, n)
        with self.assertRaises(AssertionError):
            solve0004.trace_gate(self.mc, wrong, 0x1234)

    def test_trace_gate_rejects_a_wrong_store_width(self):
        wrong = dict(self.insns)
        pc = next(p for p, i in wrong.items() if i[1][0] == "store" and i[1][1] == 8)
        op, sem, arg, n = wrong[pc]
        wrong[pc] = (op, ("store", 4, sem[2]), arg, n)
        with self.assertRaises(AssertionError):
            solve0004.trace_gate(self.mc, wrong, 0x1234)

    def test_snapshot_run_equals_run_from_entry(self):
        for x in (0, 1, 0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0):
            self.assertTrue(self.mc.call(x))
            self.assertEqual(self.mc.q(self.mc.out), self.mc.run(x))


if __name__ == "__main__":
    unittest.main()
