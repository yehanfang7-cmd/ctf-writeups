"""Unit 06 checks: the layout comes from the code, the classifier finds what the handlers do, and each gate
rejects a model with one of the mistakes made while building it."""
import random
import unittest

import devirt

HAVE_INPUTS = all((devirt.INPUTS / f"challenge-{k}").exists() for k in devirt.BINARIES)
HAVE_CC = devirt.compiler() is not None


def with_sem(insns, op, sem):
    """copy of insns where every occurrence of opcode `op` gets semantics `sem`"""
    return {pc: (o, sem if o == op else s, a, n) for pc, (o, s, a, n) in insns.items()}


@unittest.skipUnless(HAVE_INPUTS, "run devirt.py once to download the challenge")
class Tigress0000(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mc, cls.isa, cls.insns, cls.paths = {}, {}, {}, {}
        for k in (0, 1, 4):
            mc = devirt.Machine(devirt.binary(k))
            cls.mc[k] = mc
            cls.isa[k], cls.insns[k] = devirt.decode(mc)
        cls.paths[1] = devirt.explore(cls.insns[1])

    # ---- layout
    def test_layout_is_read_from_the_code(self):
        self.assertEqual({k: (m.L["secret"], m.L["head"], m.L["vpc"], m.L["vsp"], m.L["code"]) for k, m in self.mc.items()},
                         {0: (0x4006D1, 0x40070D, -0x70, -0x80, 0x602060),
                          1: (0x4005F4, 0x400630, -0x70, -0x80, 0x602060),
                          4: (0x4006D1, 0x400710, -0x70, -0x80, 0x602060)})

    def test_unexpected_code_is_rejected(self):
        data = bytearray(devirt.binary(0))
        elf = devirt.Elf(bytes(data))
        head = self.mc[0].L["head"]
        off = next(o + head - va for o, va, fs, ms in elf.loads if va <= head < va + fs)
        data[off:off + 4] = b"\x90" * 4                      # the head no longer reads the bytecode pointer
        with self.assertRaisesRegex(ValueError, "dispatch head"):
            devirt.Machine(bytes(data))
        with self.assertRaisesRegex(ValueError, "not an ELF64"):
            devirt.Elf(b"MZ" + bytes(100))

    # ---- classifier: facts read from the handlers' disassembly
    def test_classifier_finds_operand_order_casts_and_widths(self):
        isa0, isa1, isa4 = self.isa[0], self.isa[1], self.isa[4]
        self.assertEqual(isa0[0x2B], ("bin", "shr", "st", "", "", 64))        # second >> top
        self.assertEqual(isa0[0x27], ("bin", "add", "ts", "", "s32", 64))     # pointer + (int)index
        self.assertEqual(isa0[0x8E], ("param", {0: ("in", -392), 1: ("out", -400)}))
        self.assertEqual(isa1[0x90], ("br", "nz", 32))                      # tests an int, not the whole slot
        self.assertEqual(isa1[0x45], ("push", 4, 0, 32))                    # 32-bit push keeps the slot's high half
        self.assertEqual(isa1[0x4F], ("load", 2, 0, 16))
        self.assertEqual(isa4[0x0E], ("bin", "udiv", "st", "", "", 64))

    def test_the_five_dispatchers_share_no_opcode_numbering(self):
        adds = {k: sorted(op for op, s in self.isa[k].items() if s[:2] == ("bin", "add")) for k in self.isa}
        self.assertTrue(all(adds.values()))
        self.assertNotEqual(adds[0], adds[1])

    # ---- gate A: lockstep
    def test_lockstep_accepts_the_model(self):
        for p in self.paths[1]:
            self.assertGreater(devirt.lockstep(self.mc[1], self.insns[1], p["input"]), 300)

    def test_lockstep_rejects_a_64_bit_branch_test(self):
        bad = with_sem(self.insns[1], 0x90, ("br", "nz", 64))             # my first model of the branch
        with self.assertRaisesRegex(ValueError, "lockstep"):
            for x in [p["input"] for p in self.paths[1]] + [0x1234567]:
                devirt.lockstep(self.mc[1], bad, x)

    def test_lockstep_rejects_a_full_width_push(self):
        bad = with_sem(self.insns[1], 0x45, ("push", 4, 0, 64))           # my second mistake
        with self.assertRaisesRegex(ValueError, "lockstep.*push"):
            devirt.lockstep(self.mc[1], bad, 0x1234567)

    def test_lockstep_rejects_a_swapped_operand_order(self):
        bad = with_sem(self.insns[0], 0x2B, ("bin", "shr", "ts", "", "", 64))
        with self.assertRaisesRegex(ValueError, "lockstep"):
            devirt.lockstep(self.mc[0], bad, 0x1234567)

    # ---- gate B: paths
    def test_random_inputs_miss_a_branch_that_z3_finds(self):
        mc, insns = self.mc[1], self.insns[1]
        seen = set()
        for x in devirt.test_inputs(300):
            mc.run(x, on_head=lambda m: seen.add(m.vm_state()[0]))
        self.assertLess(len(seen), len(insns))                              # 600 of 630
        self.assertEqual(len(self.paths[1]), 2)
        self.assertEqual(set().union(*(p["pcs"] for p in self.paths[1])), set(insns))

    # ---- gate C: recovered C
    @unittest.skipUnless(HAVE_CC, "no C compiler")
    def test_recovered_c_equals_the_original(self):
        src = devirt.Lifter(self.insns[1]).source()
        xs = devirt.test_inputs(300) + [p["input"] for p in self.paths[1]]
        self.assertEqual(devirt.compare(self.mc[1], devirt.build(src, "test-1"), xs), [])
        self.assertNotIn("frame[", src)

    @unittest.skipUnless(HAVE_CC, "no C compiler")
    def test_narrow_accesses_must_alias_the_64_bit_variable(self):
        src = devirt.Lifter(self.insns[1], alias_narrow=False).source()     # my first rendering
        self.assertIn("unsigned short v38_16;", src)
        bad = devirt.compare(self.mc[1], devirt.build(src, "test-1-noalias"), devirt.test_inputs(100))
        self.assertGreater(len(bad), 50)

    def test_32_bit_index_constants_are_signed(self):
        src = devirt.Lifter(self.insns[4]).source()
        self.assertIn("a80[(v42 - 1UL)]", src)
        self.assertNotIn("0xffffffffUL)]", src)

    def test_lifter_refuses_stale_stack_bits(self):
        # a narrow push whose high bits reach the output must not be rendered as a constant
        insns = {0: (1, ("push", 4, 0, 32), 7, 5), 5: (2, ("param", {0: ("out", -400)}), 0, 5),
                 10: (3, ("load", 8, 0, 64), 0, 1), 11: (4, ("store", 8, "ptr_top"), 0, 1), 12: (5, ("ret",), 0, 1)}
        with self.assertRaisesRegex(ValueError, "stale"):
            devirt.Lifter(insns).source()


if __name__ == "__main__":
    unittest.main()
