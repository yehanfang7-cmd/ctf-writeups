"""Unit 05 checks: constants come from the code, each layer model is checked, and wrong models are rejected."""
import importlib.util
import os
import shutil
import unittest

import devirt

HAVE_IMAGE = devirt.IMAGE.exists()
HAVE_CC = bool(os.environ.get("CC") or shutil.which("gcc") or shutil.which("cc") or shutil.which("g++"))
HAVE_UNICORN = importlib.util.find_spec("unicorn") is not None
FLAG = b"Av0cad0_Love_2018@flare-on.com"


@unittest.skipUnless(HAVE_IMAGE, "FlareOn/Fo5/12/suspicious_floppy_v1.0.img missing")
class Layers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.r = devirt.load_inputs()
        cls.image = devirt.rssb_image(cls.r)
        cls.targets = devirt.table(cls.image)

    # ---- x86 constants
    def test_constants_are_read_from_the_code(self):
        r = self.r
        self.assertEqual((r.mem0, r.words, r.pc0, r.pwdst, r.maxlen, r.result),
                         (0x223, 0x2DAD, 5, 0x142B, 32, 0x903))

    def test_unexpected_code_is_rejected(self):
        bad = bytearray(self.tmp)
        bad[0x43 + 0x1EF] = 0x90                      # no longer 'add ax, imm16'
        with self.assertRaisesRegex(ValueError, "add ax"):
            devirt.parse_resident(bytes(bad))

    # ---- Subleq
    @unittest.skipUnless(HAVE_CC, "no C compiler")
    def test_python_subleq_equals_vm_c(self):
        steps = 200_000
        s = devirt.Subleq(self.r, b"hello@flare-on.com")
        for _ in range(steps):
            s.step()
        fast = devirt.subleq_fast(self.r, b"hello@flare-on.com", max_steps=steps)
        self.assertEqual(bytes(s.seg), fast["segment"])
        self.assertEqual(s.pc, fast["pc"])

    # ---- RSSB rules (Python lockstep on a prefix)
    def test_rssb_rules_match_subleq(self):
        self.assertEqual(devirt.lockstep_python(self.r, b"a@b", 800), 800)

    def test_missing_zero_register_rule_is_caught(self):
        with self.assertRaisesRegex(ValueError, "at cell 0x2$"):           # the constant-zero cell
            devirt.lockstep_python(self.r, b"a@b", 800, zero_register=False)

    def test_missing_output_rule_is_caught(self):
        with self.assertRaisesRegex(ValueError, "RSSB model differs"):
            devirt.lockstep_python(self.r, b"a@b", 800, output_rule=False)

    @unittest.skipUnless(HAVE_CC, "no C compiler")
    def test_wrong_rssb_layout_is_caught(self):
        old = devirt.RSSB_IP0
        try:
            devirt.RSSB_IP0 = 0x15B                 # the ip before the Subleq start-up code ran
            with self.assertRaisesRegex(ValueError, "lockstep failed"):
                devirt.lockstep(self.r, b"a@b")
        finally:
            devirt.RSSB_IP0 = old

    # ---- lifted formula
    def observe(self, pw):
        m = devirt.Rssb(self.image, self.r, pw)
        ys = m.run(probe=devirt.PROBE_Y)
        return m.result, ys

    def test_at_sign_weight_has_the_0x8000_move_bug(self):
        self.assertEqual(devirt.at_weight(16), 0x4000)
        self.assertEqual(devirt.at_weight(17), 0xCC00)
        pw = b"Q" * 16 + b"@" + b"z" * 13
        _, ys = self.observe(pw)
        observed_g = (ys[0] - ((ord("Q") - 32) * 128 + (ord("Q") - 32))) & 0xFFFF
        self.assertEqual(observed_g, (0x4000 + 16 * ord("Q")) & 0xFFFF)
        self.assertNotEqual(observed_g, (0xC00 * 16 + 16 * ord("Q")) & 0xFFFF)   # the naive law
        self.assertEqual(devirt.lifted(devirt.cells(self.r, pw), self.targets)[1], ys)

    def test_no_at_sign_is_rejected_before_the_loop(self):
        result, ys = self.observe(b"no-at-sign")
        self.assertEqual((result, ys), (0, []))
        self.assertEqual(devirt.lifted(devirt.cells(self.r, b"no-at-sign"), self.targets), (0, []))

    def test_flag_is_accepted_and_one_change_is_not(self):
        self.assertEqual(self.observe(FLAG)[0], 1)
        self.assertEqual(devirt.lifted(devirt.cells(self.r, FLAG), self.targets)[0], 1)
        bad = FLAG[:5] + b"x" + FLAG[6:]
        self.assertEqual(self.observe(bad)[0], 0)

    # ---- solver
    def test_solver_finds_exactly_the_flag_family(self):
        self.assertEqual(devirt.solve(self.targets, self.r.maxlen),
                         [FLAG, FLAG + b"?", FLAG + b"??"])

    def test_solver_follows_the_table(self):
        changed = self.targets[:]
        changed[3] ^= 0x0101
        self.assertFalse(any(s.startswith(FLAG) for s in devirt.solve(changed, self.r.maxlen)))

    # ---- real x86
    @unittest.skipUnless(HAVE_UNICORN, "unicorn not installed")
    def test_x86_accepts_flag_with_free_tail(self):
        ax, printed, _ = devirt.x86_check(self.r, FLAG + b"!?")
        self.assertEqual(ax, 1)
        self.assertIn(b"Password Matched", printed)

    @unittest.skipUnless(HAVE_UNICORN, "unicorn not installed")
    def test_x86_rejects_wrong_password(self):
        ax, printed, _ = devirt.x86_check(self.r, b"Av0cad0_Love_2018@flare-on.co")
        self.assertEqual(ax, 0)
        self.assertIn(b"Incorrect Password", printed)


if __name__ == "__main__":
    unittest.main()
