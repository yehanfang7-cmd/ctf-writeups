"""Unit 07 checks: the shipped binary keeps no plaintext secret but still computes it, the interpreter survives
malformed bytecode, and the attack recovers the secret from the binary alone -- with controls that fail."""
import os
import subprocess
import unittest

import attack
import build

HAVE_CC = build.compiler() is not None

CORE_CASES = r"""
#include <stdio.h>
#include "isa.h"
static void t(const char *name, const uint8_t *c, size_t n, uint64_t x) {
    uint64_t out = 0; int err = vm_run(c, n, x, &out, NULL);
    printf("%s %d %llu\n", name, err, (unsigned long long)out);
}
int main(void) {
    static uint8_t many[300];
    for (int i = 0; i < 300; i++) many[i] = OP_INPUT;
    const uint8_t halt[] = {OP_HALT}, add[] = {OP_ADD}, dup[] = {OP_DUP}, bad[] = {0xff},
        trunc[] = {OP_PUSH, 1, 2, 3}, shr64[] = {OP_INPUT, OP_SHR, 64, 0, 0, 0, 0, 0, 0, 0, OP_HALT},
        shl63[] = {OP_INPUT, OP_SHL, 63, 0, 0, 0, 0, 0, 0, 0, OP_HALT},
        sub[] = {OP_INPUT, OP_INPUT, OP_SUB, OP_HALT}, nohalt[] = {OP_INPUT};
    t("empty", halt, 0, 0);   t("halt", halt, 1, 0);   t("add", add, 1, 0);   t("dup", dup, 1, 0);
    t("bad", bad, 1, 0);      t("trunc", trunc, 4, 0); t("shr64", shr64, sizeof shr64, 5);
    t("shl63", shl63, sizeof shl63, 1); t("sub", sub, sizeof sub, 5); t("nohalt", nohalt, 1, 0);
    t("overflow", many, sizeof many, 0);
    return 0;
}
"""


@unittest.skipUnless(HAVE_CC, "no C compiler")
class MiniVM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = build.build()
        cls.original = build.cc(build.HERE / "original" / "vm.c", build.GEN / f"vm_original{build.EXE}", "-Wno-error")
        cls.att = attack.attack(cls.b["ship"], n_inputs=40, out_dir=build.GEN / "attack")

    # ---- the protector
    def test_shipped_binary_keeps_no_plaintext_secret(self):
        self.assertEqual(build.leaks(self.b["ship"]), [])
        # controls: the same detector finds every constant in the original and in the self-test build
        for exe in (self.original, self.b["selftest"]):
            found = build.leaks(exe)
            for c in ("0x5bd1e995", "0x100000001b3", "0x9e3779b97f4a7c15", "0xff51afd7ed558ccd"):
                self.assertIn(c, found)

    def test_shipped_binary_ignores_vm_disasm(self):
        env = dict(os.environ, VM_DISASM="1")
        rc, out, _ = build.run(self.b["ship"], 1234, env=env)
        self.assertEqual((rc, out), (0, "1448883231529079547"))
        rc, out, _ = build.run(self.original, 1234, env=env)          # control: the original dumps its bytecode
        self.assertIn("PUSH   0x5bd1e995", out)

    def test_shipped_binary_computes_the_secret(self):
        xs = build.test_inputs(40)
        self.assertEqual(build.compare(self.b["ship"], xs), [])
        self.assertEqual(build.compare(self.b["selftest"], xs), [])

    def test_bad_arguments_are_rejected(self):
        for a in ("abc", "", "-1", "12x", "0x", "99999999999999999999"):
            self.assertEqual(build.run(self.b["ship"], a)[0], 1, a)
        self.assertEqual(build.run(self.original, "abc")[1], build.run(self.original, "0")[1])  # control: "abc" == 0

    def test_interpreter_rejects_malformed_bytecode(self):
        src = build.GEN / "core_cases.c"
        src.write_text(CORE_CASES, encoding="utf-8")
        exe = build.cc(src, build.GEN / f"core_cases{build.EXE}", include=[build.HERE])
        res = {l.split()[0]: tuple(map(int, l.split()[1:]))
               for l in subprocess.run([str(exe)], capture_output=True, text=True).stdout.splitlines()}
        m = {"VM_OK": 0, "VM_BAD_OP": 1, "VM_TRUNCATED": 2, "VM_UNDERFLOW": 3, "VM_OVERFLOW": 4, "VM_BAD_SHIFT": 5,
             "VM_NO_HALT": 6}
        self.assertEqual({k: v[0] for k, v in res.items()},
                         {"empty": m["VM_NO_HALT"], "halt": m["VM_UNDERFLOW"], "add": m["VM_UNDERFLOW"],
                          "dup": m["VM_UNDERFLOW"], "bad": m["VM_BAD_OP"], "trunc": m["VM_TRUNCATED"],
                          "shr64": m["VM_BAD_SHIFT"], "shl63": 0, "sub": 0, "nohalt": m["VM_NO_HALT"],
                          "overflow": m["VM_OVERFLOW"]})
        self.assertEqual(res["shl63"][1], 1 << 63)
        self.assertEqual(res["sub"][1], 0)

    def test_gen_refuses_a_wide_shift(self):
        src = (build.HERE / "gen.c").read_text(encoding="utf-8").replace("a_shr(a, 33)", "a_shr(a, 64)")
        bad = build.GEN / "gen_wide.c"
        bad.write_text(src, encoding="utf-8")
        exe = build.cc(bad, build.GEN / f"gen_wide{build.EXE}", include=[build.HERE])
        r = subprocess.run([str(exe), str(build.GEN / "unused.h")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("shift 64 out of range", r.stderr)

    # ---- the attack
    def test_attack_recovers_the_secret_from_the_binary_alone(self):
        a = self.att
        self.assertEqual((a["candidates"], len(a["confirmed"]), a["seed"]), (1, 1, 0xA5))
        self.assertTrue(a["c_matches"])
        for x in build.test_inputs(20):
            self.assertEqual(attack.emulate(a["insns"], x), build.reference(x))
        self.assertIn("rotl64((t0 ^ (t0 >> 15)) + 0x9e3779b97f4a7c15ULL, 13)", a["source"])

    def test_attack_does_not_depend_on_the_key(self):
        b = build.build(build.GEN / "seed3c", seed=0x3C)
        a = attack.attack(b["ship"], n_inputs=20)
        self.assertEqual((len(a["confirmed"]), a["seed"]), (1, 0x3C))
        self.assertNotEqual(a["offset"], None)

    def test_attack_trusts_the_binary_not_the_scan(self):
        # a decoy: a second well-formed encrypted program appended to the file. The scan finds both;
        # only the one the binary actually runs agrees with it.
        data = bytearray(self.b["ship"].read_bytes())
        off = self.att["offset"]
        blob = bytearray(data[off:off + 73])
        decoy = bytearray(b ^ k for b, k in zip(blob, attack.KS[0xA5]))
        decoy[2] ^= 0x01                                   # 0x5bd1e995 -> 0x5bd1e994 (PUSH imm, byte 0)
        data += bytes(b ^ k for b, k in zip(decoy, attack.KS[0x5A]))
        exe = build.GEN / f"vm_decoy{build.EXE}"
        exe.write_bytes(bytes(data))
        a = attack.attack(exe, n_inputs=20)
        self.assertEqual(a["candidates"], 2)
        self.assertEqual([(o, s) for o, s, _ in a["confirmed"]], [(off, 0xA5)])


@unittest.skipUnless(HAVE_CC, "no C compiler")
class Diversity(unittest.TestCase):
    """opcode numbering shuffled per build; broken by unit 06's behavioural classification"""
    @classmethod
    def setUpClass(cls):
        import attack_div
        cls.attack_div = attack_div
        cls.b = build.build(build.GEN / "div_test", seed=0x3C, opcode_seed=0x1234)
        cls.res = attack_div.break_build(cls.b["ship"], cls.b["oracle"], n_inputs=40)

    def test_shuffling_changes_the_opcode_bytes(self):
        canon = {"INPUT": 0x10, "PUSH": 0x11, "ADD": 0x12, "HALT": 0x1C}
        self.assertTrue(any(self.b["opcodes"][k] != v for k, v in canon.items()))
        self.assertEqual(len(set(self.b["opcodes"].values())), 13)        # still a permutation

    def test_shuffled_build_keeps_no_plaintext_secret_and_computes_it(self):
        self.assertEqual(build.leaks(self.b["ship"]), [])
        self.assertEqual(build.compare(self.b["ship"], build.test_inputs(40)), [])

    def test_fixed_opcode_scanner_fails_on_a_shuffled_build(self):
        self.assertEqual(self.res["scanner_fixed"], 0)                    # attack.py's numbering is gone

    def test_behavioural_classification_recovers_the_numbering(self):
        for name, byte in self.b["opcodes"].items():
            self.assertEqual(self.res["ops"].get(byte), name)            # recovered without reading the table

    def test_recovered_c_matches_the_shuffled_binary(self):
        self.assertEqual(len(self.res["confirmed"]), 1)
        self.assertIn("rotl64((t0 ^ (t0 >> 15)) + 0x9e3779b97f4a7c15ULL, 13)", self.res["source"])

    def test_two_seeds_give_different_numberings_both_broken(self):
        other = build.build(build.GEN / "div_test2", seed=0x3C, opcode_seed=0x9999)
        self.assertNotEqual(self.b["opcodes"], other["opcodes"])
        r = self.attack_div.break_build(other["ship"], other["oracle"], n_inputs=30)
        self.assertEqual((r["scanner_fixed"], len(r["confirmed"])), (0, 1))


if __name__ == "__main__":
    unittest.main()
