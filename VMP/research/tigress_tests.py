"""Check independent known output, state isolation, and incomplete coverage rejection."""
import unittest

from tigress_vm0 import INPUTS, Image, check_control_flow, concrete_oracle, explore, symbolic


class TigressExecutionTests(unittest.TestCase):
    def image(self, index):
        path = INPUTS / f"tigress-challenges/tigress-0-challenge-{index}"
        if not path.exists():
            self.skipTest("Download Tigress research inputs first")
        return Image(path)

    def test_published_known_output(self):
        self.assertEqual(concrete_oracle(self.image(0), 1234), 3035321144166078008)

    def test_insufficient_path_budget_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "coverage incomplete"):
            explore(self.image(1), max_paths=1)

    def test_replaying_in_shared_context_retains_old_expression(self):
        image = self.image(0)
        ctx, variable, first, _ = symbolic(image, 1234)
        self.assertEqual(first.evaluate(), 3035321144166078008)
        ctx, variable, second, _ = symbolic(image, 0xFFFFFFFFFFFFFFFF, ctx, variable)
        expected = concrete_oracle(image, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(first.evaluate(), expected)
        self.assertEqual(second.evaluate(), expected)

    def test_input_dependent_indirect_jump_is_rejected(self):
        from triton import ARCH, Instruction, TritonContext
        ctx = TritonContext(ARCH.X86_64)
        ctx.setConcreteRegisterValue(ctx.registers.rax, 0x2000)
        ctx.symbolizeRegister(ctx.registers.rax, "target")
        instruction = Instruction(0x1000, bytes.fromhex("ffe0"))  # jmp rax
        ctx.processing(instruction)
        with self.assertRaisesRegex(ValueError, "Symbolic native target"):
            check_control_flow(ctx, instruction)


if __name__ == "__main__":
    unittest.main()
