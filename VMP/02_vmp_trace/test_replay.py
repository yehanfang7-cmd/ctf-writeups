"""Check that the equivalence verifier rejects plausible but wrong results."""
import unittest
from triton import ARCH, TritonContext
from replay import verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.ctx = TritonContext(ARCH.X86_64)
        self.variables = [self.ctx.symbolizeRegister(self.ctx.registers.edi, "x"),
                          self.ctx.symbolizeRegister(self.ctx.registers.esi, "y")]
        ast = self.ctx.getAstContext()
        self.x, self.y = (ast.variable(variable) for variable in self.variables)

    def test_xor_passes(self):
        self.assertEqual(verify(self.ctx, self.variables, self.x ^ self.y), 1088)

    def test_addition_is_not_xor(self):
        with self.assertRaisesRegex(ValueError, "Equivalence was not proved"):
            verify(self.ctx, self.variables, self.x + self.y)

    def test_symbolic_path_is_not_global_equivalence(self):
        self.ctx.pushPathConstraint(self.x == 0)
        with self.assertRaisesRegex(ValueError, "single trace is insufficient"):
            verify(self.ctx, self.variables, self.x ^ self.y)


if __name__ == "__main__":
    unittest.main()
