"""Compile the emitted C and compare tricky integer semantics to LLVM execution."""
from pathlib import Path
import tempfile
import unittest

from llvmlite import binding as llvm
from tigress_c import MASK, compile_c, emit_c, load_ir, load_object


class CReconstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

    def compare_compilers(self, text, values):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ir = root / "input.ll"
            ir.write_text(text, encoding="utf-8")
            source = root / "recovered.c"
            source.write_text(emit_c(text)[0], encoding="utf-8")
            ref_engine, reference = load_ir(ir)
            for optimization in ("-O0", "-O2"):
                obj = root / f"{optimization}.obj"
                compile_c(source, obj, optimization)
                engine, recovered = load_object(obj)
                for value in values:
                    self.assertEqual(recovered(value), reference(value), (optimization, value))

    def test_funnel_shifts_with_distinct_operands(self):
        for intrinsic in ("fshl", "fshr"):
            text = f'''declare i64 @llvm.{intrinsic}.i64(i64, i64, i64)
define i64 @__triton(i64 %input) {{
  %count = and i64 %input, 63
  %result = call i64 @llvm.{intrinsic}.i64(i64 %input, i64 123456789, i64 %count)
  ret i64 %result
}}
'''
            self.compare_compilers(text, [0, 1, 2, 63, 64, 128, MASK])

    def test_signed_comparison_and_if_else(self):
        text = '''define i64 @__triton(i64 %input) {
  %condition = icmp slt i64 %input, -1
  %yes = add i64 %input, 1
  %no = sub i64 %input, 3
  %result = select i1 %condition, i64 %yes, i64 %no
  ret i64 %result
}
'''
        self.compare_compilers(text, [0, 1, (1 << 63) - 1, 1 << 63, MASK - 1, MASK])

    def test_unknown_external_call_is_rejected(self):
        text = '''declare i64 @unknown(i64)
define i64 @__triton(i64 %input) {
  %result = call i64 @unknown(i64 %input)
  ret i64 %result
}
'''
        with self.assertRaisesRegex(ValueError, "Unsupported C call"):
            emit_c(text)

    def test_variable_division_is_rejected(self):
        text = '''define i64 @__triton(i64 %input) {
  %result = udiv i64 10, %input
  ret i64 %result
}
'''
        with self.assertRaisesRegex(ValueError, "nonzero constant"):
            emit_c(text)


if __name__ == "__main__":
    unittest.main()
