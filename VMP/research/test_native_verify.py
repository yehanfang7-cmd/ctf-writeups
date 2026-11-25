"""Check actual compiled code with both LLVM formal argument orders."""
from pathlib import Path
import tempfile
import unittest

from llvmlite import binding as llvm
from native_verify import compile_and_check


class NativeArgumentMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

    def check_order(self, names, expected):
        # Asymmetric outputs catch swapped inputs, including x=0,y=1 -> 1 (not 2).
        source = f'''define i32 @__triton(i32 %{names[0]}, i32 %{names[1]}) {{
entry:
  %sum = add i32 %SymVar_0, %SymVar_1
  %condition = icmp ult i32 %sum, 1234
  %yes = add i32 %SymVar_0, 1
  %no = sub i32 %SymVar_1, 1
  %result = select i1 %condition, i32 %yes, i32 %no
  ret i32 %result
}}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "function.ll"
            path.write_text(source, encoding="utf-8")
            result = compile_and_check("sample6", path, Path(directory) / "output")
            self.assertEqual(result["argument_order"], expected)
            self.assertEqual(result["status"], "passed")

    def test_standard_argument_order(self):
        self.check_order(["SymVar_0", "SymVar_1"], [0, 1])

    def test_reversed_argument_order(self):
        self.check_order(["SymVar_1", "SymVar_0"], [1, 0])
