"""Emit portable integer C from validated VM-0 IR, compile it, and cross-check execution."""
import argparse
import ctypes
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import platform
from pathlib import Path
import random
import re
import subprocess
import sys
import time
from zipfile import ZipFile, ZIP_DEFLATED

from llvmlite import binding as llvm
from tigress_vm0 import HERE, INPUTS, Image, concrete_oracle, HASHES

MASK = (1 << 64) - 1
PREAMBLE = '''/* Reconstructed integer data flow. Original C names and loop structure are unknown. */
#include <stdint.h>

static uint64_t shift_left(uint64_t value, uint64_t count) {
    return count < 64 ? value << count : UINT64_C(0);
}
static uint64_t shift_right(uint64_t value, uint64_t count) {
    return count < 64 ? value >> count : UINT64_C(0);
}
static uint64_t funnel_left(uint64_t high, uint64_t low, uint64_t count) {
    count &= UINT64_C(63);
    return count == 0 ? high : (high << count) | (low >> (64 - count));
}
static uint64_t funnel_right(uint64_t high, uint64_t low, uint64_t count) {
    count &= UINT64_C(63);
    return count == 0 ? low : (high << (64 - count)) | (low >> count);
}

'''
CLI = '''
/* Optional command-line wrapper: compile with -DBUILD_CLI. */
#ifdef BUILD_CLI
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *end;
    if (argc != 2) return 2;
    uint64_t input = (uint64_t)strtoull(argv[1], &end, 10);
    if (*end != '\\0') return 2;
    printf("%llu\\n", (unsigned long long)recovered(input));
    return 0;
}
#endif
'''


def emit_c(text):
    module = llvm.parse_assembly(text)
    module.verify()
    fn = module.get_function("__triton")
    args = list(fn.arguments)
    blocks = list(fn.blocks)
    if str(fn.global_value_type) != "i64 (i64)" or len(args) != 1 or len(blocks) != 1:
        raise ValueError("C emitter requires a single-block i64(i64) function")
    names = {args[0]: "input"}
    def value(operand):
        if operand in names:
            return names[operand]
        if operand.is_constant and str(operand.type) in ("i1", "i64"):
            return f"UINT64_C({int(operand.get_constant_value()) & MASK})"
        raise ValueError(f"Unsupported C operand: {operand}")
    lines = [PREAMBLE, "uint64_t recovered(uint64_t input) {"]
    if_count = 0
    for index, instruction in enumerate(blocks[0].instructions):
        op = instruction.opcode
        operands = list(instruction.operands)
        if op == "ret":
            lines.append(f"    return {value(operands[0])};")
            continue
        if str(instruction.type) not in ("i1", "i64"):
            raise ValueError(f"Unsupported integer width: {instruction.type}")
        name = f"value_{index}"
        if op == "select":
            condition, yes, no = map(value, operands)
            lines += [f"    uint64_t {name};", f"    if ({condition}) {{",
                      f"        {name} = {yes};", "    } else {", f"        {name} = {no};", "    }"]
            names[instruction] = name
            if_count += 1
            continue
        if op in ("add", "sub", "mul", "and", "or", "xor"):
            operator = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}[op]
            expression = f"{value(operands[0])} {operator} {value(operands[1])}"
        elif op in ("shl", "lshr"):
            helper = "shift_left" if op == "shl" else "shift_right"
            expression = f"{helper}({value(operands[0])}, {value(operands[1])})"
        elif op == "udiv":
            if not operands[1].is_constant or operands[1].get_constant_value() == 0:
                raise ValueError("Only nonzero constant unsigned divisors are supported")
            expression = f"{value(operands[0])} / {value(operands[1])}"
        elif op == "icmp":
            match = re.search(r"\bicmp\s+(\w+)", str(instruction))
            predicate = match.group(1) if match else ""
            operator = {"eq": "==", "ne": "!=", "ult": "<", "ule": "<=", "ugt": ">", "uge": ">=",
                        "slt": "<", "sle": "<=", "sgt": ">", "sge": ">="}.get(predicate)
            if operator is None:
                raise ValueError(f"Unsupported comparison: {instruction}")
            a, b = map(value, operands)
            if predicate.startswith("s"):
                a, b = f"({a} ^ UINT64_C(9223372036854775808))", f"({b} ^ UINT64_C(9223372036854775808))"
            expression = f"{a} {operator} {b}"
        elif op == "call":
            callee = operands[-1].name
            helper = {"llvm.fshl.i64": "funnel_left", "llvm.fshr.i64": "funnel_right"}.get(callee)
            if helper is None or len(operands) != 4:
                raise ValueError(f"Unsupported C call: {instruction}")
            expression = f"{helper}({', '.join(value(v) for v in operands[:-1])})"
        else:
            raise ValueError(f"Unsupported C instruction: {instruction}")
        lines.append(f"    uint64_t {name} = {expression};")
        names[instruction] = name
    lines += ["}", CLI]
    return "\n".join(lines), if_count


def compiler_environment():
    environment = os.environ.copy()
    cache = HERE.parent / ".cache/zig"
    for name, suffix in (("ZIG_GLOBAL_CACHE_DIR", "global"), ("ZIG_LOCAL_CACHE_DIR", "local")):
        destination = cache / suffix
        destination.mkdir(parents=True, exist_ok=True)
        environment[name] = str(destination)
    return environment


def compile_c(source, obj, optimization="-O2"):
    command = [sys.executable, "-m", "ziglang", "cc", "-std=c11", optimization, "-c", str(source),
               "-o", str(obj), "-ffreestanding", "-fno-stack-protector", "-fno-unwind-tables",
               "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
               "-target", "x86_64-linux-gnu"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, env=compiler_environment())
    obj.with_suffix(".build.txt").write_text(" ".join(command) + "\n" + result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise ValueError(f"C compilation failed: {result.stderr}")


def load_object(path):
    # RuntimeDyld accepts ELF here. An explicit Win64 entry adapts ctypes' Windows ABI
    # to the SysV ABI used by the independently compiled C object.
    triple = "x86_64-pc-linux-gnu"
    target = llvm.Target.from_triple(triple).create_target_machine()
    convention = "win64cc " if os.name == "nt" else ""
    wrapper = llvm.parse_assembly('''declare i64 @recovered(i64)
define CALLING_CONVENTIONi64 @call_recovered(i64 %input) {
entry:
  %result = call i64 @recovered(i64 %input)
  ret i64 %result
}
'''.replace("CALLING_CONVENTION", convention))
    wrapper.triple = triple
    wrapper.data_layout = str(target.target_data)
    wrapper.verify()
    engine = llvm.create_mcjit_compiler(wrapper, target)
    engine.add_object_file(llvm.ObjectFileRef.from_path(str(path)))
    engine.finalize_object()
    address = engine.get_function_address("call_recovered")
    if not address:
        raise ValueError("Compiled C object did not export recovered")
    return engine, ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address)


def load_ir(path):
    module = llvm.parse_assembly(path.read_text(encoding="utf-8"))
    module.verify()
    target = llvm.Target.from_default_triple().create_target_machine()
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(""), target)
    engine.add_module(module)
    engine.finalize_object()
    address = engine.get_function_address("__triton")
    if not address:
        raise ValueError("Reference IR function missing")
    return engine, ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address)


def run_case(index, previous, output, extra_cases):
    started = time.perf_counter()
    name = f"tigress-0-challenge-{index}"
    directory = output / name
    directory.mkdir(parents=True)
    path = previous / name / "optimized.ll"
    prior = json.loads((previous / name / "results.json").read_text())
    binary = INPUTS / "tigress-challenges" / name
    if hashlib.sha256(binary.read_bytes()).hexdigest() != HASHES[index] or prior["sha256"] != HASHES[index]:
        raise ValueError("Tigress source binding mismatch")
    text, branches = emit_c(path.read_text(encoding="utf-8"))
    (directory / "input.ll").write_bytes(path.read_bytes())
    source = directory / "recovered.c"
    source.write_text(text, encoding="utf-8")
    compile_c(source, directory / "recovered.obj")
    c_engine, function = load_object(directory / "recovered.obj")
    ir_engine, reference = load_ir(path)
    image = Image(binary)
    rng = random.Random(20261125 + index)
    values = [row["input"] for row in prior["observations"]]
    values += [rng.getrandbits(64) for _ in range(extra_cases)]
    observations = []
    for value in values:
        original = concrete_oracle(image, value)
        c_result, ir_result = function(value), reference(value)
        observations.append({"input": value, "unicorn": original, "compiled_c": c_result, "compiled_ir": ir_result})
        if not original == c_result == ir_result:
            (directory / "counterexample.json").write_text(json.dumps(observations[-1], indent=2), encoding="utf-8")
            raise ValueError(f"C result mismatch at {value}")
    row = {"sample": name, "status": "passed", "if_statements": branches, "c_lines": len(text.splitlines()),
           "cases": len(values), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
           "input_ir_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "binary_sha256": HASHES[index],
           "seconds": time.perf_counter() - started, "observations": observations}
    (directory / "results.json").write_text(json.dumps(row, indent=2), encoding="utf-8")
    print(f"{name}: C compiled; {branches} if statements; {len(values)} C/IR/Unicorn comparisons passed", flush=True)
    return row


def write_report(rows, prior, output, tests=None):
    lines = ["# Tigress VM-0 C 函式重建與編譯驗證報告", "",
             f"報告時間：{datetime.now(timezone(timedelta(hours=8))).isoformat()}。", "",
             f"本輪從既有 VM-0 還原 IR 重建 C，成功 {sum(r['status']=='passed' for r in rows)} / {len(rows)} 個樣本。",
             "輸出是可編譯的整數運算與 if/else 資料流函式，並非原始 C 結構的完整恢復。", "",
             "| 樣本 | C 行數 | if/else 數 | 新一輪三方比對組數 | 結果 |", "|---|---:|---:|---:|---|"]
    for row in rows:
        if row["status"] == "passed":
            lines.append(f"| {row['sample']} | {row['c_lines']} | {row['if_statements']} | {row['cases']} | 通過 |")
        else:
            lines.append(f"| {row['sample']} | — | — | — | 失敗：{row['error']} |")
    lines += ["", "## 方法與驗證", "",
              "輸入為上一輪實際從 ELF 符號執行產生的 optimized.ll。逐個 LLVM 整數運算轉成 uint64_t C，select 轉成 if/else；支援明確列出的位元運算、比較、非零常數除法及 funnel shift，未知指令即拒絕。", "",
              "使用 Zig 0.13.0 所附 C 編譯器，以 C11、O2、Wall、Wextra、Werror 編譯成目的檔，載入後執行。另重新以 Unicorn 模擬原始 ELF，並執行前輪 LLVM 函式，每組輸入比較這三個結果。新增的固定種子隨機輸入不沿用舊觀測值作答案。", "",
              "C 編譯輸出為 x86-64 Linux ELF 可重定位目的檔，不需 Linux 作業系統。LLVM RuntimeDyld 載入其機器碼，在 Windows 以明確的 Win64 至 SysV 呼叫介面轉接後實際執行；這不是對 Linux ELF 程式的作業系統原生執行。", "",
              "整數加減乘採 uint64_t 回繞；funnel shift 的零位移另處理以避免 C 位移 64 位元的未定義行為。一般位移超過寬度時有明確回傳值；這是 C 的總函式化處理，不是宣稱保留 LLVM poison 行為。有效來源輸入仍須靠比對檢查。[LLVM 語義](https://llvm.org/docs/LangRef.html#llvm-fshl-intrinsic)", "",
              "## 成果範圍", "",
              "每個 recovered.c 可獨立閱讀，包含 uint64_t recovered(uint64_t input)，亦附 BUILD_CLI 條件下的命令列包裝。本輪實際驗證的是函式目的檔，未編譯該命令列包裝，也未使用 gcc。", "",
              "原本展開的 IR 不保留足夠資訊以證明原始程式是否有迴圈。因此未自行發明迴圈或原始變數名稱；產生的 C 仍有暫存值與資料流特徵。if/else 對應 LLVM select，不能據此聲稱已恢復原始程式的分支布局。", "",
              "官方要求可讀 C 並保留高階結構；目前增加的是 C 重建與實際編譯驗證，仍不能宣稱正式完成官方 source recovery。Unicorn 與 Triton 共用載入及外部函式假設；有限測試亦不是對整個 64 位元定義域的獨立證明。[官方規則](https://tigress.cs.arizona.edu/challenges.html)", "",
              "## 產物與重現", "",
              f"來源實驗：`{prior.relative_to(HERE).as_posix()}`。", "",
              f"本輪產物：`{output.relative_to(HERE).as_posix()}`。每個樣本含 recovered.c、實際編譯的 recovered.obj、建置日誌與逐筆比對。",
              "一鍵入口為 start_tigress_c.ps1；預設使用最近一次五個樣本均成功的 Tigress 執行結果。", ""]
    if tests is not None:
        lines += ["## 轉換器回歸測試", "", f"四項專用測試：{'通過' if tests.returncode == 0 else '失敗'}。funnel shift 與 signed comparison 案例分別以 O0 和 O2 編譯 C，與 LLVM 執行結果比較；另驗證未知呼叫及非常數除數會被拒絕。完整記錄見 tests.txt。", ""]
    report = "\n".join(lines)
    (HERE / "TIGRESS_C_REPORT.md").write_text(report, encoding="utf-8")
    (output / "TIGRESS_C_REPORT.md").write_text(report, encoding="utf-8")
    with ZipFile(output / "tigress_c_bundle.zip", "w", compression=ZIP_DEFLATED) as bundle:
        for path in output.rglob("*"):
            if path.is_file() and path.name != "tigress_c_bundle.zip":
                bundle.write(path, path.relative_to(output).as_posix())
        for name in ("tigress_c.py", "tigress_c_tests.py", "tigress_vm0.py", "start_tigress_c.ps1", "requirements-tigress-c.txt", "requirements-tigress.txt", "requirements.txt"):
            if (HERE / name).exists():
                bundle.write(HERE / name, "project/" + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run", type=Path)
    parser.add_argument("--sample", type=int, choices=range(5))
    parser.add_argument("--extra-cases", type=int, default=256)
    args = parser.parse_args()
    if args.extra_cases < 0:
        parser.error("extra-cases must be nonnegative")
    prior = args.source_run
    if prior is None:
        for path in sorted((HERE / "generated/tigress").glob("*/results.json"), reverse=True):
            rows = json.loads(path.read_text())
            if len(rows) == 5 and all(row["status"] == "passed" for row in rows):
                prior = path.parent
                break
    if prior is None:
        parser.error("Run start_tigress.ps1 first")
    prior = prior.resolve()
    output = HERE / "generated/tigress-c" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True)
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    rows = []
    for index in range(5) if args.sample is None else [args.sample]:
        try:
            rows.append(run_case(index, prior, output, args.extra_cases))
        except Exception as error:
            rows.append({"sample": f"tigress-0-challenge-{index}", "status": "failed", "error": str(error)})
            print(str(error), flush=True)
    (output / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(HERE), "-p", "tigress_c_tests.py"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    (output / "tests.txt").write_text(tests.stdout + tests.stderr, encoding="utf-8")
    print(tests.stdout + tests.stderr, end="", flush=True)
    compiler = subprocess.run([sys.executable, "-m", "ziglang", "version"], capture_output=True, text=True, check=True)
    (output / "environment.json").write_text(json.dumps({"python": sys.version, "platform": platform.platform(),
        "zig": compiler.stdout.strip(), "c_target": "x86_64-linux-gnu", "reference_run": str(prior),
        "analysis_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2), encoding="utf-8")
    (output / "downloads.tsv").write_bytes((INPUTS / "downloads.tsv").read_bytes())
    write_report(rows, prior, output, tests)
    print("C run directory:", output, flush=True)
    return int(any(row["status"] != "passed" for row in rows) or tests.returncode != 0)


if __name__ == "__main__":
    sys.exit(main())
