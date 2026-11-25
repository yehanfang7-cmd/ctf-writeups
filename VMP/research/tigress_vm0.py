"""Recover VM-0 expressions from actual ELF execution and cross-check with Unicorn."""
import argparse
import ctypes
from datetime import datetime, timezone, timedelta
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time
import traceback
from zipfile import ZipFile, ZIP_DEFLATED

import lief

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs/tigress"
HOOK_BASE, ARGV_BASE, STACK_BASE = 0x10000000, 0x20000000, 0x70000000
MASK = (1 << 64) - 1
LIMIT = 2000000
EXPECTED_REVISION = "382a8e9e9aacad553f0b3c228e2b76077ff0ced2"
HASHES = [
    "581936cbe0b0b7a7b323f2c48d93202100faf78d7d512418c7f6f873d8ce011b",
    "5f0d952c0e8d3471e38b0ed3bc96263a2b84001a133f3cce626334cbb28b1191",
    "087a550f3730c574548806ed34e465ba0370f48173e53edc5c4137fcf6bcd072",
    "fe8e69f2d348bcc2c9050f2552665736fc3a3f098fcd11b2bfbb514cef1a8043",
    "3344044ae05863f4162be58c234e5c40819c5a8630b2de118c17f4454b84dfa9",
]


class Image:
    def __init__(self, path):
        self.path = path
        binary = lief.parse(str(path))
        if binary is None or str(binary.header.machine_type) != "ARCH.X86_64":
            raise ValueError("Expected x86-64 ELF")
        self.entry = binary.entrypoint
        self.segments = [(s.virtual_address, s.virtual_size, bytes(s.content))
                         for s in binary.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
        self.hooks = {}
        self.relocations = []
        allowed = {"__stack_chk_fail", "printf", "__libc_start_main", "strtoul", "exit"}
        for relocation in binary.pltgot_relocations:
            name = relocation.symbol.name
            if name not in allowed:
                raise ValueError(f"Unmodelled external function: {name}")
            address = HOOK_BASE + len(self.hooks) * 16
            self.hooks[address] = name
            self.relocations.append((relocation.address, address))

    def initialize(self, write, setreg, value):
        for address, size, content in self.segments:
            write(address, content + bytes(size - len(content)))
        for address, target in self.relocations:
            write(address, struct.pack("<Q", target))
        write(ARGV_BASE, b"tigress\0")
        write(ARGV_BASE + 0x100, str(value).encode() + b"\0")
        write(ARGV_BASE + 0x200, struct.pack("<QQQ", ARGV_BASE, ARGV_BASE + 0x100, 0))
        write(STACK_BASE, bytes(0x10000))
        setreg("rsp", STACK_BASE + 0x10000 - 0x100)
        setreg("rbp", STACK_BASE + 0x10000 - 0x100)


def read_string(read, address, limit=1024):
    result = bytearray()
    for offset in range(limit):
        byte = read(address + offset, 1)[0]
        if byte == 0:
            return result.decode("ascii")
        result.append(byte)
    raise ValueError("Unterminated guest string")


def check_control_flow(ctx, instruction):
    if ctx.getRegisterAst(ctx.registers.rip).isSymbolized():
        mnemonic = instruction.getDisassembly().split()[0].lower()
        if not (mnemonic.startswith("j") and mnemonic != "jmp"):
            raise ValueError(f"Symbolic native target: {instruction}")


def symbolic(image, seed=1234, ctx=None, variable=None):
    from triton import ARCH, EXCEPTION, Instruction, MODE, MemoryAccess, TritonContext
    ctx = ctx if ctx is not None else TritonContext(ARCH.X86_64)
    ctx.concretizeAllMemory()
    ctx.concretizeAllRegister()
    ctx.clearPathConstraints()
    ctx.setSolverTimeout(30000)
    for mode in (MODE.ALIGNED_MEMORY, MODE.AST_OPTIMIZATIONS, MODE.CONSTANT_FOLDING):
        ctx.setMode(mode, True)
    def setreg(name, value):
        ctx.setConcreteRegisterValue(getattr(ctx.registers, name), value)
    def getreg(name):
        return ctx.getConcreteRegisterValue(getattr(ctx.registers, name))
    def write(address, data):
        ctx.setConcreteMemoryAreaValue(address, data)
    def read(address, size):
        return ctx.getConcreteMemoryAreaValue(address, size)
    def ret():
        stack = getreg("rsp")
        setreg("rip", struct.unpack("<Q", read(stack, 8))[0])
        setreg("rsp", stack + 8)
    for name in "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip".split():
        setreg(name, 0)
    setreg("eflags", 2)
    image.initialize(write, setreg, seed)
    setreg("rip", image.entry)
    converted = False
    instructions = 0
    dependencies = 0
    calls = []
    while instructions < LIMIT:
        pc = getreg("rip")
        if pc in image.hooks:
            name = image.hooks[pc]
            calls.append(name)
            if name == "__libc_start_main":
                main = getreg("rdi")
                setreg("rdi", 2)
                setreg("rsi", ARGV_BASE + 0x200)
                setreg("rip", main)
                continue
            if name == "strtoul":
                text = read_string(read, getreg("rdi"))
                if getreg("rdx") not in (0, 10):
                    raise ValueError("Unsupported numeric base")
                setreg("rax", int(text))
                if converted:
                    raise ValueError("Multiple symbolic input conversions")
                if variable is None:
                    variable = ctx.symbolizeRegister(ctx.registers.rax, "input")
                else:
                    ctx.setConcreteVariableValue(variable, int(text))
                    ctx.assignSymbolicExpressionToRegister(
                        ctx.newSymbolicExpression(ctx.getAstContext().variable(variable)), ctx.registers.rax)
                converted = True
                ret()
                continue
            if name == "printf":
                fmt = read_string(read, getreg("rdi"))
                if fmt != "%lu\n" or not converted:
                    raise ValueError(f"Unexpected output contract: {fmt!r}")
                node = ctx.getRegisterAst(ctx.registers.rsi)
                if not node.isSymbolized():
                    raise ValueError("Output lost input dependence")
                return ctx, variable, node, {"instructions": instructions,
                    "input_dependent_memory": dependencies, "calls": calls, "seed": seed,
                    "recorded_output": node.evaluate(), "native_symbolic_paths": ctx.getPathPredicateSize()}
            raise ValueError(f"Unexpected external call: {name}")
        instruction = Instruction(pc, read(pc, 16))
        fault = ctx.processing(instruction)
        instructions += 1
        if fault != EXCEPTION.NO_FAULT:
            raise ValueError(f"Instruction fault {fault}: {instruction}")
        # Conditional jumps have path predicates; input-derived indirect targets do not
        # supply a complete set of successor addresses and must be rejected.
        check_control_flow(ctx, instruction)
        for access, _ in instruction.getLoadAccess() + instruction.getStoreAccess():
            lea = access.getLeaAst()
            if lea is not None and lea.isSymbolized():
                dependencies += 1
                raise ValueError(f"Input-dependent memory outside supported scope: {instruction}")
    raise ValueError("Symbolic execution instruction limit reached")


def explore(image, max_paths=8):
    from triton import SOLVER_STATE
    ctx, variable, node, info = symbolic(image)
    ast = ctx.getAstContext()
    paths = [(ctx.getPathPredicate(), node, info)]
    while True:
        coverage = ast.lor([predicate for predicate, _, _ in paths]) if len(paths) > 1 else paths[0][0]
        model, status, _ = ctx.getModel(ast.lnot(coverage), status=True)
        if status == SOLVER_STATE.UNSAT:
            break
        if status != SOLVER_STATE.SAT or len(paths) >= max_paths:
            raise ValueError(f"Path coverage incomplete: paths={len(paths)}, solver={status}")
        if variable.getId() not in model:
            raise ValueError("Solver did not provide unexplored input")
        seed = model[variable.getId()].getValue()
        ctx, variable, node, info = symbolic(image, seed, ctx, variable)
        predicate = ctx.getPathPredicate()
        if not predicate.evaluate():
            raise ValueError("Path predicate does not hold for its own input")
        paths.append((predicate, node, info))
    merged = paths[-1][1]
    for predicate, node, _ in reversed(paths[:-1]):
        merged = ast.ite(predicate, node, merged)
    for predicate, node, info in paths:
        _, status, _ = ctx.getModel(ast.land([predicate, merged != node]), status=True)
        if status != SOLVER_STATE.UNSAT:
            raise ValueError("Merged output does not agree with a path")
    for index, (predicate, _, info) in enumerate(paths):
        info["condition"] = str(ast.unroll(predicate))
    return ctx, variable, merged, {"paths": [info for _, _, info in paths],
        "path_count": len(paths), "coverage": "UNSAT", "path_merge_equivalence": "UNSAT",
        "coverage_condition": str(ast.unroll(coverage)),
        "instructions": sum(info["instructions"] for _, _, info in paths)}


def concrete_oracle(image, value):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
    from unicorn import x86_const
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = set()
    for address, size, _ in image.segments:
        pages.update(range(address & ~0xFFF, (address + size + 0xFFF) & ~0xFFF, 0x1000))
    pages.update((0, HOOK_BASE))
    pages.update(range(ARGV_BASE, ARGV_BASE + 0x1000, 0x1000))
    pages.update(range(STACK_BASE, STACK_BASE + 0x10000, 0x1000))
    for address in sorted(pages):
        uc.mem_map(address, 0x1000)
    def reg(name):
        return getattr(x86_const, "UC_X86_REG_" + name.upper())
    def setreg(name, value):
        uc.reg_write(reg(name), value)
    def getreg(name):
        return uc.reg_read(reg(name))
    def ret():
        stack = getreg("rsp")
        setreg("rip", struct.unpack("<Q", uc.mem_read(stack, 8))[0])
        setreg("rsp", stack + 8)
    image.initialize(uc.mem_write, setreg, value)
    result = []
    errors = []
    def hook(engine, address, size, user):
        try:
            name = image.hooks[address]
            if name == "__libc_start_main":
                main = getreg("rdi")
                setreg("rdi", 2)
                setreg("rsi", ARGV_BASE + 0x200)
                setreg("rip", main)
            elif name == "strtoul":
                text = read_string(uc.mem_read, getreg("rdi"))
                if getreg("rdx") not in (0, 10):
                    raise ValueError("Unsupported numeric base")
                setreg("rax", int(text))
                ret()
            elif name == "printf":
                fmt = read_string(uc.mem_read, getreg("rdi"))
                if fmt != "%lu\n":
                    raise ValueError(f"Unexpected output format {fmt!r}")
                result.append(getreg("rsi"))
                uc.emu_stop()
            else:
                raise ValueError(f"Unexpected external call {name}")
        except Exception as error:
            errors.append(str(error))
            uc.emu_stop()
    for address in image.hooks:
        uc.hook_add(UC_HOOK_CODE, hook, begin=address, end=address)
    uc.emu_start(image.entry, 0, timeout=2000000, count=LIMIT)
    if errors or len(result) != 1:
        raise ValueError(f"Oracle failed or reached limit: {errors}")
    return result[0]


def compile_ir(ctx, variable, node, output):
    from llvmlite import binding as llvm
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    text = ctx.liftToLLVM(node)
    (output / "recovered.ll").write_text(text + "\n", encoding="utf-8")
    module = llvm.parse_assembly(text)
    module.verify()
    fn = module.get_function("__triton")
    args = list(fn.arguments)
    if str(fn.global_value_type) != "i64 (i64)" or len(args) != 1 or args[0].name != f"SymVar_{variable.getId()}":
        raise ValueError(f"Unexpected LLVM input mapping: {fn.global_value_type}")
    before = sum(1 for block in fn.blocks for _ in block.instructions)
    target = llvm.Target.from_default_triple().create_target_machine(opt=3)
    module.triple = llvm.get_default_triple()
    module.data_layout = str(target.target_data)
    options = llvm.create_pipeline_tuning_options(speed_level=3)
    builder = llvm.create_pass_builder(target, options)
    manager = builder.getModulePassManager()
    manager.run(module, builder)
    module.verify()
    after = sum(1 for block in module.get_function("__triton").blocks for _ in block.instructions)
    (output / "optimized.ll").write_text(str(module), encoding="utf-8")
    (output / "recovered.s").write_text(target.emit_assembly(module), encoding="utf-8")
    (output / "recovered.obj").write_bytes(target.emit_object(module))
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(""), target)
    engine.add_module(module)
    engine.finalize_object()
    address = engine.get_function_address("__triton")
    if not address:
        raise ValueError("Missing JIT function")
    function = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(address)
    return engine, function, before, after


def run_case(index, run_dir, random_cases=64):
    path = INPUTS / f"tigress-challenges/tigress-0-challenge-{index}"
    if hashlib.sha256(path.read_bytes()).hexdigest() != HASHES[index]:
        raise ValueError("VM-0 binary hash mismatch")
    output = run_dir / path.name
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    image = Image(path)
    ctx, variable, node, data = explore(image)
    variable_name = str(ctx.getAstContext().variable(variable))
    (output / "coverage_query.smt2").write_text(
        f"(set-logic QF_BV)\n(declare-fun {variable_name} () (_ BitVec 64))\n"
        f"(assert (not {data['coverage_condition']}))\n(check-sat)\n", encoding="utf-8")
    engine, native, before, after = compile_ir(ctx, variable, node, output)
    edges = [0, 1, 2, 1234, 255, 256, 65535, 65536, (1 << 31)-1, 1 << 31,
             (1 << 32)-1, 1 << 32, (1 << 63)-1, 1 << 63, MASK-1, MASK]
    rng = random.Random(20261125)
    values = edges + [rng.getrandbits(64) for _ in range(random_cases)]
    values += [info["seed"] for info in data["paths"] if info["seed"] not in values]
    observations = []
    for value in values:
        expected = concrete_oracle(image, value)
        ctx.setConcreteVariableValue(variable, value)
        symbolic_value, compiled = node.evaluate(), native(value)
        observations.append({"input": value, "unicorn": expected, "symbolic": symbolic_value, "compiled": compiled})
        if not expected == symbolic_value == compiled:
            (output / "counterexample.json").write_text(json.dumps(observations[-1], indent=2), encoding="utf-8")
            raise ValueError(f"Mismatch for input {value}: oracle={expected}, AST={symbolic_value}, native={compiled}")
    data.update({"sample": path.name, "sha256": HASHES[index], "pairs": len(values),
                 "ir_before": before, "ir_after": after, "seconds": time.perf_counter()-started,
                 "status": "passed", "observations": observations})
    (output / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"{path.name}: {data['instructions']} symbolic instructions; IR {before}->{after}; {len(values)} Unicorn/AST/native comparisons passed", flush=True)
    return data


def write_report(rows, run_dir, tests=None):
    now = datetime.now(timezone(timedelta(hours=8))).isoformat()
    passed = [row for row in rows if row["status"] == "passed"]
    lines = ["# Tigress VM-0 函式語義還原研究報告", "", f"報告產生時間：{now}。", "",
             f"本輪完成 {len(passed)} / {len(rows)} 個樣本的自動路徑探索、LLVM 還原及交叉比對。",
             "這是 VM-0 的函式語義還原實驗，尚未宣稱符合官方可讀 C 與迴圈結構恢復標準。", "",
             "## 結果", "", "| 樣本 | 路徑數 | 合計符號執行指令 | IR 指令數 | 最佳化後 | 三方比對組數 | 結果 |",
             "|---|---:|---:|---:|---:|---:|---|"]
    for row in rows:
        if row["status"] == "passed":
            lines.append(f"| {row['sample']} | {row['path_count']} | {row['instructions']} | {row['ir_before']} | {row['ir_after']} | {row['pairs']} | 通過 |")
        else:
            lines.append(f"| {row['sample']} | — | — | — | — | — | 失敗：{row['error']} |")
    lines += ["", f"三方比對共 {sum(row['pairs'] for row in passed)} 組：Unicorn 模擬原始 ELF、Triton 還原表達式求值，以及編譯後函式的本機執行。IR 指令數包含 ret，不是執行加速倍數。", "",
              "## 材料與實驗方法", "",
              f"使用 [公開研究倉庫固定版本](https://github.com/JonathanSalwan/Tigress_protection/tree/{EXPECTED_REVISION}) 的 VM-0 五個 ELF。每檔核對預期 SHA-256；上游 solve-vm.py 僅作方法參考，實驗未執行其程式或使用其既有還原 IR。", "",
              "本地以 LIEF 解析載入段與 GOT，將原始 ELF 的 x64 指令送入 Triton 執行。只模擬 __libc_start_main、十進位 strtoul 及固定格式 printf；其他外部呼叫立即拒絕。輸入在 strtoul 的 RAX 結果符號化為 64 位元變數，輸出取 printf 的 RSI。", "",
              "初次執行只分析一條路徑時，樣本 1、2、4 被拒絕，因此新增符號路徑探索。求解尚未覆蓋的條件得到下一個輸入，清除前一路徑的符號記憶體與暫存器綁定，重設堆疊並重新執行。最多探索八條；超過上限或求解不確定均不算成功。", "",
              "把所有路徑條件的聯集取反後查詢為 UNSAT，並逐路徑檢查合併表達式與該路徑輸出不等的查詢為 UNSAT。這證明的是已建立模型中的覆蓋與合併一致性，不是對整個真實程式與作業系統的等價證明。", "",
              "每個成功樣本使用 16 組固定邊界值、64 組固定種子隨機 64 位元輸入，以及尚未列入的求解器探索輸入。隨機種子為 20261125。每組輸入重新以 Unicorn 模擬 ELF，與 AST 及本機函式的數值比對。", "",
              "## 交叉驗證的獨立性與限制", "",
              "Unicorn 與 Triton 是不同的 CPU 指令引擎，但共用 ELF 解析與外部函式契約。此比對能提供指令語義及編譯結果的交叉檢查，不能排除共同載入模型錯誤；沒有在 Linux 作業系統下原生執行 ELF。", "",
              "未知外部呼叫、輸入相依記憶體位址及不支援指令會停止實驗。原生函式求值測試是有限輸入，不能替代整個 64 位元定義域的獨立正確性證明。官方挑戰要求可讀 C、迴圈及資料結構；目前輸出為 LLVM IR、組合語言和目的檔，未恢復高階 C 結構。[官方規則](https://tigress.cs.arizona.edu/challenges.html)", "",
              "## 產物與重現", "",
              "一鍵執行：在倉庫根目錄執行 `& VMP/research/start_tigress.ps1`。", "",
              f"本次目錄：`{run_dir.relative_to(HERE).as_posix()}`。每個樣本保存 recovered.ll、optimized.ll、recovered.s、recovered.obj 與 results.json；JSON 包含路徑探索輸入、條件和逐筆三方比對。失敗記錄保留於歷史執行目錄。", "",
              "本輪以五個樣本為一組統計，與 VMP 的五組案例分開；目前研究增量是從既有 VMP trace 重播擴充到 ELF 指令模擬及自動求解多路徑。下一階段需補上原始 ELF 的原生執行對照與高階結構恢復。", ""]
    if tests is not None:
        lines += ["## 回歸測試", "", f"四項專用回歸測試：{'通過' if tests.returncode == 0 else '失敗'}。檢查上游已知輸出、路徑預算不足時拒絕、同一符號 context 重播後既有表達式仍正確，以及拒絕輸入相依的間接跳轉。完整輸出見 tests.txt。", ""]
    report = "\n".join(lines)
    (HERE / "TIGRESS_REPORT.md").write_text(report, encoding="utf-8")
    (run_dir / "TIGRESS_REPORT.md").write_text(report, encoding="utf-8")
    import unicorn
    environment = {"python": sys.version, "triton": version("triton-library"),
                   "llvmlite": version("llvmlite"), "lief": version("lief"),
                   "unicorn_python": unicorn.__version__, "unicorn_native": unicorn.uc_version(),
                   "source_revision": EXPECTED_REVISION,
                   "analysis_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (run_dir / "environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    (run_dir / "downloads.tsv").write_bytes((INPUTS / "downloads.tsv").read_bytes())
    with ZipFile(run_dir / "tigress_bundle.zip", "w", compression=ZIP_DEFLATED) as archive:
        for path in run_dir.rglob("*"):
            if path.is_file() and path.name != "tigress_bundle.zip":
                archive.write(path, path.relative_to(run_dir).as_posix())
        for name in ("tigress_vm0.py", "fetch_tigress.py", "start_tigress.ps1", "requirements-tigress.txt", "requirements.txt", "tigress_tests.py"):
            if (HERE / name).exists():
                archive.write(HERE / name, "project/" + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, choices=range(5))
    parser.add_argument("--random-cases", type=int, default=64)
    args = parser.parse_args()
    if args.random_cases < 0:
        parser.error("random-cases must be nonnegative")
    if (INPUTS / "revision.txt").read_text().strip() != EXPECTED_REVISION:
        parser.error("Unexpected source revision")
    run_dir = HERE / "generated/tigress" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir.mkdir(parents=True)
    rows = []
    for index in range(5) if args.sample is None else [args.sample]:
        try:
            rows.append(run_case(index, run_dir, args.random_cases))
        except Exception as error:
            row = {"sample": f"tigress-0-challenge-{index}", "status": "failed", "error": str(error)}
            rows.append(row)
            target = run_dir / row["sample"]
            target.mkdir(parents=True, exist_ok=True)
            (target / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
            print(json.dumps(row), flush=True)
    (run_dir / "results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(HERE), "-p", "tigress_tests.py"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    (run_dir / "tests.txt").write_text(tests.stdout + tests.stderr, encoding="utf-8")
    print(tests.stdout + tests.stderr, end="", flush=True)
    write_report(rows, run_dir, tests)
    print("Run directory:", run_dir, flush=True)
    return int(any(row["status"] != "passed" for row in rows) or tests.returncode != 0)


if __name__ == "__main__":
    sys.exit(main())
