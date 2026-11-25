"""Extend the trace analysis to sample3 and exhaust its 8-bit input domain."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

from native_verify import argument_order
from fetch_extension import HASHES, BASE, ASSETS

HERE = Path(__file__).resolve().parent
MASK = 0xFFFFFFFF


def source_model(x, y):
    """Source-derived MBA with explicit wrapping arithmetic; output is an 8-bit pattern."""
    x = x if x < 128 else x - 256
    y = y if y < 128 else y - 256
    a = (229 * x + 247) & MASK
    b = (237 * a + 214 + ((38 * a + 85) & 254)) & MASK
    c = ((b + ((-(2 * b) + 255) & 254)) * 3 + 77) & MASK
    d = ((86 * c + 36) & 70) * 75 + 231 * c + 118
    d &= MASK
    e = ((58 * d + 175) & 244) + 99 * d + 46
    e &= MASK
    f = e & 148
    g = ((f - (e & 255) + f) * 103 + 13) & MASK
    return ((237 * (45 * g + (174 * g | 34) * 229 + 194 - 247) & 255) + y) & 255


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.run_dir / "mba"
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    for name, expected in HASHES.items():
        if hashlib.sha256((HERE / "inputs/mba" / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"SHA256 mismatch: {name}")
    source = HERE.parent / "03_multipath/merge.py"
    spec = importlib.util.spec_from_file_location("mba_replay", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    from triton import ARCH, MODE, SOLVER_STATE, TritonContext
    ctx = TritonContext(ARCH.X86_64)
    ctx.setSolverTimeout(120000)
    for mode in (MODE.ALIGNED_MEMORY, MODE.AST_OPTIMIZATIONS, MODE.CONSTANT_FOLDING):
        ctx.setMode(mode, True)
    variables = []
    path = module.replay(ctx, HERE / "inputs/mba/sample3.vmp.trace", variables)
    if path.sites:
        raise ValueError("New case has input-dependent memory addresses; one-path model is insufficient")
    ast = ctx.getAstContext()
    raw = ast.extract(7, 0, path.result)
    x, y = [ast.variable(v) for v in variables]
    expected = ast.extract(7, 0, (x ^ 92) + y)
    _, status, _ = ctx.getModel(raw != expected, status=True)
    if status != SOLVER_STATE.UNSAT:
        raise ValueError(f"Sample3 8-bit equivalence not proved: status {status}")
    (output / "recovered.ll").write_text(ctx.liftToLLVM(raw) + "\n", encoding="utf-8")
    from llvmlite import binding as llvm
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    recovered = llvm.parse_assembly((output / "recovered.ll").read_text(encoding="utf-8"))
    recovered.verify()
    target = llvm.Target.from_default_triple().create_target_machine(opt=3)
    recovered.triple = llvm.get_default_triple()
    recovered.data_layout = str(target.target_data)
    fn = recovered.get_function("__triton")
    if str(fn.global_value_type) != "i8 (i32, i32)":
        raise ValueError(f"Unexpected signature: {fn.global_value_type}")
    order = argument_order(fn)
    before = sum(1 for block in fn.blocks for _ in block.instructions)
    tuning = llvm.create_pipeline_tuning_options(speed_level=3)
    builder = llvm.create_pass_builder(target, tuning)
    manager = builder.getModulePassManager()
    manager.run(recovered, builder)
    recovered.verify()
    after = sum(1 for block in recovered.get_function("__triton").blocks for _ in block.instructions)
    (output / "optimized.ll").write_text(str(recovered), encoding="utf-8")
    (output / "recovered.s").write_text(target.emit_assembly(recovered), encoding="utf-8")
    (output / "recovered.obj").write_bytes(target.emit_object(recovered))
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(""), target)
    engine.add_module(recovered)
    engine.finalize_object()
    address = engine.get_function_address("__triton")
    if not address:
        raise ValueError("Missing compiled function")
    native = ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint32)(address)
    cases = 0
    for x_value in range(256):
        for y_value in range(256):
            values = (x_value, y_value)
            got = native(*(values[index] for index in order))
            simple = ((x_value ^ 92) + y_value) & 255
            original = source_model(x_value, y_value)
            if not got == simple == original:
                raise ValueError(f"Mismatch x={x_value}, y={y_value}: native={got}, simple={simple}, MBA={original}")
            cases += 1
    # Verify that high input bits do not affect the low-byte contract at the native boundary.
    upper_cases = 0
    for x_value in (0, 1, 127, 128, 255):
        for y_value in (0, 1, 127, 128, 255):
            for upper in (0x100, 0x7FFFFF00, 0xFFFFFF00):
                values = (upper | x_value, upper | y_value)
                got = native(*(values[index] for index in order))
                if got != (((x_value ^ 92) + y_value) & 255):
                    raise ValueError("Unexpected dependence on upper input bits")
                upper_cases += 1
    data = {"sample": "sample3", "time_utc": datetime.now(timezone.utc).isoformat(),
            "instructions": path.instructions, "trace_inputs": path.inputs,
            "virtual_branch_sites": len(path.sites), "smt": "UNSAT", "contract": "return low8((x XOR 92) + y)",
            "native_exhaustive_pairs": cases, "upper_bit_checks": upper_cases,
            "ir_before": before, "ir_after": after, "argument_order": order,
            "flag_corrections": path.flag_corrections, "seconds": time.perf_counter() - started,
            "hashes": HASHES, "source_urls": {name: BASE + relative for name, relative in ASSETS.items()},
            "replayer_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "status": "passed"}
    (output / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps(data, indent=2), flush=True)


if __name__ == "__main__":
    main()
