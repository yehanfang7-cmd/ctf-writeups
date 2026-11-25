"""Compile recovered LLVM IR and compare actual machine-code output to independent models."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random

MASK = 0xFFFFFFFF


def argument_order(function):
    """LLVM preserves formal parameter order, which Triton need not emit in variable-ID order."""
    names = [argument.name for argument in function.arguments]
    if sorted(names) != ["SymVar_0", "SymVar_1"]:
        raise ValueError(f"Unsupported symbolic input mapping: {names}")
    return [int(name.removeprefix("SymVar_")) for name in names]


def signed(value):
    return value if value < 0x80000000 else value - 0x100000000


def reference(name, x, y):
    if name == "sample2":
        return x ^ y
    if name == "sample4":
        return x if signed(x) >= signed(y) else y
    condition = ((x + y) & MASK) == 1001 if name == "sample5" else ((x + y) & MASK) < 1234
    return ((x + 1) if condition else (y - 1)) & MASK


def cases(name):
    edges = [0, 1, 2, 1000, 1001, 1233, 1234, 0x7FFFFFFF, 0x80000000, MASK]
    result = [(x, y) for x in edges for y in edges]
    rng = random.Random(20261122)
    result += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(10000)]
    # Ensure both outcomes of rare equality and unsigned-threshold branches are exercised.
    if name in ("sample5", "sample6"):
        for _ in range(256):
            x = rng.getrandbits(32)
            total = 1001 if name == "sample5" else rng.randrange(1234)
            result.append((x, (total - x) & MASK))
    return result


def compile_and_check(name, path, output):
    from llvmlite import binding as llvm

    original = path.read_bytes()
    module = llvm.parse_assembly(original.decode("utf-8"))
    module.verify()
    target = llvm.Target.from_default_triple().create_target_machine(opt=3)
    module.triple = llvm.get_default_triple()
    module.data_layout = str(target.target_data)
    function = module.get_function("__triton")
    signature = function.global_value_type
    if str(signature) != "i32 (i32, i32)":
        raise ValueError(f"Unexpected recovered signature: {signature}")
    order = argument_order(function)
    before = sum(1 for block in function.blocks for _ in block.instructions)
    tuning = llvm.create_pipeline_tuning_options(speed_level=3)
    builder = llvm.create_pass_builder(target, tuning)
    manager = builder.getModulePassManager()
    manager.run(module, builder)
    module.verify()
    after = sum(1 for block in module.get_function("__triton").blocks for _ in block.instructions)
    destination = output / name
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "optimized.ll").write_text(str(module), encoding="utf-8")
    (destination / "recovered.s").write_text(target.emit_assembly(module), encoding="utf-8")
    object_data = target.emit_object(module)
    (destination / "recovered.obj").write_bytes(object_data)
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(""), target)
    engine.add_module(module)
    engine.finalize_object()
    address = engine.get_function_address("__triton")
    if not address:
        raise ValueError("JIT did not expose recovered function")
    native = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32)(address)
    inputs = cases(name)
    for x, y in inputs:
        values = (x, y)
        got, expected = native(*(values[index] for index in order)), reference(name, x, y)
        if got != expected:
            raise ValueError(f"{name} mismatch: x={x:#x}, y={y:#x}: {got:#x} != {expected:#x}")
    return {"sample": name, "cases": len(inputs), "ir_before": before, "ir_after": after,
            "object_bytes": len(object_data), "ir_sha256": hashlib.sha256(original).hexdigest(),
            "status": "passed", "target": module.triple, "argument_order": order}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    from llvmlite import binding as llvm
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    output = args.run_dir / "native"
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in ("sample2", "sample4", "sample5", "sample6"):
        relative = "xor/recovered.ll" if name == "sample2" else f"multipath/{name}/recovered.ll"
        row = compile_and_check(name, args.run_dir / relative, output)
        rows.append(row)
        print(f"{name}: {row['cases']} native evaluations passed; LLVM instructions "
              f"{row['ir_before']} -> {row['ir_after']}; object {row['object_bytes']} bytes", flush=True)
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
