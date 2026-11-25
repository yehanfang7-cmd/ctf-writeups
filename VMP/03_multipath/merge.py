"""Merge two VMProtect traces of a branching pure function and prove the merged result.

The virtual branch is located automatically: VMProtect selects the next virtual
block through an input-dependent memory address, not a native jcc. The condition
"address == value observed in this trace" is that trace's path condition.
"""
import argparse
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
REGISTER_ORDER = "rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
MASK32 = 0xFFFFFFFF
FLAG_BITS = {"cf": 0x1, "pf": 0x4, "af": 0x10, "zf": 0x40, "sf": 0x80, "of": 0x800}


def s32(value):
    return value - (1 << 32) if value >> 31 else value


# Each sample is pinned by SHA-256 so its C-derived oracle cannot be applied to another trace.
SAMPLES = {
    "sample4": {
        # Needs the flag-correction ordering fix: without it the signed compare loses SF (see writeup).
        "status": "verified",
        "source": "da01cd6f8a4b3a1a5f0d6289bf1b3103f1fa560ed03a5cbc1c38e9be001d02de",
        "traces": ("e54a4323f23bf3ad481aebf71385d6a2d8b80682674b2d8a138434624a77ff02",
                   "2d1aae4d2fddf1fc3f28c10266fc3a68e08b44477dec67f379414215cde22d06"),
        "c": "int secret(int x, int y) { return x >= y ? x : y; }",
        "oracle": lambda ast, x, y: ast.ite(ast.bvsge(x, y), x, y),
        "reference": lambda x, y: x if s32(x) >= s32(y) else y,
        "edges": [(5, 5), (0, 0x80000000), (0x7FFFFFFF, 0x80000000), (0xFFFFFFFF, 0)],
    },
    "sample5": {
        "status": "verified",
        "source": "4a4a4cab88d19e29178a1db0b890599a89395db0a525419ee39a9e24346daa3e",
        "traces": ("fe78089e4be602e75921f13861db58764435d3186211e2d0013a8ec7163f1017",
                   "be80affee738b521253f7e2c3e438c5a694f26aa37afe66ecc79418c6ea0c936"),
        "c": "int secret(int x, int y) { return x + y == 1001 ? x + 1 : y - 1; }",
        "oracle": lambda ast, x, y: ast.ite(x + y == 1001, x + 1, y - 1),
        "reference": lambda x, y: (x + 1) & MASK32 if (x + y) & MASK32 == 1001 else (y - 1) & MASK32,
        "edges": [(1000, 1), (1001, 0), (0, 1001), (1002, 0xFFFFFFFF), (0x80000000, 0x800003E9)],
    },
    "sample6": {
        "status": "verified",
        "source": "12472198c9ed06dc0a2d952e090559181dc58b6933f053e4836f8479f1901d17",
        "traces": ("2ff85b4d4ac080a58a6ef9e93829cb5443f7ef33e5a9b49b4b18a7950b96b729",
                   "d06ad3b2fd1a4f2e152d933ca061c7285052b1fb7f49f014575283f751d6d785"),
        "c": "unsigned secret(unsigned x, unsigned y) { return x + y < 1234 ? x + 1 : y - 1; }",
        "oracle": lambda ast, x, y: ast.ite(ast.bvult(x + y, ast.bv(1234, 32)), x + 1, y - 1),
        "reference": lambda x, y: (x + 1) & MASK32 if (x + y) & MASK32 < 1234 else (y - 1) & MASK32,
        "edges": [(1233, 0), (1234, 0), (0, 1233), (0xFFFFFFFF, 1), (0xFFFFFFFF, 1235)],
    },
}


@dataclass
class Site:
    """One instruction whose memory address depends on the inputs."""
    index: int
    address: int
    disassembly: str
    lea: object
    value: int


@dataclass
class PathResult:
    trace: Path
    inputs: tuple
    instructions: int
    result: object
    sites: list
    register_syncs: int = 0
    memory_syncs: int = 0
    flag_corrections: dict = field(default_factory=dict)
    divergences: list = field(default_factory=list)
    output_lines: list = field(default_factory=list)
    stale_flags_dropped: dict = field(default_factory=dict)


def depends_on_input(node):
    """Whether an AST contains a symbolic variable.

    Do not use ctx.isRegisterSymbolized()/isMemorySymbolized(): in triton-library 1.0.0rc4 they
    can return False for a register whose AST is input-dependent (seen after a load from a
    symbolic stack slot), which would let a real divergence be overwritten silently.
    """
    return node.isSymbolized()


def undefined_flags(instruction, count):
    """Flags that Intel SDM leaves undefined after this instruction (count = shift/rotate amount)."""
    from triton import OPCODE

    x86 = OPCODE.X86
    kind = instruction.getType()
    if kind in (x86.AND, x86.OR, x86.XOR, x86.TEST):
        return FLAG_BITS["af"]
    if kind in (x86.SHL, x86.SAL, x86.SHR, x86.SAR, x86.SHLD, x86.SHRD):
        if count == 0:
            return 0
        return FLAG_BITS["af"] | (FLAG_BITS["of"] if count != 1 else 0)
    if kind in (x86.ROL, x86.ROR, x86.RCL, x86.RCR):
        return FLAG_BITS["of"] if count not in (0, 1) else 0
    if kind in (x86.BT, x86.BTS, x86.BTR, x86.BTC):
        return FLAG_BITS["of"] | FLAG_BITS["sf"] | FLAG_BITS["af"] | FLAG_BITS["pf"]
    if kind in (x86.MUL, x86.IMUL):
        return FLAG_BITS["sf"] | FLAG_BITS["zf"] | FLAG_BITS["af"] | FLAG_BITS["pf"]
    if kind in (x86.BSF, x86.BSR):
        return FLAG_BITS["cf"] | FLAG_BITS["of"] | FLAG_BITS["sf"] | FLAG_BITS["af"] | FLAG_BITS["pf"]
    return 0


def shift_count(ctx, instruction):
    operands = instruction.getOperands()
    if len(operands) < 2:
        return 1  # one-operand shift/rotate forms shift by one
    from triton import OPERAND

    source = operands[-1]
    if source.getType() == OPERAND.IMM:
        raw = source.getValue()
    else:
        raw = ctx.getConcreteRegisterValue(ctx.registers.cl)
    return raw & (0x3F if operands[0].getBitSize() == 64 else 0x1F)


def replay(ctx, trace, variables, diagnose=False, observer=None):
    """Replay one trace in ctx. variables is shared across traces so their ASTs can be merged.

    observer(index, instruction) is called after each instruction (used for diagnosis).
    """
    from triton import EXCEPTION, Instruction, MemoryAccess, OPCODE

    ast = ctx.getAstContext()
    # Start from a clean symbolic state: trace 1 must not leak expressions into trace 2.
    ctx.concretizeAllMemory()
    ctx.concretizeAllRegister()
    ctx.clearPathConstraints()
    out = PathResult(trace, (), 0, None, [])
    snapshot_pending, started = False, False
    undefined_mask = 0           # flags currently holding undefined values
    pushed = {}                  # stack address -> undefined mask captured by PUSHFQ
    count_before = 0
    for line_number, line in enumerate(trace.read_text(encoding="ascii").splitlines(), 1):
        fields = line.split(":")
        if fields[0] == "r":
            if len(fields) != 17 or snapshot_pending:
                raise ValueError(f"{trace.name}:{line_number}: malformed register snapshot")
            for name, raw in zip(REGISTER_ORDER, fields[1:]):
                register = getattr(ctx.registers, name)
                observed = int(raw, 16)
                if ctx.getConcreteRegisterValue(register) != observed:
                    if depends_on_input(ctx.getRegisterAst(register)):
                        message = f"{trace.name}:{line_number}: symbolic register {name} diverged"
                        if not diagnose:
                            raise ValueError(message)
                        out.divergences.append(message)
                    ctx.setConcreteRegisterValue(register, observed)
                    out.register_syncs += 1
            snapshot_pending = True
        elif fields[0] == "mr":
            if len(fields) != 4:
                raise ValueError(f"{trace.name}:{line_number}: malformed memory snapshot")
            memory = MemoryAccess(int(fields[1], 16), int(fields[2]))
            observed = int(fields[3], 16)
            model = ctx.getConcreteMemoryValue(memory)
            if model != observed:
                corrected = None
                if depends_on_input(ctx.getMemoryAst(memory)):
                    delta = model ^ observed
                    allowed = pushed.get(memory.getAddress()) if memory.getSize() == 8 else None
                    if allowed is None or delta & ~allowed:
                        message = (f"{trace.name}:{line_number}: symbolic memory diverged at "
                                   f"{memory.getAddress():#x} delta={delta:#x} allowed={allowed}")
                        if not diagnose:
                            raise ValueError(message)
                        out.divergences.append(message)
                    else:
                        # Only bits of flags that were undefined when PUSHFQ stored them are taken
                        # from the recording; every other bit of the AST is kept.
                        flags = ctx.getMemoryAst(memory)
                        corrected = (flags & ast.bv(~delta & (2**64 - 1), 64)) | ast.bv(observed & delta, 64)
                        for name, bit in FLAG_BITS.items():
                            if delta & bit:
                                out.flag_corrections[name] = out.flag_corrections.get(name, 0) + 1
                # setConcreteMemoryValue() concretizes the cell, discarding its AST, so it must run
                # before the corrected expression is assigned. In the reverse order the input-
                # dependent SF/ZF/... bits of the pushed flags are silently lost.
                ctx.setConcreteMemoryValue(memory, observed)
                if corrected is not None:
                    ctx.assignSymbolicExpressionToMemory(ctx.newSymbolicExpression(corrected), memory)
                    if not depends_on_input(ctx.getMemoryAst(memory)) and depends_on_input(corrected):
                        raise ValueError(f"{trace.name}:{line_number}: corrected flags lost their AST")
                out.memory_syncs += 1
        elif fields[0] == "i":
            if len(fields) != 4 or not snapshot_pending:
                raise ValueError(f"{trace.name}:{line_number}: instruction without register snapshot")
            address, size, opcode = int(fields[1], 16), int(fields[2]), bytes.fromhex(fields[3])
            if len(opcode) != size:
                raise ValueError(f"{trace.name}:{line_number}: wrong instruction size")
            if not started:
                # Linux x64 SysV: secret(int x, int y) receives x in EDI and y in ESI.
                out.inputs = (ctx.getConcreteRegisterValue(ctx.registers.edi),
                              ctx.getConcreteRegisterValue(ctx.registers.esi))
                if not variables:
                    variables += [ctx.symbolizeRegister(ctx.registers.edi, "x"),
                                  ctx.symbolizeRegister(ctx.registers.esi, "y")]
                else:
                    for variable, parent, value in zip(variables, (ctx.registers.rdi, ctx.registers.rsi),
                                                       out.inputs):
                        ctx.setConcreteVariableValue(variable, value)
                        upper = ast.bv(ctx.getConcreteRegisterValue(parent) >> 32, 32)
                        expression = ast.concat([upper, ast.variable(variable)])
                        ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(expression), parent)
                started = True
            instruction = Instruction(address, opcode)
            ctx.disassembly(instruction)
            count_before = shift_count(ctx, instruction) if instruction.getType() in (
                OPCODE.X86.SHL, OPCODE.X86.SAL, OPCODE.X86.SHR, OPCODE.X86.SAR, OPCODE.X86.SHLD,
                OPCODE.X86.SHRD, OPCODE.X86.ROL, OPCODE.X86.ROR, OPCODE.X86.RCL, OPCODE.X86.RCR) else 1
            if ctx.processing(instruction) != EXCEPTION.NO_FAULT:
                raise ValueError(f"{trace.name}:{line_number}: unsupported instruction {instruction}")
            out.instructions += 1
            if observer:
                observer(out.instructions, instruction)
            if instruction.isControlFlow() and ctx.getRegisterAst(ctx.registers.rip).isSymbolized():
                raise ValueError(f"{trace.name}:{line_number}: input-dependent native control flow is out of scope")
            for access, _ in instruction.getLoadAccess() + instruction.getStoreAccess():
                lea = access.getLeaAst()
                if lea is not None and lea.isSymbolized():
                    out.sites.append(Site(out.instructions, address, instruction.getDisassembly(),
                                          lea, lea.evaluate()))
            for written, _ in instruction.getStoreAccess():
                start, end = written.getAddress(), written.getAddress() + written.getSize()
                pushed = {slot: mask for slot, mask in pushed.items() if not (start < slot + 8 and slot < end)}
            written_flags = 0
            for register, _ in instruction.getWrittenRegisters():
                written_flags |= FLAG_BITS.get(register.getName(), 0)
            now_undefined = undefined_flags(instruction, count_before)
            # Triton leaves an architecturally undefined flag unchanged, so it would keep a stale
            # input-dependent AST (e.g. AF from an earlier CMP). The CPU replaced that value, so the
            # dependency is spurious: drop it now. If it only matched the recording by luck, keeping
            # it would silently corrupt a later path condition.
            for name, bit in FLAG_BITS.items():
                if now_undefined & bit:
                    flag = getattr(ctx.registers, name)
                    if depends_on_input(ctx.getRegisterAst(flag)):
                        out.stale_flags_dropped[name] = out.stale_flags_dropped.get(name, 0) + 1
                    ctx.concretizeRegister(flag)
            undefined_mask = (undefined_mask & ~written_flags) | now_undefined
            if instruction.getType() == OPCODE.X86.PUSHFQ and undefined_mask:
                pushed[ctx.getConcreteRegisterValue(ctx.registers.rsp)] = undefined_mask
            snapshot_pending = False
        else:
            # Pin wrote the target's stdout/stderr into the same file (VMProtect demo banner,
            # "> result", a missing zenity). These lines carry no CPU state; they are counted.
            out.output_lines.append(line)
    if snapshot_pending or not out.instructions:
        raise ValueError(f"{trace.name}: incomplete trace")
    if ctx.getPathPredicate().isSymbolized():
        raise ValueError(f"{trace.name}: native jcc path constraint found; this lab expects VM-only branches")
    out.result = ctx.getRegisterAst(ctx.registers.eax)
    return out


def solve(ctx, constraint):
    from triton import SOLVER_STATE

    model, status, _ = ctx.getModel(constraint, status=True)
    if status not in (SOLVER_STATE.SAT, SOLVER_STATE.UNSAT):
        raise ValueError(f"Solver inconclusive (status {status})")
    return model if status == SOLVER_STATE.SAT else None


def proved(ctx, claim_negation):
    """True only when the negation of a claim is UNSAT."""
    return solve(ctx, claim_negation) is None


def evaluate(ctx, variables, node, x, y):
    ctx.setConcreteVariableValue(variables[0], x)
    ctx.setConcreteVariableValue(variables[1], y)
    return node.evaluate()


def path_condition(ast, path):
    if len(path.sites) != 1:
        found = ", ".join(f"{site.address:#x}" for site in path.sites) or "none"
        raise ValueError(f"{path.trace.name}: expected exactly one virtual branch, found {found}; "
                         "more traces or a richer path model are needed")
    site = path.sites[0]
    return ast.equal(site.lea, ast.bv(site.value, site.lea.getBitvectorSize()))


def merge_and_verify(ctx, variables, path1, path2, oracle, reference, edges):
    """Return (merged AST, report lines). Every check fails closed with ValueError."""
    ast = ctx.getAstContext()
    x, y = (ast.variable(variable) for variable in variables)
    cond1, cond2 = path_condition(ast, path1), path_condition(ast, path2)
    site1, site2 = path1.sites[0], path2.sites[0]
    if site1.address != site2.address:
        raise ValueError(f"Virtual branch differs: {site1.address:#x} vs {site2.address:#x}")
    for path, cond in ((path1, cond1), (path2, cond2)):
        if not evaluate(ctx, variables, cond, *path.inputs):
            raise ValueError(f"{path.trace.name}: its own inputs do not satisfy its path condition")
    # Coverage: the branch address has exactly two feasible values, one per trace.
    other = solve(ctx, ast.lnot(cond1))
    if other is None:
        raise ValueError("Branch address is constant: not a real two-way branch")
    alt_x, alt_y = (other[variable.getId()].getValue() for variable in variables)
    alt_value = evaluate(ctx, variables, site1.lea, alt_x, alt_y)
    width = site1.lea.getBitvectorSize()
    if not proved(ctx, ast.land([ast.lnot(cond1), site1.lea != ast.bv(alt_value, width)])):
        raise ValueError("Branch address can take more than two values: more traces are needed")
    if not proved(ctx, ast.lnot(ast.equal(cond2, ast.lnot(cond1)))):
        raise ValueError("Trace 2 does not take the complement of trace 1's branch")
    merged = ast.ite(cond1, path1.result, path2.result)
    expected = oracle(ast, x, y)
    try:  # display only: the proofs below use the unsimplified ASTs
        shown = str(ctx.simplify(cond1, solver=True))
    except Exception:  # Triton built without z3 simplification
        shown = "(z3 simplification unavailable)"
    for name, node in (("trace 1 path", ast.land([cond1, path1.result != expected])),
                       ("trace 2 path", ast.land([cond2, path2.result != expected])),
                       ("merged function", merged != expected)):
        counterexample = solve(ctx, node)
        if counterexample is not None:
            values = {variables[i].getName(): counterexample[v.getId()].getValue()
                      for i, v in enumerate(variables) if v.getId() in counterexample}
            raise ValueError(f"{name} differs from the C source, counterexample {values}")
    rng = random.Random(20261121)
    cases = list(edges) + [path1.inputs, path2.inputs, (alt_x, alt_y)]
    cases += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(1024)]
    for case in cases:
        if evaluate(ctx, variables, merged, *case) != reference(*case):
            raise ValueError(f"Evaluation mismatch for x={case[0]:#x}, y={case[1]:#x}")
    lines = [
        f"virtual branch: {site1.address:#x} `{site1.disassembly}` (trace 1 #{site1.index}, trace 2 #{site2.index})",
        f"branch address values: {site1.value:#x} (trace 1), {alt_value:#x} (other side); exactly two feasible",
        "trace 2 condition == NOT trace 1 condition: proved",
        f"trace 1 condition, z3-simplified for display: {shown[:400]}{' ...' if len(shown) > 400 else ''}",
        "each path == C source under its own condition: proved",
        "SMT: merged != C source is UNSAT, for 32-bit x/y",
        f"edge/random evaluations: {len(cases)} passed",
    ]
    return merged, lines


def check_hash(path, expected):
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"SHA256 mismatch for {path}; run python VMP/fetch_samples.py multipath")


def run_sample(name, out_dir, diagnose=False, input_dir=None):
    from triton import ARCH, MODE, TritonContext

    spec = SAMPLES[name]
    input_dir = Path(input_dir) if input_dir is not None else HERE / "inputs"
    check_hash(input_dir / f"{name}.c", spec["source"])
    traces = [input_dir / f"{name}.vmp.trace.{i}" for i in (1, 2)]
    for trace, expected in zip(traces, spec["traces"]):
        check_hash(trace, expected)
    ctx = TritonContext(ARCH.X86_64)
    for mode in (MODE.ALIGNED_MEMORY, MODE.AST_OPTIMIZATIONS, MODE.CONSTANT_FOLDING):
        ctx.setMode(mode, True)
    variables = []
    paths = [replay(ctx, trace, variables, diagnose) for trace in traces]
    lines = [f"== {name}: {spec['c']}"]
    for i, path in enumerate(paths, 1):
        flags = ", ".join(f"{k}={v}" for k, v in sorted(path.flag_corrections.items())) or "none"
        stale = ", ".join(f"{k}={v}" for k, v in sorted(path.stale_flags_dropped.items())) or "none"
        lines.append(f"trace {i}: inputs x={path.inputs[0]:#x} y={path.inputs[1]:#x}, "
                     f"{path.instructions} instructions, syncs reg={path.register_syncs} "
                     f"mem={path.memory_syncs}")
        lines.append(f"  stale symbolic flags dropped: {stale}; PUSHFQ undefined-bit corrections: {flags}")
        lines.append(f"  branch sites: {[hex(site.address) for site in path.sites]}; "
                     f"non-trace program output lines skipped: {len(path.output_lines)}")
        for message in path.divergences[:5]:
            lines.append(f"  DIVERGENCE {message}")
        if len(path.divergences) > 5:
            lines.append(f"  ... {len(path.divergences) - 5} more divergences")
    if diagnose:
        return "\n".join(lines) + "\n"
    merged, checks = merge_and_verify(ctx, variables, *paths, spec["oracle"], spec["reference"], spec["edges"])
    lines += checks
    llvm = ctx.liftToLLVM(merged)
    lines.append(f"LLVM IR: {sum(1 for l in llvm.splitlines() if l.startswith('  %'))} instructions "
                 "(unoptimized; optionally run `opt -S -O3`)")
    lines.append("scope: two recorded traces of one binary; no new native execution or whole-EXE rebuild")
    target = out_dir / name
    target.mkdir(parents=True, exist_ok=True)
    (target / "recovered.ll").write_text(llvm + "\n", encoding="utf-8")
    report = "\n".join(lines) + "\n"
    (target / "verification.txt").write_text(report, encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    verified = [name for name, spec in SAMPLES.items() if spec["status"] == "verified"]
    parser.add_argument("samples", nargs="*", metavar="sample",
                        help=f"default: verified samples ({', '.join(verified)}); also: "
                             + ", ".join(n for n in SAMPLES if n not in verified))
    parser.add_argument("--out", type=Path, default=HERE / "generated")
    parser.add_argument("--inputs", type=Path, default=HERE / "inputs",
                        help="Directory containing pinned C sources and traces")
    parser.add_argument("--diagnose", action="store_true",
                        help="Replay without failing on divergences and report them; no merge or proof")
    args = parser.parse_args()
    unknown = sorted(set(args.samples) - set(SAMPLES))
    if unknown:
        parser.error(f"unknown sample(s): {', '.join(unknown)}")
    failures = 0
    try:
        for name in args.samples or verified:
            try:
                print(run_sample(name, args.out, args.diagnose, args.inputs), end="", flush=True)
            except ValueError as error:
                failures += 1
                note = " (known open problem, see writeup)" if SAMPLES[name]["status"] == "open" else ""
                print(f"== {name}: FAILED{note}: {error}", flush=True)
    except ImportError:
        parser.exit(1, "Install dependencies: python -m pip install -r VMP/02_vmp_trace/requirements.txt\n")
    except OSError as error:
        parser.exit(1, f"error: {error}\n")
    if failures:
        parser.exit(1, f"{failures} sample(s) failed\n")


if __name__ == "__main__":
    main()
