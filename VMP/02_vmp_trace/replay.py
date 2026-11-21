"""Replay Salwan's pinned sample2 trace and verify the recovered 32-bit function."""
import argparse
import hashlib
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
TRACE_SHA256 = "735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443"
REGISTER_ORDER = "rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()


def replay(trace):
    from triton import ARCH, EXCEPTION, Instruction, MemoryAccess, MODE, OPCODE, TritonContext

    if hashlib.sha256(trace.read_bytes()).hexdigest() != TRACE_SHA256:
        raise ValueError("This lab supports only the pinned sample2 trace; SHA256 mismatch")
    ctx = TritonContext(ARCH.X86_64)
    for mode in (MODE.ALIGNED_MEMORY, MODE.AST_OPTIMIZATIONS, MODE.CONSTANT_FOLDING):
        ctx.setMode(mode, True)
    variables = []
    count, register_syncs, memory_syncs = 0, 0, 0
    snapshot_pending = False
    last_opcode, af_undefined = None, False
    undefined_flag_syncs = 0
    undefined_af_locations = set()
    for line_number, line in enumerate(trace.read_text(encoding="ascii").splitlines(), 1):
        fields = line.split(":")
        if fields[0] == "r":
            if len(fields) != 17 or snapshot_pending:
                raise ValueError(f"Malformed register snapshot on line {line_number}")
            for name, raw in zip(REGISTER_ORDER, fields[1:]):
                register = getattr(ctx.registers, name)
                observed = int(raw, 16)
                if ctx.getConcreteRegisterValue(register) != observed:
                    if ctx.isRegisterSymbolized(register):
                        raise ValueError(f"Symbolic register diverged at line {line_number}: {name}")
                    ctx.setConcreteRegisterValue(register, observed)
                    register_syncs += 1
            snapshot_pending = True
        elif fields[0] == "mr":
            if len(fields) != 4:
                raise ValueError(f"Malformed memory snapshot on line {line_number}")
            memory = MemoryAccess(int(fields[1], 16), int(fields[2]))
            observed = int(fields[3], 16)
            if ctx.getConcreteMemoryValue(memory) != observed:
                fixed = None
                if ctx.getMemoryAst(memory).isSymbolized():
                    delta = ctx.getConcreteMemoryValue(memory) ^ observed
                    if not (memory.getAddress() in undefined_af_locations
                            and memory.getSize() == 8 and delta == 0x10):
                        raise ValueError(f"Symbolic memory diverged at line {line_number}: observed={observed:#x}, model={ctx.getConcreteMemoryValue(memory):#x}, delta={delta:#x}, previous={last_opcode}, AF_undefined={af_undefined}")
                    # Logical x86 instructions leave AF undefined. The trace omits RFLAGS.
                    # Correct only the observed undefined AF bit; retain every other AST bit.
                    ast = ctx.getAstContext()
                    flags = ctx.getMemoryAst(memory)
                    fixed = (flags & ast.bv(0xffffffffffffffef, 64)) | ast.bv(observed & 0x10, 64)
                    undefined_flag_syncs += 1
                # setConcreteMemoryValue() discards the cell's AST, so assign the corrected
                # expression afterwards; the reverse order silently concretized every flag bit.
                ctx.setConcreteMemoryValue(memory, observed)
                if fixed is not None:
                    ctx.assignSymbolicExpressionToMemory(ctx.newSymbolicExpression(fixed), memory)
                memory_syncs += 1
        elif fields[0] == "i":
            if len(fields) != 4 or not snapshot_pending:
                raise ValueError(f"Instruction missing register snapshot on line {line_number}")
            address, size = int(fields[1], 16), int(fields[2])
            opcode = bytes.fromhex(fields[3])
            if len(opcode) != size:
                raise ValueError(f"Wrong instruction size on line {line_number}")
            if not variables:
                # The trace is from Linux x64 SysV, even when replayed on Windows.
                variables = [ctx.symbolizeRegister(ctx.registers.edi, "x"),
                             ctx.symbolizeRegister(ctx.registers.esi, "y")]
            instruction = Instruction(address, opcode)
            exception = ctx.processing(instruction)
            if exception != EXCEPTION.NO_FAULT:
                raise ValueError(f"Unsupported/faulting instruction: {instruction}")
            for written, _ in instruction.getStoreAccess():
                undefined_af_locations = {address for address in undefined_af_locations
                                          if not (written.getAddress() < address + 8
                                                  and address < written.getAddress() + written.getSize())}
            if instruction.getType() == OPCODE.X86.PUSHFQ and af_undefined:
                undefined_af_locations.add(ctx.getConcreteRegisterValue(ctx.registers.rsp))
            last_opcode = instruction.getType()
            if last_opcode in (OPCODE.X86.AND, OPCODE.X86.OR, OPCODE.X86.XOR, OPCODE.X86.TEST):
                af_undefined = True
            elif any(reg.getName() == "af" for reg, _ in instruction.getWrittenRegisters()):
                af_undefined = False
            count += 1
            snapshot_pending = False
        else:
            raise ValueError(f"Unknown trace record on line {line_number}")
    if snapshot_pending or not count:
        raise ValueError("Incomplete trace")
    return ctx, variables, count, register_syncs, memory_syncs, undefined_flag_syncs


def verify(ctx, variables, expression):
    from triton import SOLVER_STATE

    ast = ctx.getAstContext()
    expected = ast.variable(variables[0]) ^ ast.variable(variables[1])
    _, status, _ = ctx.getModel(expression != expected, status=True)
    if status != SOLVER_STATE.UNSAT:
        raise ValueError(f"Equivalence was not proved (solver status {status})")
    # This demo expects no input-dependent path restriction. Fail closed if that changes.
    if ctx.getPathPredicate().isSymbolized():
        raise ValueError("Input-dependent path predicate: a single trace is insufficient")
    edge = [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 0xaaaaaaaa, 0x55555555]
    cases = [(x, y) for x in edge for y in edge]
    rng = random.Random(20261004)
    cases += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(1024)]
    for x, y in cases:
        ctx.setConcreteVariableValue(variables[0], x)
        ctx.setConcreteVariableValue(variables[1], y)
        if expression.evaluate() != (x ^ y):
            raise ValueError(f"Evaluation mismatch for {x:#x}, {y:#x}")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, default=HERE / "inputs/sample2.vmp.trace")
    parser.add_argument("--out", type=Path, default=HERE / "generated")
    args = parser.parse_args()
    try:
        ctx, variables, count, reg_sync, mem_sync, flag_sync = replay(args.trace)
        raw = ctx.getRegisterAst(ctx.registers.eax)
        seed_result = raw.evaluate()
        # Prove against the unsynthesized expression so synthesis is not the oracle.
        cases = verify(ctx, variables, raw)
        simplified = ctx.synthesize(raw)
        if simplified is None:
            raise ValueError("Triton could not synthesize this expression")
        verify(ctx, variables, simplified)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "recovered.ll").write_text(ctx.liftToLLVM(simplified) + "\n", encoding="utf-8")
        (args.out / "expression.smt2.txt").write_text(str(ctx.getAstContext().unroll(raw)) + "\n", encoding="utf-8")
        summary = (
            f"trace SHA256: {TRACE_SHA256}\n"
            f"instructions replayed: {count}\n"
            f"recorded result (x=1, y=2): {seed_result}\n"
            f"concrete snapshot synchronizations: registers={reg_sync}, memory={mem_sync}\n"
            f"undefined AF snapshot corrections: {flag_sync}\n"
            f"recovered expression: {simplified}\n"
            f"SMT: recovered != (x XOR y) is UNSAT, for 32-bit x/y\n"
            f"edge/random evaluations: {cases} passed (raw and synthesized ASTs)\n"
            "scope: recorded pure-function trace; no new native execution or whole-EXE rebuild\n"
        )
        (args.out / "verification.txt").write_text(summary, encoding="utf-8")
        print(summary, end="")
    except ImportError:
        parser.exit(1, "Install dependencies: python -m pip install -r VMP/02_vmp_trace/requirements.txt\n")
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
