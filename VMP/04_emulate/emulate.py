"""Emulate Salwan's VMProtect-protected ELF samples on any OS, without Pin, and devirtualize them.

1. Learn the input-independent environment (CPUID result, the VMP runtime's heap object) from one
   recorded trace.
2. Check emulator fidelity: replay every recorded trace and require the same instruction addresses
   and the same value for every recorded memory read. Where a sample has two traces, the
   environment comes from the *other* trace.
3. Concolic exploration from the binary alone: symbolic x/y, every input-dependent memory address
   (VMP virtual branch) or native branch becomes a branch point; the solver produces inputs for
   the untaken side until no new path appears.
4. Merge the paths, prove the path conditions cover every input, and prove the merged expression
   equals the C source with SMT.
"""
import argparse
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import random
import struct
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
COMMIT = "d2b26d66db59e341f179c7e326246d28c4d25491"
BASE = f"https://raw.githubusercontent.com/JonathanSalwan/VMProtect-devirtualization/{COMMIT}/"
REGISTERS = "rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
CPUID_SUBLEAF = {4, 7, 0xB, 0xD, 0xF, 0x10, 0x12, 0x14, 0x17, 0x18}
ENTRY = 0x4011C0       # secret() in samples 1, 2, 4, 5, 6; sample3 overrides it
HEAP_SLOT = 0x616E00   # .vmp data cell the VMP runtime fills with a heap pointer at start-up
RETURN_SENTINEL = 0xDEAD0000
STACK = 0x7FFFFFFFD000
MASK32 = 0xFFFFFFFF


def s32(value):
    return value - (1 << 32) if value & 0x80000000 else value


def s8(value):
    return value - 256 if value & 0x80 else value


def sample3_reference(x, y):
    """C semantics of sample3.c on gcc/x86-64: signed char arguments, 32-bit wrapping int arithmetic."""
    def w(v):
        return s32(v & MASK32)
    x, y = s8(x), s8(y)
    a = w(229 * x + 247)
    b = w(237 * a + 214 + ((38 * a + 85) & 254))
    c = w((b + ((-(2 * b) + 255) & 254)) * 3 + 77)
    d = w(((86 * c + 36) & 70) * 75 + 231 * c + 118)
    e = w(((58 * d + 175) & 244) + 99 * d + 46)
    f = e & 148
    g = w((f - (e & 255) + f) * 103 + 13)
    r = w((w(237 * w(45 * g + w((174 * g | 34) * 229) + 194 - 247)) & 255) + y)
    return r & 0xFF


def sample3_oracle(ast, x8, y8):
    x, y = ast.sx(24, x8), ast.sx(24, y8)
    def k(v):
        return ast.bv(v & MASK32, 32)
    a = k(229) * x + k(247)
    b = k(237) * a + k(214) + ((k(38) * a + k(85)) & k(254))
    c = (b + ((k(0) - k(2) * b + k(255)) & k(254))) * k(3) + k(77)
    d = ((k(86) * c + k(36)) & k(70)) * k(75) + k(231) * c + k(118)
    e = ((k(58) * d + k(175)) & k(244)) + k(99) * d + k(46)
    f = e & k(148)
    g = (f - (e & k(255)) + f) * k(103) + k(13)
    r = ((k(237) * (k(45) * g + (k(174) * g | k(34)) * k(229) + k(194) - k(247))) & k(255)) + y
    return ast.extract(7, 0, r)


SAMPLES = {
    "sample1": {"width": 32, "binary": "b7b577bd569a10cdd1c660c28c8e78e8ae35af8add43f0f57766d899dbd03564",
                "source": "08744c704b5297c8d5634b29ba5aa9c6ceec9e6641d9058229933dadf3d673b7",
                "traces": {"sample1.vmp.trace": "f3538856d197490b1d3280cef45e5f2dfa4829308030fd6f8de39b2a77848f06"},
                "c": "x + y", "oracle": lambda ast, x, y: x + y,
                "reference": lambda x, y: (x + y) & MASK32},
    "sample2": {"width": 32, "binary": "d3e3f92c8cdad93e22d8eca0db4e306687716d612437574cc46bb79a677700e2",
                "source": "29304276e06d81a111fdde1b19c52266355c23de0e3a960fc941472ce1f010da",
                "traces": {"sample2.vmp.trace": "735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443"},
                "c": "x ^ y", "oracle": lambda ast, x, y: x ^ y, "reference": lambda x, y: x ^ y},
    "sample3": {"width": 8, "entry": 0x4011C9, "binary": "01fe0e95e8f202089aa13afe237d1dfd8f4ce98641a91acb9a5e2757c004f464",
                "source": "d66a8f75fed8968abef1dc44e62eb0b4962ab3107c5829b732599a1c59c29d47",
                "traces": {"sample3.vmp.trace": "8dbd08069f095f64966dfe960e350a872e8a0eef6cd0177ecd6db60a1346d846"},
                "c": "8-step MBA over signed char, returned as char",
                "oracle": sample3_oracle, "reference": sample3_reference},
    "sample4": {"width": 32, "binary": "f065eea78171fd8070c78ccb858b69d24182c826a33b3c3fb87ed297a3888935",
                "source": "da01cd6f8a4b3a1a5f0d6289bf1b3103f1fa560ed03a5cbc1c38e9be001d02de",
                "traces": {"sample4.vmp.trace.1": "e54a4323f23bf3ad481aebf71385d6a2d8b80682674b2d8a138434624a77ff02",
                           "sample4.vmp.trace.2": "2d1aae4d2fddf1fc3f28c10266fc3a68e08b44477dec67f379414215cde22d06"},
                "c": "x >= y ? x : y (signed)", "oracle": lambda ast, x, y: ast.ite(ast.bvsge(x, y), x, y),
                "reference": lambda x, y: x if s32(x) >= s32(y) else y},
    "sample5": {"width": 32, "binary": "81d2a1d1ad0ced2e2f23c4add44f27b8cf899b4947c2d4a248a84e0d2947ad58",
                "source": "4a4a4cab88d19e29178a1db0b890599a89395db0a525419ee39a9e24346daa3e",
                "traces": {"sample5.vmp.trace.1": "fe78089e4be602e75921f13861db58764435d3186211e2d0013a8ec7163f1017",
                           "sample5.vmp.trace.2": "be80affee738b521253f7e2c3e438c5a694f26aa37afe66ecc79418c6ea0c936"},
                "c": "x + y == 1001 ? x + 1 : y - 1",
                "oracle": lambda ast, x, y: ast.ite(x + y == 1001, x + 1, y - 1),
                "reference": lambda x, y: (x + 1) & MASK32 if (x + y) & MASK32 == 1001 else (y - 1) & MASK32},
    "sample6": {"width": 32, "binary": "1527da956e3483e907d35f63f9d6a54abb3148ea6e341dae21675ee7330175e4",
                "source": "12472198c9ed06dc0a2d952e090559181dc58b6933f053e4836f8479f1901d17",
                "traces": {"sample6.vmp.trace.1": "2ff85b4d4ac080a58a6ef9e93829cb5443f7ef33e5a9b49b4b18a7950b96b729",
                           "sample6.vmp.trace.2": "d06ad3b2fd1a4f2e152d933ca061c7285052b1fb7f49f014575283f751d6d785"},
                "c": "(unsigned)(x + y) < 1234 ? x + 1 : y - 1",
                "oracle": lambda ast, x, y: ast.ite(ast.bvult(x + y, ast.bv(1234, 32)), x + 1, y - 1),
                "reference": lambda x, y: (x + 1) & MASK32 if (x + y) & MASK32 < 1234 else (y - 1) & MASK32},
}


def inputs_for(name):
    spec = SAMPLES[name]
    files = {f"{name}.vmp.bin": ("vmp_binaries/binaries/", spec["binary"]),
             f"{name}.c": ("vmp_binaries/samples-source/", spec["source"])}
    files.update({trace: ("vmp_traces/", digest) for trace, digest in spec["traces"].items()})
    return files


def fetch(names, directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        for filename, (folder, digest) in inputs_for(name).items():
            path = directory / filename
            if not path.exists():
                with urlopen(BASE + folder + filename, timeout=60) as response:
                    path.write_bytes(response.read(64 * 1024 * 1024))
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"SHA256 mismatch for {path}")


# --------------------------------------------------------------------------- traces and ELF

@dataclass
class Step:
    address: int
    opcode: bytes
    registers: list
    reads: list


def read_trace(path, entry=ENTRY):
    registers, steps, reads = None, [], []
    for line in Path(path).read_text(encoding="ascii").splitlines():
        fields = line.split(":")
        if fields[0] == "r":
            registers = [int(v, 16) for v in fields[1:]]
        elif fields[0] == "mr":
            reads.append((int(fields[1], 16), int(fields[2]), int(fields[3], 16)))
        elif fields[0] == "i":
            steps.append(Step(int(fields[1], 16), bytes.fromhex(fields[3]), registers, reads))
            reads = []
    if not steps or steps[0].address != entry:
        raise ValueError(f"{path}: trace does not start at secret() ({entry:#x})")
    return steps


def elf_segments(path):
    data = Path(path).read_bytes()
    if data[:5] != b"\x7fELF\x02" or struct.unpack_from("<H", data, 0x12)[0] != 0x3E:
        raise ValueError(f"{path}: not an x86-64 ELF")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segments = []
    for i in range(phnum):
        p_type, _, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1:  # PT_LOAD
            segments.append((vaddr, data[offset:offset + filesz] + b"\0" * (memsz - filesz)))
    return segments


@dataclass
class Environment:
    """Input-independent machine state the VMP code reads but never writes inside secret()."""
    cpuid: dict = field(default_factory=dict)     # (leaf, subleaf) -> (eax, ebx, ecx, edx)
    memory: dict = field(default_factory=dict)    # absolute address -> byte (image and heap)
    stack: dict = field(default_factory=dict)     # offset from the entry RSP -> byte
    rflags: int = 0x202                           # IF set, as in user mode

    def heap_pointer(self):
        return sum(self.memory.get(HEAP_SLOT + k, 0) << (8 * k) for k in range(8))

    def heap_dwords(self):
        base = self.heap_pointer()
        starts = sorted({a & ~3 for a in self.memory if base <= a < base + 0x10000})
        return {a - base: sum(self.memory.get(a + k, 0) << (8 * k) for k in range(4)) for a in starts}


# --------------------------------------------------------------------------- the emulator

class Machine:
    """One Triton context reused for every run, so ASTs from different paths can be merged."""

    def __init__(self, binary, env):
        from triton import ARCH, MODE, TritonContext

        self.ctx = TritonContext(ARCH.X86_64)
        for mode in (MODE.ALIGNED_MEMORY, MODE.AST_OPTIMIZATIONS, MODE.CONSTANT_FOLDING):
            self.ctx.setMode(mode, True)
        self.segments = elf_segments(binary)
        self.env = env
        self.written = set()
        self.learning = False
        for vaddr, body in self.segments:
            self.ctx.setConcreteMemoryAreaValue(vaddr, body)
        self.apply_env()

    def pristine(self, address):
        for vaddr, body in self.segments:
            if vaddr <= address < vaddr + len(body):
                return body[address - vaddr]
        return self.env.memory.get(address, 0)

    def apply_env(self):
        for address, value in self.env.memory.items():
            self.ctx.setConcreteMemoryValue(address, value)

    def reset(self, registers):
        """Fresh concrete state at secret()'s entry; symbolic variables survive for merging."""
        ctx = self.ctx
        ctx.concretizeAllMemory()
        ctx.concretizeAllRegister()
        ctx.clearPathConstraints()
        for address in self.written:
            ctx.setConcreteMemoryValue(address, self.pristine(address))
        self.written = set()
        self.apply_env()
        for name, value in zip(REGISTERS, registers):
            ctx.setConcreteRegisterValue(getattr(ctx.registers, name), value)
        ctx.setConcreteRegisterValue(ctx.registers.eflags, self.env.rflags)
        rsp = registers[7]
        for offset, value in self.env.stack.items():
            ctx.setConcreteMemoryValue(rsp + offset, value)
        self.rsp0 = rsp

    def multiply_flags(self, instruction):
        """SF/ZF/PF are undefined after MUL/IMUL. On the recording CPU they follow the low half of the
        product and AF is cleared; this rule reproduces all 13 multiplications in the traces (all in sample3),
        while "clear them all" fails sample3. They are assigned as ASTs so input dependence is kept."""
        ctx, ast = self.ctx, self.ctx.getAstContext()
        operands = instruction.getOperands()
        if len(operands) == 1:
            low = {1: ctx.registers.al, 2: ctx.registers.ax, 4: ctx.registers.eax, 8: ctx.registers.rax}[operands[0].getSize()]
        else:
            low = operands[0]
        value = ctx.getRegisterAst(low)
        bits = value.getBitvectorSize()
        parity = ast.extract(0, 0, value)
        for bit in range(1, 8):
            parity = parity ^ ast.extract(bit, bit, value)
        flags = {"sf": ast.extract(bits - 1, bits - 1, value),
                 "zf": ast.ite(value == ast.bv(0, bits), ast.bv(1, 1), ast.bv(0, 1)),
                 "pf": ~parity, "af": ast.bv(0, 1)}
        for name, node in flags.items():
            register = getattr(ctx.registers, name)
            ctx.setConcreteRegisterValue(register, node.evaluate())
            ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(node), register)

    def learn_reads(self, reads):
        for address, size, value in reads:
            for k in range(size):
                cell, byte = address + k, (value >> (8 * k)) & 0xFF
                if cell not in self.written and self.ctx.getConcreteMemoryValue(cell) != byte:
                    if abs(cell - self.rsp0) < 0x100000:
                        self.env.stack[cell - self.rsp0] = byte
                    else:
                        self.env.memory[cell] = byte
                    self.ctx.setConcreteMemoryValue(cell, byte)

    def step(self, pc, recorded_cpuid=None):
        from triton import EXCEPTION, Instruction, OPCODE

        ctx = self.ctx
        instruction = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 16))
        leaf = None
        if ctx.getConcreteMemoryAreaValue(pc, 2) == b"\x0f\xa2":
            eax = ctx.getConcreteRegisterValue(ctx.registers.eax)
            leaf = (eax, ctx.getConcreteRegisterValue(ctx.registers.ecx) if eax in CPUID_SUBLEAF else 0)
        if ctx.processing(instruction) != EXCEPTION.NO_FAULT:
            raise ValueError(f"emulation fault at {instruction}")
        kind = instruction.getType()
        if kind in (OPCODE.X86.AND, OPCODE.X86.OR, OPCODE.X86.XOR, OPCODE.X86.TEST):
            # AF is architecturally undefined here; the recording CPU cleared it (Triton keeps a stale value).
            ctx.setConcreteRegisterValue(ctx.registers.af, 0)
        elif kind in (OPCODE.X86.MUL, OPCODE.X86.IMUL):
            self.multiply_flags(instruction)
        if leaf is not None:
            if recorded_cpuid is not None:
                self.env.cpuid[leaf] = recorded_cpuid
            if leaf not in self.env.cpuid:
                raise ValueError(f"CPUID leaf {leaf} is not in the environment")
            for name, value in zip(("rax", "rbx", "rcx", "rdx"), self.env.cpuid[leaf]):
                ctx.setConcreteRegisterValue(getattr(ctx.registers, name), value)
        for access, _ in instruction.getStoreAccess():
            self.written.update(range(access.getAddress(), access.getAddress() + access.getSize()))
        return instruction, ctx.getConcreteRegisterValue(ctx.registers.rip)


def learn_environment(binary, trace, entry=ENTRY):
    """Replay a recorded trace once, keeping CPUID results and every never-written byte the CPU read."""
    steps = read_trace(trace, entry)
    env = Environment()
    machine = Machine(binary, env)
    machine.reset(steps[0].registers)
    for index, step in enumerate(steps):
        machine.learn_reads(step.reads)
        cpuid = tuple(steps[index + 1].registers[:4]) if step.opcode == b"\x0f\xa2" else None
        _, pc = machine.step(step.address, cpuid)
        if index + 1 < len(steps) and pc != steps[index + 1].address:
            raise ValueError(f"{Path(trace).name}: diverged while learning at #{index + 1}")
    return env


def relocate_heap(env, new_pointer, keyed_offsets):
    """Move the VMP heap object. Keyed dwords hold (pointer ^ K) in their low 32 bits (observed rule)."""
    old = env.heap_pointer()
    moved = Environment(dict(env.cpuid), {}, dict(env.stack), env.rflags)
    for address, value in env.memory.items():
        if old <= address < old + 0x10000:
            moved.memory[address - old + new_pointer] = value
        elif not HEAP_SLOT <= address < HEAP_SLOT + 8:
            moved.memory[address] = value
    for k, byte in enumerate(struct.pack("<Q", new_pointer)):
        moved.memory[HEAP_SLOT + k] = byte
    delta = (old ^ new_pointer) & MASK32
    for offset in keyed_offsets:
        value = env.heap_dwords()[offset] ^ delta
        for k in range(4):
            moved.memory[new_pointer + offset + k] = (value >> (8 * k)) & 0xFF
    return moved


def reproduce(binary, env, trace, entry=ENTRY):
    """Require the recorded instruction addresses and every recorded memory-read value."""
    from triton import MemoryAccess

    steps = read_trace(trace, entry)
    machine = Machine(binary, env)
    machine.reset(steps[0].registers)
    pc = steps[0].address
    reads = 0
    for index, step in enumerate(steps):
        if pc != step.address:
            raise ValueError(f"{Path(trace).name}: PC diverged at #{index}: emulated {pc:#x}, recorded {step.address:#x}")
        for address, size, value in step.reads:
            model = machine.ctx.getConcreteMemoryValue(MemoryAccess(address, size))
            if model != value:
                raise ValueError(f"{Path(trace).name}: read #{index} [{address:#x}:{size}] real={value:#x} emulated={model:#x}")
            reads += 1
        _, pc = machine.step(pc)
    return len(steps), reads


# --------------------------------------------------------------------------- concolic exploration

@dataclass
class Path_:
    inputs: tuple
    conditions: list        # ASTs that must all hold for this path
    labels: list            # human-readable branch points
    result: object          # output AST
    instructions: int


class Explorer:
    def __init__(self, binary, env, width, entry=ENTRY):
        self.entry = entry
        self.machine = Machine(binary, env)
        ctx = self.machine.ctx
        self.ast = ctx.getAstContext()
        self.width = width
        self.variables = [ctx.newSymbolicVariable(width, "x"), ctx.newSymbolicVariable(width, "y")]
        self.x, self.y = (self.ast.variable(v) for v in self.variables)

    def extend(self, node):
        return self.ast.zx(32, node) if self.width == 32 else self.ast.sx(56, node)

    def concrete_register(self, value):
        if self.width == 32:
            return value
        return value | (0xFFFFFFFFFFFFFF00 if value & 0x80 else 0)

    def run(self, x, y, limit=400000):
        from triton import OPCODE

        machine, ctx, ast = self.machine, self.machine.ctx, self.ast
        registers = [0] * 16
        registers[4], registers[5], registers[7] = self.concrete_register(x), self.concrete_register(y), STACK
        machine.reset(registers)
        ctx.setConcreteMemoryAreaValue(STACK, struct.pack("<Q", RETURN_SENTINEL))
        ctx.setConcreteVariableValue(self.variables[0], x)
        ctx.setConcreteVariableValue(self.variables[1], y)
        ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(self.extend(self.x)), ctx.registers.rdi)
        ctx.assignSymbolicExpressionToRegister(ctx.newSymbolicExpression(self.extend(self.y)), ctx.registers.rsi)
        conditions, labels = [], []
        pc, count = self.entry, 0
        while pc != RETURN_SENTINEL:
            instruction, pc = machine.step(pc)
            count += 1
            if count > limit:
                raise ValueError("instruction limit reached")
            for access, _ in list(instruction.getLoadAccess()) + list(instruction.getStoreAccess()):
                lea = access.getLeaAst()
                if lea is not None and lea.isSymbolized():
                    conditions.append(lea == ast.bv(access.getAddress(), lea.getBitvectorSize()))
                    labels.append(f"#{count} {instruction.getAddress():#x} {instruction.getDisassembly()} -> [{access.getAddress():#x}]")
        # Triton records a path constraint for every control-flow instruction; an input-dependent one
        # is a native conditional branch or an indirect jump/ret whose target depends on x/y.
        for constraint in ctx.getPathConstraints():
            predicate = constraint.getTakenPredicate()
            if predicate.isSymbolized():
                conditions.append(predicate)
                kind = "native conditional branch" if constraint.isMultipleBranches() else "input-dependent jump target"
                labels.append(f"{kind} -> {constraint.getTakenAddress():#x}")
        output = ctx.getRegisterAst(ctx.registers.eax if self.width == 32 else ctx.registers.al)
        return Path_((x, y), conditions, labels, output, count)

    def solve(self, constraint):
        from triton import SOLVER_STATE

        model, status, _ = self.machine.ctx.getModel(constraint, status=True)
        if status != SOLVER_STATE.SAT:
            return None
        values = [model[v.getId()].getValue() if v.getId() in model else 0 for v in self.variables]
        return tuple(values)

    def explore(self, seed, max_paths=16):
        ast = self.ast
        paths, queue, seen = [], [seed], set()
        while queue:
            inputs = queue.pop(0)
            if inputs in seen:
                continue
            seen.add(inputs)
            if any(self.holds(p.conditions, inputs) for p in paths):
                continue
            path = self.run(*inputs)
            paths.append(path)
            if len(paths) > max_paths:
                raise ValueError(f"more than {max_paths} paths; stop")
            for i in range(len(path.conditions)):
                prefix = path.conditions[:i]
                flipped = ast.lnot(path.conditions[i])
                query = ast.land(prefix + [flipped]) if prefix else flipped
                new = self.solve(query)
                if new is not None:
                    queue.append(new)
        return paths

    def holds(self, conditions, inputs):
        ctx = self.machine.ctx
        ctx.setConcreteVariableValue(self.variables[0], inputs[0])
        ctx.setConcreteVariableValue(self.variables[1], inputs[1])
        return all(c.evaluate() for c in conditions)

    def merge(self, paths):
        ast = self.ast
        merged = paths[-1].result
        for path in reversed(paths[:-1]):
            merged = ast.ite(self.condition(path), path.result, merged)
        return merged

    def condition(self, path):
        ast = self.ast
        if not path.conditions:
            return ast.equal(ast.bvtrue(), ast.bvtrue())
        return ast.land(path.conditions) if len(path.conditions) > 1 else path.conditions[0]

    def unsat(self, node):
        from triton import SOLVER_STATE

        _, status, _ = self.machine.ctx.getModel(node, status=True)
        return status == SOLVER_STATE.UNSAT

    def evaluate(self, node, x, y):
        ctx = self.machine.ctx
        ctx.setConcreteVariableValue(self.variables[0], x)
        ctx.setConcreteVariableValue(self.variables[1], y)
        return node.evaluate()


def verify(explorer, paths, spec, rng):
    """Coverage, own-input consistency, SMT equivalence with the C source, concrete differential tests."""
    ast = explorer.ast
    for path in paths:
        if not explorer.holds(path.conditions, path.inputs):
            raise ValueError(f"path {path.inputs} does not satisfy its own condition")
    covered = ast.lor([explorer.condition(p) for p in paths]) if len(paths) > 1 else explorer.condition(paths[0])
    if not explorer.unsat(ast.lnot(covered)):
        raise ValueError("path conditions do not cover every input; exploration incomplete")
    merged = explorer.merge(paths)
    expected = spec["oracle"](ast, explorer.x, explorer.y)
    if not explorer.unsat(merged != expected):
        raise ValueError("merged expression differs from the C source")
    bits = explorer.width
    edge = [0, 1, 2, 0x7F, 0x80, 0xFF] if bits == 8 else [0, 1, 2, 1000, 1001, 1233, 1234, 0x7FFFFFFF, 0x80000000, MASK32]
    cases = [(a, b) for a in edge for b in edge] + [(rng.getrandbits(bits), rng.getrandbits(bits)) for _ in range(6)]
    native = []
    for x, y in cases:
        if explorer.evaluate(merged, x, y) != spec["reference"](x, y):
            raise ValueError(f"merged evaluation mismatch for {x:#x}, {y:#x}")
    # Independent check: fresh concrete emulation of the protected code (no merging) on a few inputs.
    for x, y in cases[::max(1, len(cases) // 6)][:6]:
        run = explorer.run(x, y)
        got = explorer.evaluate(run.result, x, y)
        if got != spec["reference"](x, y):
            raise ValueError(f"emulated secret({x:#x}, {y:#x}) = {got:#x}, C gives {spec['reference'](x, y):#x}")
        native.append((x, y))
    return merged, len(cases), len(native)


# --------------------------------------------------------------------------- driver

def environment_source(name):
    """Which trace teaches the environment and which traces are replayed against it."""
    traces = list(SAMPLES[name]["traces"])
    if len(traces) == 1:
        return traces[0], [(traces[0], traces[0])]
    return traces[0], [(traces[1], traces[0]), (traces[0], traces[1])]


def run_sample(name, inputs, out_dir):
    spec = SAMPLES[name]
    fetch([name], inputs)
    binary = inputs / f"{name}.vmp.bin"
    lines = [f"[{name}] C: {spec['c']}"]
    entry = spec.get("entry", ENTRY)
    learned = {t: learn_environment(binary, inputs / t, entry) for t in spec["traces"]}
    env_trace, pairs = environment_source(name)
    for env_from, replayed in pairs:
        env = learned[env_from]
        if env_from != replayed:
            # Different process, different heap address (ASLR): move the heap object, re-key its dword.
            target = learned[replayed].heap_pointer()
            env = relocate_heap(env, target, keyed_offsets(learned[env_from], learned[replayed]))
        count, reads = reproduce(binary, env, inputs / replayed, entry)
        lines.append(f"fidelity: {replayed} reproduced with environment from {env_from}: "
                     f"{count} instructions, {reads} memory reads, all equal")
    env = learned[env_trace]
    lines.append(f"environment: CPUID leaf 1 = {tuple(hex(v) for v in env.cpuid[(1, 0)])}, "
                 f"{len(env.memory)} image/heap bytes, {len(env.stack)} caller-stack bytes")
    explorer = Explorer(binary, env, spec["width"], entry)
    paths = explorer.explore((1, 2))
    for path in paths:
        lines.append(f"path inputs=({path.inputs[0]:#x}, {path.inputs[1]:#x}) instructions={path.instructions} "
                     f"branch points={len(path.conditions)}")
        lines.extend(f"    {label}" for label in path.labels)
    merged, cases, native = verify(explorer, paths, spec, random.Random(20261122))
    lines.append(f"paths explored: {len(paths)}; coverage: NOT(OR of path conditions) is UNSAT")
    lines.append(f"SMT: merged != C source is UNSAT, for {spec['width']}-bit x/y")
    lines.append(f"evaluations: {cases} merged-AST cases and {native} fresh emulations agree with C")
    if name == "sample3":
        ast = explorer.ast
        claim = (explorer.x ^ ast.bv(92, 8)) + explorer.y
        lines.append("SMT: sample3 == (x ^ 92) + y (8-bit) is " + ("proved" if explorer.unsat(merged != claim) else "NOT proved"))
    out_dir.mkdir(parents=True, exist_ok=True)
    simplified = explorer.machine.ctx.simplify(merged, solver=False)
    (out_dir / f"{name}.smt2.txt").write_text(str(explorer.ast.unroll(merged)) + "\n", encoding="utf-8")
    try:
        (out_dir / f"{name}.ll").write_text(explorer.machine.ctx.liftToLLVM(simplified) + "\n", encoding="utf-8")
    except Exception as error:  # lifting is a by-product; the proof above does not depend on it
        lines.append(f"note: LLVM lifting failed: {error}")
    return "\n".join(lines) + "\n"


def keyed_offsets(a, b):
    """Heap dwords whose low 32 bits move with the heap pointer: value ^ pointer is the same in both runs."""
    pa, pb = a.heap_pointer() & MASK32, b.heap_pointer() & MASK32
    da, db = a.heap_dwords(), b.heap_dwords()
    return [o for o in da if o in db and da[o] != db[o] and da[o] ^ pa == db[o] ^ pb]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("samples", nargs="*", help=f"default: all ({', '.join(SAMPLES)})")
    parser.add_argument("--inputs", type=Path, default=HERE / "inputs")
    parser.add_argument("--out", type=Path, default=HERE / "generated")
    args = parser.parse_args()
    unknown = [s for s in args.samples if s not in SAMPLES]
    if unknown:
        parser.error(f"unknown sample(s): {', '.join(unknown)}")
    failures = 0
    report = []
    for name in args.samples or SAMPLES:
        try:
            text = run_sample(name, args.inputs, args.out)
        except ImportError:
            parser.exit(1, "Install dependencies: python -m pip install -r VMP/02_vmp_trace/requirements.txt\n")
        except (OSError, ValueError) as error:
            failures += 1
            text = f"[{name}] FAILED: {error}\n"
        print(text, end="", flush=True)
        report.append(text)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "verification.txt").write_text("".join(report), encoding="utf-8")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
