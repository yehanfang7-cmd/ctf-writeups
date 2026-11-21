"""fsvm bytecode decoder and bounded ASCII interpreter (not VMProtect)."""
from dataclasses import dataclass
import re


class VMError(ValueError):
    pass


@dataclass(frozen=True)
class Instruction:
    pc: int
    op: str
    args: tuple[int, ...]
    next_pc: int

    def __str__(self):
        return f"{self.pc:04x}: {self.op:8s} " + ", ".join(f"r{r}" for r in self.args)


# Explicit operands are in bytecode order: sources first, destination last.
OPS = {
    0x28: ("jmp", 0), 0x29: ("je", 0), 0x2a: ("jne", 0), 0x2b: ("jl", 0),
    0x3d: ("ord", 2), 0x3e: ("chr", 2), 0x3f: ("concat", 3),
    0x51: ("add", 3), 0x52: ("append", 1), 0x53: ("pop", 1),
    0x54: ("neg", 1), 0x55: ("print", 0), 0x56: ("read", 0), 0x57: ("ret", 0),
}


def decode(code: bytes) -> list[Instruction]:
    instructions = []
    pc = 0
    while pc < len(code):
        start = pc
        opcode = code[pc]
        pc += 1
        if 0x2c <= opcode <= 0x33:
            op, args = "clear", (opcode - 0x2c,)
        elif 0x40 <= opcode <= 0x47:
            op, args = "zero", (opcode - 0x40,)
        else:
            if opcode not in OPS:
                raise VMError(f"Unknown opcode {opcode:#x} at {start:#x}")
            op, count = OPS[opcode]
            args = tuple(code[pc:pc + count])
            if len(args) != count:
                raise VMError(f"Truncated {op} at {start:#x}")
            if any(r > 7 for r in args):
                raise VMError(f"Invalid register at {start:#x}")
            pc += count
        instructions.append(Instruction(start, op, args, pc))
    return instructions


def token(text: str) -> str:
    """C-locale formatted string extraction, for the documented ASCII domain."""
    if not text.isascii():
        raise VMError("Only ASCII input is modeled")
    parts = re.findall(r"[^ \t\n\r\v\f]+", text)
    return parts[0] if parts else ""


def number(text: str) -> int:
    match = re.match(r"[ \t\n\r\v\f]*[+-]?[0-9]+", text)
    if not match:
        raise VMError(f"Undefined/failed integer extraction: {text!r}")
    value = int(match[0])
    if not -(1 << 63) <= value < (1 << 63):
        raise VMError("Outside signed 64-bit arithmetic domain")
    return value


def step_data(ins: Instruction, regs: list[str], input_text: str, output: list[str]):
    """Execute a non-control instruction, using strings as the VM file contents."""
    op, a = ins.op, ins.args
    if op == "clear":
        regs[a[0]] = ""
    elif op == "zero":
        regs[a[0]] = "0"
    elif op == "ord":
        source = token(regs[a[0]])
        if not source:
            raise VMError(f"ord(empty) is outside the defined input domain at {ins.pc:#x}")
        regs[a[1]] = str(ord(source[-1]))
    elif op == "chr":
        regs[a[1]] = chr(number(regs[a[0]]) & 0xff)
    elif op == "concat":
        regs[a[2]] = token(regs[a[0]]) + token(regs[a[1]])
    elif op == "add":
        value = number(regs[a[0]]) + number(regs[a[1]])
        regs[a[2]] = str(number(str(value)))
    elif op == "append":
        regs[a[0]] += "1"
    elif op == "pop":
        source = token(regs[a[0]])
        if source:
            regs[a[0]] = source[:-1]
    elif op == "neg":
        source = token(regs[a[0]])
        regs[a[0]] = source[1:] if source.startswith("-") else "-" + source
    elif op == "print":
        output.append(token(regs[4]))
    elif op == "read":
        regs[0] = token(input_text)
    else:
        raise VMError(f"Unsupported data operation: {op}")


def run(instructions: list[Instruction], input_text: str, max_steps=10000) -> list[str]:
    by_pc = {ins.pc: ins for ins in instructions}
    regs, output, pc = [""] * 8, [], 0
    for _ in range(max_steps):
        if pc not in by_pc:
            raise VMError(f"PC is not an instruction boundary: {pc:#x}")
        ins = by_pc[pc]
        pc = ins.next_pc
        if ins.op == "ret":
            return output
        if ins.op in ("jmp", "je", "jne", "jl"):
            if ins.op == "jmp":
                taken = True
            elif ins.op == "je":
                taken = token(regs[6]) == token(regs[7])
            elif ins.op == "jne":
                taken = token(regs[6]) != token(regs[7])
            else:
                taken = number(regs[6]) < number(regs[7])
            if taken:
                pc += number(regs[5])
        else:
            step_data(ins, regs, input_text, output)
    raise VMError(f"Step limit {max_steps} exceeded")
