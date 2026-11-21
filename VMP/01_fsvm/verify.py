"""Differential tests: bytecode interpreter vs recovered check, optionally official C++."""
import argparse
import hashlib
from pathlib import Path
import random
import shutil
import subprocess
import tempfile

from solve import HERE, lift, recovered_source
from vm import VMError, decode, run, step_data


def decoder_checks():
    for malformed in (b"\x00", b"\x3d\x00", b"\x51\x00\x08\x00"):
        try:
            decode(malformed)
        except VMError:
            pass
        else:
            raise AssertionError(f"Malformed bytecode accepted: {malformed!r}")
    # r5='0'; append -> '01'; jump from next PC over one invalid-in-context read.
    program = decode(bytes([0x45, 0x52, 5, 0x28, 0x56, 0x57]))
    assert run(program, "") == []
    regs, output = [""] * 8, []
    regs[1] = "001"
    for ins in decode(bytes([0x54, 1, 0x54, 1, 0x51, 1, 1, 2])):
        step_data(ins, regs, "", output)
    assert regs[1] == "001" and regs[2] == "2"
    # Unterminated loops must stop rather than hang.
    loop = decode(bytes([0x45, 0x52, 5, 0x54, 5, 0x28]))
    try:
        run(loop, "", max_steps=10)
    except VMError as error:
        assert "Step limit" in str(error)
    else:
        raise AssertionError("Infinite loop was not bounded")


def make_cases(suffix):
    cases = [suffix, "prefix" + suffix, "X" + suffix, suffix + suffix,
             suffix + "X", "A" * len(suffix), " " + suffix + " ignored\n"]
    for i, original in enumerate(suffix):
        replacement = "A" if original != "A" else "B"
        cases.append(suffix[:i] + replacement + suffix[i + 1:])
    rng = random.Random(20261004)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_!"
    for _ in range(512):
        cases.append("".join(rng.choice(alphabet) for _ in range(rng.randint(len(suffix), 96))))
    return cases


def native_check(instructions, cases, compiler):
    original = (HERE / "inputs/vm.cpp").read_bytes()
    expected = "aba793d119f902e3ea5d5390ae307c72094b354d67c7fe03225fa75e4da702b9"
    if hashlib.sha256(original).hexdigest() != expected:
        raise ValueError("Official vm.cpp SHA256 mismatch")
    executable = shutil.which(compiler)
    if not executable:
        raise ValueError(f"C++ compiler not found: {compiler}")
    source = original.decode("utf-8")
    # Only the OS directory-creation call is adapted for MinGW. VM handlers are unchanged.
    source = source.replace("#include <sys/stat.h>",
                            "#include <sys/stat.h>\n#ifdef _WIN32\n#include <direct.h>\n#endif")
    source = source.replace('mkdir("regs", S_IRWXU);',
                            '#ifdef _WIN32\n    _mkdir("regs");\n#else\n    mkdir("regs", S_IRWXU);\n#endif')
    with tempfile.TemporaryDirectory(prefix="fsvm-verify-") as temporary:
        work = Path(temporary)
        cpp, binary = work / "vm.cpp", work / "vm.exe"
        cpp.write_text(source, encoding="utf-8")
        subprocess.run([executable, "-std=c++17", "-O0", str(cpp), "-o", str(binary)],
                       check=True, capture_output=True, timeout=60)
        for text in cases:
            result = subprocess.run([str(binary), str(HERE / "inputs/bytecode")],
                                    input=text + "\n", text=True, capture_output=True,
                                    cwd=work, check=True, timeout=15)
            if result.stdout.splitlines() != run(instructions, text):
                raise AssertionError(f"Native mismatch for {text!r}: {result.stdout!r}")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="Compile and test the pinned official C++ VM")
    parser.add_argument("--compiler", default="g++")
    args = parser.parse_args()
    try:
        decoder_checks()
        instructions = decode((HERE / "inputs/bytecode").read_bytes())
        suffix, _, _, accepted, rejected = lift(instructions)
        namespace = {}
        exec(compile(recovered_source(suffix), "<recovered-fsvm>", "exec"), namespace)
        cases = make_cases(suffix)
        for text in cases:
            expected = accepted if namespace["check"](text) else rejected
            if run(instructions, text) != expected:
                raise AssertionError(f"Recovered check mismatch for {text!r}")
        assert namespace["check"]("prefix" + suffix)
        try:
            run(instructions, "short")
        except VMError as error:
            assert "ord(empty)" in str(error)
        else:
            raise AssertionError("Short input must report undefined original behavior")
        lines = ["decoder/operand/control-flow checks: passed",
                 f"interpreter vs recovered predicate: {len(cases)} cases passed",
                 "prefix acceptance and every single-position mutation: verified",
                 "short input: interpreter reports ord(empty); recovered check rejects safely"]
        if args.native:
            native_count = native_check(instructions, cases[:52], args.compiler)
            lines.append(f"official C++ VM vs interpreter: {native_count} cases passed")
        else:
            lines.append("official C++ VM: not run (use --native)")
        report = "\n".join(lines) + "\n"
        (HERE / "generated").mkdir(exist_ok=True)
        (HERE / "generated/verification.txt").write_text(report, encoding="utf-8")
        print(report, end="")
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
