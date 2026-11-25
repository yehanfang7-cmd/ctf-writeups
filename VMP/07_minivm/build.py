"""Unit 07 builder: generate the encrypted blob, build the shipped and self-test interpreters, then check that
the shipped binary no longer carries the secret and still computes it.

    python VMP/07_minivm/build.py            # writes VMP/07_minivm/generated/
"""
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GEN = HERE / "generated"
EXE = ".exe" if os.name == "nt" else ""
WINLIBS = Path(os.environ.get("LOCALAPPDATA", "")) / ("Microsoft/WinGet/Packages/BrechtSanders.WinLibs.POSIX.UCRT_"
                                                       "Microsoft.Winget.Source_8wekyb3d8bbwe/mingw64/bin/gcc.exe")
M64 = (1 << 64) - 1

# the secret algorithm's constants (what a reverser greps for) and debug strings that reveal the ISA
SECRET_CONSTANTS = {0x5BD1E995: 4, 0x100000001B3: 8, 0x9E3779B97F4A7C15: 8, 0xFF51AFD7ED558CCD: 8}
DEBUG_STRINGS = [b"VM_DISASM", b"MISMATCH!", b"INPUT"]


def compiler():
    for c in (os.environ.get("CC"), shutil.which("gcc"), shutil.which("cc"), str(WINLIBS) if WINLIBS.exists() else None):
        if c:
            return c
    return None


def rotl(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def reference(x):
    """the secret, written independently of the C sources"""
    h = x ^ 0x5BD1E995
    h = h * 0x100000001B3 & M64
    h ^= h >> 15
    h = (h + 0x9E3779B97F4A7C15) & M64
    h = rotl(h, 13)
    h = h * 0xFF51AFD7ED558CCD & M64
    return h ^ (h >> 33)


def cc(src, out, *flags, include=()):
    gcc = compiler()
    if gcc is None:
        raise RuntimeError("no C compiler: set CC or install gcc")
    env = dict(os.environ, PATH=str(Path(gcc).parent) + os.pathsep + os.environ.get("PATH", ""))
    cmd = [gcc, "-O2", "-Wall", "-Wextra", "-Werror", *flags, *(f"-I{d}" for d in include), "-o", str(out), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode:
        raise RuntimeError(f"compile failed: {' '.join(cmd)}\n{r.stderr}")
    return out


def build(out=GEN, seed=0xA5):
    """gen -> blob.h -> shipped vm and SELFTEST vm. Returns the paths and gen's listing."""
    out.mkdir(parents=True, exist_ok=True)
    gen = cc(HERE / "gen.c", out / f"gen{EXE}")
    r = subprocess.run([str(gen), str(out / "blob.h"), hex(seed)], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"gen failed:\n{r.stdout}{r.stderr}")
    return dict(listing=r.stdout,
                ship=cc(HERE / "vm.c", out / f"vm{EXE}", "-s", include=[out]),
                selftest=cc(HERE / "vm.c", out / f"vm_selftest{EXE}", "-DSELFTEST", include=[out]))


def leaks(path):
    """secret constants (whole, or either 32-bit half of a 64-bit one) and debug strings present in a binary"""
    data = Path(path).read_bytes()
    found = []
    for c, size in SECRET_CONSTANTS.items():
        pieces = [(c, size)] + ([(c & 0xFFFFFFFF, 4), (c >> 32, 4)] if size == 8 else [])
        for v, n in pieces:
            if v > 0xFFFF and v.to_bytes(n, "little") in data:
                found.append(f"{v:#x}")
    return found + [s.decode() for s in DEBUG_STRINGS if s in data]


def run(exe, arg, env=None):
    r = subprocess.run([str(exe), str(arg)], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def test_inputs(n, seed=7):
    rng = random.Random(seed)
    return [0, 1, 1234, 0xDEADBEEF, (1 << 63) - 1, 1 << 63, M64] + [rng.getrandbits(64) for _ in range(n)]


def compare(exe, xs):
    """inputs where `exe` (given the number in decimal or hex) disagrees with the reference"""
    bad = []
    for i, x in enumerate(xs):
        rc, out, err = run(exe, hex(x) if i % 2 else x)
        if rc or out != str(reference(x)):
            bad.append((x, rc, out, err))
    return bad


def main():
    if compiler() is None:
        sys.exit("no C compiler: set CC or install gcc")
    b = build()
    print(b["listing"], end="")
    original = cc(HERE / "original" / "vm.c", GEN / f"vm_original{EXE}", "-Wno-error")
    xs = test_inputs(193)
    report = []
    for name, exe in (("original", original), ("ship", b["ship"]), ("selftest", b["selftest"])):
        size = Path(exe).stat().st_size
        report.append(f"{name:9} {size:7} bytes  leaks: {', '.join(leaks(exe)) or 'none'}")
    ok_ship, ok_st = compare(b["ship"], xs), compare(b["selftest"], xs)
    report.append(f"ship      {len(xs) - len(ok_ship)}/{len(xs)} inputs match the reference")
    report.append(f"selftest  {len(xs) - len(ok_st)}/{len(xs)} inputs match the reference (and its own native check)")
    rejected = [a for a in ("abc", "", "-1", "12x", "0x", "99999999999999999999") if run(b["ship"], a)[0] != 1]
    report.append(f"bad arguments rejected: {6 - len(rejected)}/6" + (f"  NOT: {rejected}" if rejected else ""))
    print("\n".join(report))
    (GEN / "report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    if leaks(b["ship"]) or ok_ship or ok_st or rejected:
        sys.exit("FAILED")


if __name__ == "__main__":
    main()
