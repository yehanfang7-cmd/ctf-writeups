#!/usr/bin/env bash
# build 時產生 /ctf/TOOLS.txt：實際裝了哪些工具。CLAUDE.md 叫 agent 以這份為準。
check() { if command -v "$1" >/dev/null 2>&1; then echo "  [有] $1"; else echo "  [無] $1"; fi; }
pycheck() { if /opt/venv/bin/python -c "import $1" >/dev/null 2>&1; then echo "  [有] python: $1"; else echo "  [無] python: $1"; fi; }
echo "# 映像內工具清單（build 時自動產生）"
echo "pwn/rev:";   for t in gdb r2 objdump readelf checksec patchelf ltrace strace one_gadget ROPgadget analyzeHeadless ghidra; do check "$t"; done
echo "forensics:"; for t in binwalk foremost exiftool steghide zsteg tshark john fcrackzip fls mmls vol; do check "$t"; done
echo "web/net:";   for t in curl sqlmap nmap nc; do check "$t"; done
echo "python:";    for m in pwn Crypto z3 sympy requests angr volatility3; do pycheck "$m"; done
gh="$(dirname "$(readlink -f "$(command -v ghidra 2>/dev/null || echo /nonexistent)")" 2>/dev/null)"
for p in /usr/share/ghidra/support/analyzeHeadless "$gh/support/analyzeHeadless"; do
  [ -x "$p" ] && { echo "ghidra headless: $p"; break; }
done
exit 0
