"""Download public VMP research cases and reproduce existing devirtualization tools."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
from urllib.request import urlopen
from zipfile import ZipFile, ZIP_DEFLATED

HERE = Path(__file__).resolve().parent
VMP = HERE.parent
COMMIT = "d2b26d66db59e341f179c7e326246d28c4d25491"
BASE = f"https://raw.githubusercontent.com/JonathanSalwan/VMProtect-devirtualization/{COMMIT}/"
BINARY_HASHES = {
    2: "d3e3f92c8cdad93e22d8eca0db4e306687716d612437574cc46bb79a677700e2",
    4: "f065eea78171fd8070c78ccb858b69d24182c826a33b3c3fb87ed297a3888935",
    5: "81d2a1d1ad0ced2e2f23c4add44f27b8cf899b4947c2d4a248a84e0d2947ad58",
    6: "1527da956e3483e907d35f63f9d6a54abb3148ea6e341dae21675ee7330175e4",
}


def download():
    spec = importlib.util.spec_from_file_location("research_assets", VMP / "fetch_samples.py")
    assets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assets)
    items = assets.ASSETS["vmp"] + assets.ASSETS["multipath"]
    items += [(f"binaries/sample{n}.vmp.bin", BASE + f"vmp_binaries/binaries/sample{n}.vmp.bin", BINARY_HASHES[n])
              for n in (2, 4, 5, 6)]
    items.append(("upstream/sample4.O3.ll", BASE + "devirt/sample4.O3.ll",
                  "4f2465e04ac7fde2db3b7ab19491de2e3f76d12b57034267e1ec1439e8ee6705"))
    from fetch_extension import ASSETS as MBA_ASSETS, HASHES as MBA_HASHES
    items.extend(("mba/" + name, BASE + relative, MBA_HASHES[name]) for name, relative in MBA_ASSETS.items())
    manifest = HERE / "generated/downloads.tsv"
    previous = {}
    if manifest.exists():
        for row in manifest.read_text(encoding="utf-8").splitlines()[1:]:
            relative, _, digest, _ = row.split("\t")
            previous[relative] = digest
    rows = ["path\tbytes\tsha256\turl"]
    for relative, url, expected in items:
        path = HERE / "inputs" / relative
        data = path.read_bytes() if path.exists() else None
        if data is None:
            with urlopen(url, timeout=45) as response:
                data = response.read(64 * 1024 * 1024 + 1)
            if len(data) > 64 * 1024 * 1024:
                raise ValueError(f"Download exceeds 64 MiB: {relative}")
        digest = hashlib.sha256(data).hexdigest()
        expected = expected or previous.get(relative)
        if expected and digest != expected:
            raise ValueError(f"SHA256 mismatch: {relative}; existing files are never overwritten")
        if relative.startswith("binaries/") and data[:4] != b"\x7fELF":
            raise ValueError(f"Expected ELF research binary: {relative}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
            print(f"downloaded {relative}: {len(data)} bytes", flush=True)
        else:
            print(f"verified {relative}", flush=True)
        rows.append(f"{relative}\t{len(data)}\t{digest}\t{url}")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return len(items)


def run_step(name, arguments, run_dir):
    started = time.perf_counter()
    try:
        result = subprocess.run([sys.executable, *map(str, arguments)], cwd=VMP.parent,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=600)
        output, code = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        parts = [part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part or ""
                 for part in (error.stdout, error.stderr)]
        output, code = "".join(parts) + "\nStep timed out after 600 seconds\n", 124
    elapsed = time.perf_counter() - started
    (run_dir / f"{name}.txt").write_text(output, encoding="utf-8")
    print(output, end="", flush=True)
    return name, code, elapsed


def write_report(count, results, run_dir):
    lines = ["# VMP 實驗執行記錄", "",
             f"執行時間：{datetime.now(timezone.utc).isoformat()}。", "",
             f"環境：Python {platform.python_version()}，{platform.platform()}。", "",
             f"本次產物：`{run_dir.relative_to(HERE).as_posix()}`。", "",
             f"實驗產物壓縮包：`{run_dir.relative_to(HERE).as_posix()}/research_bundle.zip`。", "",
             f"來源 commit：`{COMMIT}`；下載材料：{count} 個檔案。", "",
             "| 步驟 | 結果 | 秒數 |", "|---|---|---:|"]
    for name, code, elapsed in results:
        lines.append(f"| {name} | {'通過' if code == 0 else '失敗，exit=' + str(code)} | {elapsed:.2f} |")
    if any(n == "robustness" and c == 0 for n, c, _ in results):
        lines += ["", "本輪可靠性研究、消融及上游結果比較見 [研究報告](REPORT.md)。", ""]
    if any(n == "mba" and c == 0 for n, c, _ in results):
        mba = json.loads((run_dir / "mba/results.json").read_text(encoding="utf-8"))
        lines += ["", "## 新增 MBA 案例", "",
                  f"sample3 重播 {mba['instructions']} 條指令；低 8 位元語義 SMT 等價檢查為 UNSAT。",
                  f"本機執行全部 {mba['native_exhaustive_pairs']} 組 8 位元輸入及 {mba['upper_bit_checks']} 組高位元檢查通過；LLVM IR 指令數 {mba['ir_before']} → {mba['ir_after']}。", "",
                  "結果契約：`low8((x XOR 92) + y)`；尚未聲稱自動合成出最短公式。", ""]
    if any(n == "native" and c == 0 for n, c, _ in results):
        rows = json.loads((run_dir / "native/results.json").read_text(encoding="utf-8"))
        lines += ["", "## 還原函式的本機執行結果", "",
                  "LLVM IR 經 O3 最佳化後編譯為本機程式碼，以 ctypes 呼叫，與獨立的 Python 機器語義模型比對。指令數含 ret，不代表執行效能倍數。", "",
                  "| 案例 | 通過輸入組數 | IR 指令數 | 最佳化後 IR 指令數 | 目的檔位元組 |",
                  "|---|---:|---:|---:|---:|"]
        for row in rows:
            lines.append(f"| {row['sample']} | {row['cases']} | {row['ir_before']} | {row['ir_after']} | {row['object_bytes']} |")
        lines += ["", "原生編譯流程依據 [llvmlite 官方範例](https://llvmlite.readthedocs.io/en/v0.46.0/user-guide/binding/examples.html) 與 [最佳化 API](https://llvmlite.readthedocs.io/en/v0.46.0/user-guide/binding/optimization-passes.html)。", ""]
    lines += ["", "## 個案驗證輸出", ""]
    for relative in ("xor/verification.txt", "multipath/sample4/verification.txt",
                     "multipath/sample5/verification.txt", "multipath/sample6/verification.txt"):
        path = run_dir / relative
        step = "xor" if relative.startswith("xor/") else "multipath"
        if path.exists() and any(n == step and c == 0 for n, c, _ in results):
            lines += [f"### {path.parent.name}", "", "```text", path.read_text(encoding="utf-8").strip(), "```", ""]
    lines += ["## 解讀範圍", "",
              "結果來自公開 trace 的符號重播。原生執行階段執行的是還原後的函式；下載的受保護 ELF 未執行，未自行加上 VMP 保護、錄製新 trace 或重建整個 EXE。",
              "SMT 結果針對工具建立的 32 位元機器語義模型；不代表原始 C 的有號溢位具有已定義行為。",
              "回歸測試使用合成符號表達式；個案還原使用本研究目錄下載的資料。", ""]
    text = "\n".join(lines)
    (run_dir / "RESULTS.md").write_text(text, encoding="utf-8")
    (HERE / "RESULTS.md").write_text(text, encoding="utf-8")
    with ZipFile(run_dir / "research_bundle.zip", "w", compression=ZIP_DEFLATED) as bundle:
        for path in run_dir.rglob("*"):
            if path.is_file() and path.name != "research_bundle.zip":
                bundle.write(path, path.relative_to(run_dir).as_posix())
        for name in ("PROJECT.md", "requirements.txt", "run.py", "native_verify.py", "start.ps1"):
            bundle.write(HERE / name, "project/" + name)
        for name in ("robustness.py", "test_pipeline.py", "test_native_verify.py", "mba.py", "fetch_extension.py", "EXTENSION_REPORT.md"):
            if (HERE / name).is_file():
                bundle.write(HERE / name, "project/" + name)
    print(f"Report: {HERE / 'RESULTS.md'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    run_dir = HERE / "generated/runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir.mkdir(parents=True)
    count, results = 0, []
    try:
        count = download()
        (run_dir / "downloads.tsv").write_bytes((HERE / "generated/downloads.tsv").read_bytes())
        if args.download_only:
            return 0
        environment = {"python": sys.version, "platform": platform.platform(),
                       "packages": {name: version(name) for name in ("triton-library", "llvmlite")}}
        if environment["packages"] != {"triton-library": "1.0.0rc4", "llvmlite": "0.46.0"}:
            raise ValueError("Run start.ps1 to install the pinned research dependencies")
        (run_dir / "environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
        steps = [
            ("xor", [VMP / "02_vmp_trace/replay.py", "--trace",
                     HERE / "inputs/02_vmp_trace/inputs/sample2.vmp.trace", "--out", run_dir / "xor"]),
            ("multipath", [VMP / "03_multipath/merge.py", "--inputs",
                           HERE / "inputs/03_multipath/inputs", "--out", run_dir / "multipath"]),
            ("mba", [HERE / "mba.py", "--run-dir", run_dir]),
            ("test_replay", ["-m", "unittest", "discover", "-s", VMP / "02_vmp_trace", "-p", "test_*.py"]),
            ("test_merge", ["-m", "unittest", "discover", "-s", VMP / "03_multipath", "-p", "test_*.py"]),
            ("test_pipeline", ["-m", "unittest", "discover", "-s", HERE, "-p", "test_*.py"]),
        ]
        results = [run_step(name, arguments, run_dir) for name, arguments in steps]
        if all(code == 0 for name, code, _ in results if name in ("xor", "multipath")):
            results.append(run_step("native", [HERE / "native_verify.py", "--run-dir", run_dir], run_dir))
        if any(name == "native" and code == 0 for name, code, _ in results):
            results.append(run_step("robustness", [HERE / "robustness.py", "--run-dir", run_dir], run_dir))
        write_report(count, results, run_dir)
        return int(any(code for _, code, _ in results))
    except (OSError, ValueError, ImportError) as error:
        (run_dir / "error.txt").write_text(str(error) + "\n", encoding="utf-8")
        results.append(("pipeline", 1, 0))
        if not args.download_only:
            write_report(count, results, run_dir)
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
