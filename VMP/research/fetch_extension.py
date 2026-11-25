"""Fetch the additional pinned public MBA case without executing downloaded files."""
import hashlib
from pathlib import Path
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
BASE = "https://raw.githubusercontent.com/JonathanSalwan/VMProtect-devirtualization/d2b26d66db59e341f179c7e326246d28c4d25491/"
ASSETS = {
    "sample3.c": "vmp_binaries/samples-source/sample3.c",
    "sample3.vmp.trace": "vmp_traces/sample3.vmp.trace",
    "sample3.O3.ll": "devirt/sample3.O3.ll",
}
HASHES = {
    "sample3.c": "d66a8f75fed8968abef1dc44e62eb0b4962ab3107c5829b732599a1c59c29d47",
    "sample3.vmp.trace": "8dbd08069f095f64966dfe960e350a872e8a0eef6cd0177ecd6db60a1346d846",
    "sample3.O3.ll": "14670bbd7830937ff774caec1c20543516a550a8de71951b313ea8ee23e2080d",
}


def main():
    destination = HERE / "inputs/mba"
    destination.mkdir(parents=True, exist_ok=True)
    rows = ["path\tbytes\tsha256\turl"]
    for name, relative in ASSETS.items():
        path = destination / name
        if path.exists():
            data = path.read_bytes()
        else:
            with urlopen(BASE + relative, timeout=45) as response:
                data = response.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                raise ValueError("Input exceeds 16 MiB")
        digest = hashlib.sha256(data).hexdigest()
        if digest != HASHES[name]:
            raise ValueError(f"SHA256 mismatch: {name}")
        if not path.exists():
            path.write_bytes(data)
        rows.append(f"{name}\t{len(data)}\t{digest}\t{BASE + relative}")
        print(rows[-1], flush=True)
    (destination / "downloads.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
