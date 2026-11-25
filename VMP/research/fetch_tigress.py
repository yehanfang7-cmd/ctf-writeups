"""Fetch VM-0 research inputs at a recorded immutable upstream revision."""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
DEST = HERE / "inputs/tigress"
REVISION = "382a8e9e9aacad553f0b3c228e2b76077ff0ced2"
EXPECTED = {
    "tigress-challenges/tigress-0-challenge-0": "581936cbe0b0b7a7b323f2c48d93202100faf78d7d512418c7f6f873d8ce011b",
    "tigress-challenges/tigress-0-challenge-1": "5f0d952c0e8d3471e38b0ed3bc96263a2b84001a133f3cce626334cbb28b1191",
    "tigress-challenges/tigress-0-challenge-2": "087a550f3730c574548806ed34e465ba0370f48173e53edc5c4137fcf6bcd072",
    "tigress-challenges/tigress-0-challenge-3": "fe8e69f2d348bcc2c9050f2552665736fc3a3f098fcd11b2bfbb514cef1a8043",
    "tigress-challenges/tigress-0-challenge-4": "3344044ae05863f4162be58c234e5c40819c5a8630b2de118c17f4454b84dfa9",
    "solve-vm.py": "04c7b35284d4d5b7deeefeb6bb20667ee74138a2c063b98a53ee88b08e7a91c4",
    "scripts/templates.py": "f01bb9e683ae8dde758e67f12f11e5d1fd436586593765895bb202c2b981058b",
    "README.md": "c262e877c090003cf35aa1460b11ed40738cd2f0ed7b9aa62eae30d62a83cc72",
}


def read(url):
    with urlopen(Request(url, headers={"User-Agent": "ctf-research"}), timeout=45) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("Input exceeds limit")
    return data


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    lock = DEST / "revision.txt"
    revision = REVISION
    if lock.exists() and lock.read_text().strip() != revision:
        raise ValueError("Unexpected revision; existing inputs will not be overwritten")
    lock.write_text(revision + "\n", encoding="ascii")
    base = f"https://raw.githubusercontent.com/JonathanSalwan/Tigress_protection/{revision}/"
    names = [f"tigress-challenges/tigress-0-challenge-{i}" for i in range(5)]
    names += ["solve-vm.py", "scripts/templates.py", "README.md"]
    manifest = DEST / "downloads.tsv"
    known = {}
    if manifest.exists():
        known = {r.split("\t")[0]: r.split("\t")[2] for r in manifest.read_text().splitlines()[1:]}
    rows = ["path\tbytes\tsha256\turl"]
    for name in names:
        path = DEST / name
        data = path.read_bytes() if path.exists() else read(base + name)
        digest = hashlib.sha256(data).hexdigest()
        if digest != EXPECTED[name]:
            raise ValueError(f"SHA256 mismatch: {name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        rows.append(f"{name}\t{len(data)}\t{digest}\t{base + name}")
        manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(rows[-1], flush=True)
    print("revision:", revision, flush=True)


if __name__ == "__main__":
    main()
