"""Extract the 0004-0006 challenge binaries into inputs/ (ignored by Git).  Nothing is executed.

The archive is the one unit 06 downloads and pins (devirt.fetch); every member is checked against a
SHA-256 recorded here before it is written.
"""
import hashlib
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "06_tigress"))
import devirt                                                    # noqa: E402

MEMBER = "tigress-challenges/Linux-x86_64/{}"
SHA256 = {
    "0004/challenge-0": "b231f9d178bc2376526158b3316c6077fcdd826f498a8a6219a8fba571014966",
    "0004/challenge-1": "8eec8b21d94e5f7196adeecf5ee0c62d58ffff9bd174d93242acaf71a4a980c0",
    "0004/challenge-2": "801ef9b9255eda2d9b008ee5ae37793810353255dfdfd154c4af69cb7fb4c1ea",
    "0004/challenge-3": "6410a27ff9266c32739dddd0901a314a81ac5b118d5dd43f425b5c9cc73f11f4",
    "0004/challenge-4": "95aa0a584aec33d7a46bcaaf80750ef3d4c44ff14f8acbaff1c6eb19048a94d7",
    "0005/challenge-0": "8633186d10b08b3ec296cb7f5555b9a0da863bf2ab9ba52ca7982db461be7cc6",
    "0005/challenge-1": "b387c59383c48546139da54c891f2ee05ba5543dbf85b9c0ecb6c4ec37038243",
    "0005/challenge-2": "bec442e0647142907c511d6942889ffdda6b0fba5b6e0d590f86308b28efa593",
    "0005/challenge-3": "92106f9aa7537618cf37c77b06a4af7869a3b957a860b07794f7b2a747d8af15",
    "0005/challenge-4": "e341e71bdc6e8577b5fd4a7b5daf98cd83c1e0f03678d153a624ebaa73ccdd63",
    "0006/challenge-0": "ea9f0479984ec0ad1bf697e76fc74eb1779cee311b4016a9c9083cda27acb380",
    "0006/challenge-1": "73100eb9fbebf6c0560b4b0c764a80caa41b3d0c94dc781c9f5486dca8505b7b",
    "0006/challenge-2": "fb7d2ef8a9349c0736d4ffb3889c5d9005dfbddc0dd5e637fe774170543b172a",
    "0006/challenge-3": "fa6fb09e6c0aba3fc410d18e0f79b7cae540b0956c52c1f5cdb681677d7ef61d",
    "0006/challenge-4": "8b05d6596d04aee889598bb692e865331f62744b1d485d77a29b80b7173376b9",
    "0004.sh": "f05be04742c5e95e315c69d4fcd342612c0f04296e1b96d04830eece31372cad",
    "0005.sh": "2ebbcdfd311cff82ef3f0594cc6fad4d40e60dc4c647ba4ca988ec5d20bd7321",
    "0006.sh": "b7c09c6aa2a2b8df630e42e83db59c76a97593cccbd4d083f3777064a436caad",
}


def fetch():
    archive = devirt.INPUTS / "tigress-challenges-Linux-x86_64.zip"
    if not archive.exists():
        devirt.fetch()                                           # downloads and checks the archive's own SHA-256
    if hashlib.sha256(archive.read_bytes()).hexdigest() != devirt.ZIP_SHA256:
        raise ValueError(f"SHA256 mismatch for {archive}")
    with zipfile.ZipFile(archive) as z:
        for name, digest in SHA256.items():
            data = z.read(MEMBER.format(name))
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"SHA256 mismatch for {name}")
            out = HERE / "inputs" / name
            out.parent.mkdir(parents=True, exist_ok=True)
            if out.exists() and out.read_bytes() != data:
                raise ValueError(f"{out} exists with different content; not overwriting")
            out.write_bytes(data)
    return len(SHA256)


if __name__ == "__main__":
    print(f"{fetch()} files checked and extracted to {HERE / 'inputs'}")
