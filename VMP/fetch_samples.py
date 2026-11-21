"""Download pinned research inputs; never execute downloaded files."""
import argparse
import hashlib
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
ECSC = "https://raw.githubusercontent.com/ECSC2024/openECSC-2024/2602f22c664eb98398413e6a7dfe03ea88b2d296/"
SALWAN = "https://raw.githubusercontent.com/JonathanSalwan/VMProtect-devirtualization/d2b26d66db59e341f179c7e326246d28c4d25491/"
ASSETS = {
    "fsvm": [
        ("01_fsvm/inputs/bytecode", ECSC + "round-1/rev01/attachments/bytecode", "5353dba4a3cfd04033275c029d00f4e1912ac5465d94633d7abc868e43f79070"),
        ("01_fsvm/inputs/vm.cpp", ECSC + "round-1/rev01/src/vm.cpp", "aba793d119f902e3ea5d5390ae307c72094b354d67c7fe03225fa75e4da702b9"),
    ],
    "vmp": [
        ("02_vmp_trace/inputs/sample2.vmp.trace", SALWAN + "vmp_traces/sample2.vmp.trace", "735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443"),
        ("02_vmp_trace/inputs/sample2.c", SALWAN + "vmp_binaries/samples-source/sample2.c", "29304276e06d81a111fdde1b19c52266355c23de0e3a960fc941472ce1f010da"),
        ("02_vmp_trace/inputs/attack_vmp.py", SALWAN + "attack_vmp.py", "2cd9f83be9eb5af9811f96a7ac2b11bbeaea7a25b4426857a89aab098a2ba7b7"),
    ],
    "multipath": [
        ("03_multipath/inputs/sample4.vmp.trace.1", SALWAN + "vmp_traces/sample4.vmp.trace.1", "e54a4323f23bf3ad481aebf71385d6a2d8b80682674b2d8a138434624a77ff02"),
        ("03_multipath/inputs/sample4.vmp.trace.2", SALWAN + "vmp_traces/sample4.vmp.trace.2", "2d1aae4d2fddf1fc3f28c10266fc3a68e08b44477dec67f379414215cde22d06"),
        ("03_multipath/inputs/sample5.vmp.trace.1", SALWAN + "vmp_traces/sample5.vmp.trace.1", "fe78089e4be602e75921f13861db58764435d3186211e2d0013a8ec7163f1017"),
        ("03_multipath/inputs/sample5.vmp.trace.2", SALWAN + "vmp_traces/sample5.vmp.trace.2", "be80affee738b521253f7e2c3e438c5a694f26aa37afe66ecc79418c6ea0c936"),
        ("03_multipath/inputs/sample6.vmp.trace.1", SALWAN + "vmp_traces/sample6.vmp.trace.1", "2ff85b4d4ac080a58a6ef9e93829cb5443f7ef33e5a9b49b4b18a7950b96b729"),
        ("03_multipath/inputs/sample6.vmp.trace.2", SALWAN + "vmp_traces/sample6.vmp.trace.2", "d06ad3b2fd1a4f2e152d933ca061c7285052b1fb7f49f014575283f751d6d785"),
        ("03_multipath/inputs/sample4.c", SALWAN + "vmp_binaries/samples-source/sample4.c", "da01cd6f8a4b3a1a5f0d6289bf1b3103f1fa560ed03a5cbc1c38e9be001d02de"),
        ("03_multipath/inputs/sample5.c", SALWAN + "vmp_binaries/samples-source/sample5.c", "4a4a4cab88d19e29178a1db0b890599a89395db0a525419ee39a9e24346daa3e"),
        ("03_multipath/inputs/sample6.c", SALWAN + "vmp_binaries/samples-source/sample6.c", "12472198c9ed06dc0a2d952e090559181dc58b6933f053e4836f8479f1901d17"),
    ],
}


def fetch(group):
    for relative, url, expected in ASSETS[group]:
        path = ROOT / relative
        if path.exists():
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"SHA256 mismatch: {path}; inspect/remove it before retrying")
            print(f"verified {relative}")
            continue
        with urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Downloaded SHA256 mismatch: {url}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"downloaded {relative} ({len(data)} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=["all", *ASSETS], nargs="?", default="all")
    args = parser.parse_args()
    try:
        for group in ASSETS if args.group == "all" else [args.group]:
            fetch(group)
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")
