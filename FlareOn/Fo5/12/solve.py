#!/usr/bin/env python3
"""
Flare-On 5 Challenge 12 - suspicious_floppy (三層嵌套 VM)

結構（完整的逐層還原與驗證見 VMP/05_floppy/）：
    TMP.DAT 是常駐的 INT 13h hook（16 位元 x86），讀取 MESSAGE.DAT 時呼叫密碼檢查。
    檢查函式在上面跑 Subleq VM，Subleq 程式又實作了一台 RSSB VM，RSSB 程式才是真正的檢查。
    flag 就是密碼本身。

還原出來的檢查（c[] 是密碼的 32 個 word，NUL 之後為 0）：
    p   = 第一個 '@' 的位置（沒有 '@' 直接拒絕）
    K(p)= (p << 11) + (p << 10)，但 p = 16 時 p << 11 == 0x8000，RSSB 的搬移巨集搬不動 0x8000，
          所以 K(16) = 0x4000
    G   = K(p) + sum(c[:p])                       (mod 2^16)
    x_i = (c[2i+1] - 32) * 128 + (c[2i] - 32)      (mod 2^16)
    通過 ⇔ i = 0..14 都滿足 ((x_i ^ 33*i) + G) mod 2^16 == table[i]

求解：G 只有 65,536 種，給定 G 每一對都能直接反推，所以窮舉 G 與長度 1..32 即可，不需要 SMT。
    只讀前 30 個字元、也不檢查長度，所以 flag 後面再接 1–2 個任意字元同樣會通過。
"""
import hashlib
import os
import struct

TMP_SHA256 = "b9917d86002ba58f10883d11ca35827f93ac293b56f4b469557c6c987e8cd423"
RESIDENT = 0x43          # TMP.DAT[0x43:] is copied to the resident segment at offset 0
MEM0 = 0x223             # Subleq word i lives at segment offset MEM0 + 2*i
RSSB_BASE = 0x7F6        # RSSB word k is Subleq word RSSB_BASE + k
TABLE = 0xA79            # RSSB index of the 15 target words
PAIRS, MAXLEN = 15, 32
PRINTABLE = range(0x20, 0x7F)


def fat12_file(image, wanted):
    bps, spc, reserved, fats, roots = struct.unpack_from("<HBHBH", image, 11)
    spf = struct.unpack_from("<H", image, 22)[0]
    fat = image[reserved * bps:(reserved + spf) * bps]
    root = (reserved + fats * spf) * bps
    data = root + roots * 32
    for i in range(roots):
        e = image[root + 32 * i:root + 32 * i + 32]
        if e[0] == 0:
            break
        name = (e[:8].rstrip() + b"." + e[8:11].rstrip()).decode(errors="replace").strip(".")
        if e[0] == 0xE5 or e[11] & 0x18 or name.upper() != wanted:
            continue
        cluster, size = struct.unpack_from("<H", e, 26)[0], struct.unpack_from("<I", e, 28)[0]
        body = bytearray()
        while 2 <= cluster < 0xFF8:
            off = data + (cluster - 2) * spc * bps
            body += image[off:off + spc * bps]
            v = struct.unpack_from("<H", fat, cluster * 3 // 2)[0]
            cluster = v >> 4 if cluster & 1 else v & 0xFFF
        return bytes(body[:size])
    raise FileNotFoundError(wanted)


def read_table(tmp):
    seg = tmp[RESIDENT:]
    off = MEM0 + 2 * (RSSB_BASE + TABLE)
    return list(struct.unpack_from("<%dH" % PAIRS, seg, off))


def at_weight(p):
    double = (p << 11) & 0xFFFF
    return ((0 if double == 0x8000 else double) + (p << 10)) & 0xFFFF


def check(password, targets):
    c = list(password[:MAXLEN]) + [0] * (MAXLEN - len(password[:MAXLEN]))
    if 0x40 not in c:
        return False
    p = c.index(0x40)
    g = (at_weight(p) + sum(c[:p])) & 0xFFFF
    return all(((((c[2 * i + 1] - 32) * 128 + (c[2 * i] - 32)) & 0xFFFF) ^ (33 * i)) + g & 0xFFFF == targets[i]
               for i in range(PAIRS))


def solve(targets):
    """All printable passwords the check accepts; '?' marks a character the check never reads."""
    found = set()
    past_end = (-32 * 128 - 32) & 0xFFFF            # x of a pair made of two zero words
    for g in range(0x10000):
        typed, half = [], []
        for i in range(PAIRS):
            x = ((targets[i] - g) & 0xFFFF) ^ (33 * i)
            lo, hi = x & 0x7F, x >> 7
            typed.append((lo + 32, hi + 32) if lo <= 0x5E and hi <= 0x5E else None)
            first = (x + 32 * 128 + 32) & 0xFFFF
            half.append("end" if x == past_end else first if first in PRINTABLE else None)
        for length in range(1, MAXLEN + 1):
            chars = []
            for i in range(PAIRS):
                a, b = 2 * i, 2 * i + 1
                if b < length:
                    if typed[i] is None:
                        break
                    chars += typed[i]
                elif a < length:
                    if half[i] in (None, "end"):
                        break
                    chars.append(half[i])
                elif half[i] != "end":
                    break
            else:
                found.update(complete(bytes(chars), length, g))
    return sorted(found)


def complete(head, length, g):
    """Characters after the 30 checked ones are free unless they hold the first '@' or precede it."""
    tail = length - len(head)
    if b"@" in head:
        p = head.index(b"@")
        return [head + b"?" * tail] if (at_weight(p) + sum(head[:p])) & 0xFFFF == g else []
    out = []
    for p in range(len(head), length):
        base = (at_weight(p) + sum(head)) & 0xFFFF
        if p == len(head) and base == g:
            out.append(head + b"@" + b"?" * (length - p - 1))
        elif p == len(head) + 1:
            ch = (g - base) & 0xFFFF
            if ch in PRINTABLE and ch != 0x40:
                out.append(head + bytes([ch]) + b"@" + b"?" * (length - p - 1))
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    image = open(os.path.join(here, "suspicious_floppy_v1.0.img"), "rb").read()
    tmp = fat12_file(image, "TMP.DAT")
    if hashlib.sha256(tmp).hexdigest() != TMP_SHA256:
        raise SystemExit("TMP.DAT 不是預期的版本")
    targets = read_table(tmp)
    print("table:", " ".join("%04x" % t for t in targets))

    solutions = solve(targets)
    for s in solutions:
        print("accepted:", s.decode())
    flag = solutions[0]
    assert all(check(s.replace(b"?", b"X"), targets) for s in solutions)
    assert not check(flag[:5] + b"x" + flag[6:], targets)
    print("FLAG:", flag.decode())


if __name__ == "__main__":
    main()
