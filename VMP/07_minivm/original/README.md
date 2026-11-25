# minivm —— 教學用小型 VM 保護器

一個單檔、可編譯執行的「虛擬化混淆」(virtualization obfuscation) 示範，
用來理解 Tigress / VMProtect 這類工具的核心原理。

> ⚠️ **定位**：這是學習與理解用的教材，**不是**可用於正式產品的保護方案。
> 它能擋住隨手的靜態反組譯，但擋不住任何認真的動態分析。詳見 [安全分析](#6-安全分析實際擋得住什麼)。

---

## 目錄

1. [它在做什麼](#1-它在做什麼)
2. [快速開始](#2-快速開始)
3. [整體架構](#3-整體架構)
4. [虛擬指令集 (ISA)](#4-虛擬指令集-isa)
5. [四層逐層拆解](#5-四層逐層拆解)
6. [安全分析：實際擋得住什麼](#6-安全分析實際擋得住什麼)
7. [擴充方向](#7-擴充方向)
8. [名詞對照](#8-名詞對照)

---

## 1. 它在做什麼

一般程式：原始碼 → 編譯成機器碼 → CPU 執行。逆向者反組譯機器碼就能看懂邏輯。

虛擬化保護：把要保護的函式**翻成一套自訂的 bytecode**，程式裡不再有這個函式的
機器碼，只有一個**直譯器 (interpreter)** 在執行期讀 bytecode 跑起來。逆向者反組譯
binary，只會看到直譯器的 dispatch 迴圈和一堆加密過的位元組，看不到原本的演算法。

本專案保護的「秘密」是一個 hash 函式（輸入一個數字，輸出一個 64-bit hash），
格式刻意對齊 Tigress 官方挑戰（`./vm 1234` → 一個數字）。

```
$ ./vm 1234
1448883231529079547
```

---

## 2. 快速開始

```bash
# 編譯
gcc -O2 -Wall -o vm vm.c

# 執行：輸入一個數字，輸出 hash
./vm 1234
./vm 0xdeadbeef        # 支援 16 進位

# 傾印解密後的 bytecode —— 這就是逆向者攻破加密層後看到的東西
VM_DISASM=1 ./vm 1234
```

`VM_DISASM=1` 的輸出：

```
[disasm of decrypted bytecode, 73 bytes]
  0000: INPUT
  0001: PUSH   0x5bd1e995
  0010: XOR
  0011: PUSH   0x100000001b3
  0020: MUL
  0021: DUP
  0022: SHR    0xf
  0031: XOR
  0032: PUSH   0x9e3779b97f4a7c15
  0041: ADD
  0042: ROL    0xd
  0051: PUSH   0xff51afd7ed558ccd
  0060: MUL
  0061: DUP
  0062: SHR    0x21
  0071: XOR
  0072: HALT
```

程式內建**自我驗證**：每次執行都會把 VM 結果和原生 reference 函式對照，
不一致會在 stderr 印出 `MISMATCH!`。正式出貨時會把 reference 拿掉。

---

## 3. 整體架構

```
            建置期 (真實情境會離線先做好)
   ┌─────────────────────────────────────────────┐
   │  secret 演算法                                 │
   │     │  assemble_secret()  (第 2 層：組譯器)     │
   │     ▼                                          │
   │  明文 bytecode                                 │
   │     │  crypt_inplace()    (第 3 層：加密)       │
   │     ▼                                          │
   │  加密 blob  ← 出貨 binary 裡只有這個            │
   └─────────────────────────────────────────────┘
                      │
            執行期    ▼
   ┌─────────────────────────────────────────────┐
   │  加密 blob                                     │
   │     │  crypt_inplace()    (XOR 兩次 = 解密)     │
   │     ▼                                          │
   │  明文 bytecode + input                         │
   │     │  vm_run()           (第 4 層：直譯器)     │
   │     ▼                                          │
   │  結果                                          │
   └─────────────────────────────────────────────┘
```

對應 `vm.c` 裡的程式碼區塊：

| 層 | 函式 / 區塊 | 角色 |
|----|-------------|------|
| 1. 指令集 | `enum { OP_* }` | 定義虛擬 CPU 懂的指令 |
| 2. 組譯器 | `assemble_secret()` + `a_*` helper | 把演算法變成 bytecode |
| 3. 加密 | `crypt_inplace()` | 滾動金鑰 XOR，藏住明文 opcode |
| 4. 直譯器 | `vm_run()` | dispatcher + handlers，執行 bytecode |
| (附) 反組譯 | `vm_disasm()` | 模擬逆向者的視角 |
| (附) 驗證 | `secret_reference()` | 原生等價函式，確認 VM 正確 |

---

## 4. 虛擬指令集 (ISA)

Stack-based（堆疊式），所有值都是 `uint64_t`。
部分指令後面跟一個 **8-byte little-endian 的 operand**。

| Opcode | 值 | Operand | 語意 |
|--------|------|---------|------|
| `INPUT` | 0x10 | — | 把輸入值推上堆疊 |
| `PUSH`  | 0x11 | imm (8B) | 推一個立即值 |
| `ADD`   | 0x12 | — | `b=pop; a=pop; push(a+b)` |
| `SUB`   | 0x13 | — | `push(a-b)` |
| `MUL`   | 0x14 | — | `push(a*b)` |
| `XOR`   | 0x15 | — | `push(a^b)` |
| `AND`   | 0x16 | — | `push(a&b)` |
| `OR`    | 0x17 | — | `push(a\|b)` |
| `SHR`   | 0x18 | n (8B) | `push(pop() >> n)` |
| `SHL`   | 0x19 | n (8B) | `push(pop() << n)` |
| `ROL`   | 0x1a | n (8B) | `push(rotl64(pop(), n))` |
| `DUP`   | 0x1b | — | 複製堆疊頂端 |
| `HALT`  | 0x1c | — | 停止，堆疊頂端即結果 |

> **為什麼是 stack-based？** 不用處理暫存器配置，組譯器超簡單，handler 也短。
> 代價是指令數比 register-based 多。教學上 stack-based 最好懂；VMProtect 實際是
> register-based（有一組虛擬暫存器 context）。

### 範例：`h ^= h >> 15` 怎麼編碼

堆疊頂端是 `h`：

```
DUP        ; 堆疊: h h
SHR 15     ; 堆疊: h (h>>15)
XOR        ; 堆疊: h^(h>>15)
```

---

## 5. 四層逐層拆解

### 第 1 層：指令集 (`enum OP_*`)

就是一張「這台虛擬 CPU 懂哪些指令」的表。`has_operand()` 告訴 fetch 邏輯哪些
opcode 後面跟著 8-byte operand——這同時也是**手動逆向 VM 的第一個難關**：
不知道指令長度，就切不出指令邊界。

### 第 2 層：組譯器 (`assemble_secret`)

用 `emit8` / `emit64` 把 opcode 和 operand 一個個寫進 buffer。
`a_input / a_push / a_xor…` 是薄薄的 helper，讓 secret 讀起來像一段程式：

```c
a_input(a);                                 // h = x
a_push(a, 0x5bd1e995ULL);  a_xor(a);        // h ^= 0x5bd1e995
a_push(a, 0x100000001b3ULL); a_mul(a);      // h *= FNV prime
a_dup(a);  a_shr(a, 15);   a_xor(a);        // h ^= h >> 15
...
```

> **真實保護器的差別**：這一步是一個完整的 compiler，輸入是 C 原始碼或某種
> IR，自動翻成 bytecode。本專案為了單檔示範，直接手工 emit。

被保護的演算法（MurmurHash 風格的 finalizer）：

```c
h = x;
h ^= 0x5bd1e995;
h *= 0x100000001b3;             // FNV-1a 質數
h ^= h >> 15;
h += 0x9e3779b97f4a7c15;        // 黃金比例常數
h  = rotl64(h, 13);
h *= 0xff51afd7ed558ccd;        // murmur3 常數
h ^= h >> 33;
return h;
```

### 第 3 層：加密 (`crypt_inplace`)

逐 byte XOR，金鑰每個 byte 更新一次：`k = k*31 + 17`（LCG 式的滾動金鑰）。
XOR 的對稱性讓同一個函式既能加密也能解密（做兩次就還原）。

出貨 binary 裡，bytecode 是密文，靜態反組譯看到的是一堆雜訊，認不出 opcode。

> **侷限**：金鑰種子 `KEY_SEED` 和更新公式都寫死在程式裡。這只是提高「看懂」的
> 成本，不是加密意義上的安全。

### 第 4 層：直譯器 (`vm_run`)

核心就是 **dispatcher**：

```c
while (pc < len) {
    uint8_t op = code[pc++];
    switch (op) {                    // ← 這個 switch 就是 dispatcher
    case OP_INPUT: PUSH(input); break;
    case OP_ADD: { uint64_t b=POP(), a=POP(); PUSH(a+b); } break;
    ...
    case OP_HALT: return POP();
    }
}
```

`pc` 是虛擬程式計數器 (VPC)，`stack/sp` 是虛擬堆疊。每個 `case` 是一個 handler。
執行前先 `crypt_inplace` 解密。

> **注意一個坑**：`PUSH(POP() >> n)` 這種寫法會在同一運算式裡同時 `sp++` 和
> `--sp`，是未定義行為。程式裡已改成先 `POP()` 進暫存變數再 `PUSH`。

---

## 6. 安全分析：實際擋得住什麼

### ✅ 擋得住

- **直接靜態反組譯 binary**：看到的是加密 blob + 一個泛用 dispatch 迴圈，
  不是原本那串算式。反編譯器還原不出 `h ^= h >> 15` 這種邏輯。

### ❌ 擋不住

- **動態分析**：金鑰和解密迴圈都在程式裡。在 `vm_run` 入口下斷點，直接從記憶體
  dump 出明文 bytecode（就是 `VM_DISASM=1` 給你看的東西）。
- **符號執行 / trace 化簡**：像 Triton 這類工具完全無視 VM 結構，把輸入設成符號，
  跑一條 trace，taint 砍掉 VM 機制指令，化簡後直接得到輸入→輸出的運算式。
  這正是 Jonathan Salwan 破 Tigress 挑戰的做法。
- **常數指紋**：`0x5bd1e995`、`0x9e3779b9...` 這些是公開演算法的招牌常數，
  一眼就認得出是 MurmurHash。

**核心教訓**：混淆是提高成本，不是提供保證。只要程式在攻擊者的機器上執行、
金鑰也在同一台機器，足夠的動態分析一定能還原。真正要保護資料，用標準加密
(AES/RSA)；混淆只適合拿來墊高逆向門檻，拖延時間。

---

## 7. 擴充方向

依性價比排序（想親手加硬度可從上往下做）：

1. **opcode 重排 + 多重 handler**（建議起手式）
   每次建置隨機打亂 opcode 編號，並為同一語意準備多個 handler，dispatch 時
   隨機選。這會破壞逆向者的 pattern matching——體現 Tigress「diversity」的核心。
2. **superoperator**：把常見指令序列（如 `DUP; SHR n; XOR`）合併成一條複合指令，
   讓單一 handler 的語意變複雜，手動分析更難。
3. **常數拆解**：把顯眼常數 `0x5bd1e995` 改寫成執行期才算出的運算式，消除指紋。
4. **bytecode 分段 + 間接跳轉**：破壞「一條直線跑到底」的結構。
5. **完整性自檢 + 反除錯**：偵測 `ptrace`，校驗自身 code section 的 checksum。
6. **多層虛擬化 / JIT**：把直譯器本身再虛擬化一次，或執行期生成 handler 機器碼。

> 每加一層，debug 難度也跟著上升，建議每次只加一項並保留自我驗證。

---

## 8. 名詞對照

| 中文 | 英文 | 說明 |
|------|------|------|
| 虛擬化混淆 | virtualization obfuscation | 把程式碼翻成自訂 bytecode 來隱藏邏輯 |
| 直譯器 | interpreter | 執行期讀 bytecode 跑起來的迴圈 |
| 派遣 | dispatch | 根據 opcode 跳到對應 handler |
| 處理常式 | handler | 實作單一 opcode 語意的那段碼 |
| 虛擬 PC | VPC (virtual program counter) | 指向目前 bytecode 位置 |
| 混淆 vs 加密 | obfuscation vs encryption | 前者拖時間無保證，後者有數學保證 |

---

## 檔案清單

```
vmprotect/
├── vm.c        # 全部原始碼（單檔，約 230 行）
└── README.md   # 本文件
```
