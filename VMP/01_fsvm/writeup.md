# openECSC 2024 fsvm：從 bytecode 還原判定邏輯

## 結果

官方 bytecode 共 1,602 bytes，解碼後是 557 條 VM 指令。部分求值恢復 29 個字元條件，得到：

```text
openECSC{supereasyvmc4e87c4d}
```

這題的實際條件是「讀取的第一個 token 以該字串結尾」。它沒有先檢查長度，因此 `prefixopenECSC{supereasyvmc4e87c4d}` 也會通過；已用官方 C++ VM 驗證。

這是自製 VM 題，適合練習反虛擬化基礎，並不是商用 VMProtect 樣本。

## 來源與重現

- [官方題目與 VM 原始碼](https://github.com/ECSC2024/openECSC-2024/tree/2602f22c664eb98398413e6a7dfe03ea88b2d296/round-1/rev01)。原倉庫以 GPL-3.0 發布，作者資訊見該目錄 `authors.txt`。
- 固定 commit：`2602f22c664eb98398413e6a7dfe03ea88b2d296`。
- bytecode SHA-256：`5353dba4a3cfd04033275c029d00f4e1912ac5465d94633d7abc868e43f79070`。
- VM C++ SHA-256：`aba793d119f902e3ea5d5390ae307c72094b354d67c7fe03225fa75e4da702b9`。
- [Ben 的還原文章](https://blog.deobfuscate.io/using-symbolic-execution-for-devirtualisation) 是方法參考。以下結論由本地 bytecode 分析與官方 VM 交叉驗證取得。

在倉庫根目錄執行：

```powershell
python VMP/fetch_samples.py fsvm
python VMP/01_fsvm/solve.py
python VMP/01_fsvm/verify.py --native
```

前兩個步驟只需 Python 3.10+。`--native` 另需 `g++`；可以 `--compiler` 指定編譯器路徑。去掉 `--native` 仍會執行 Python 比對，但不代表已驗證官方 VM。

2026-11-22 實測：Windows、WinLibs GCC 16.2.0（MinGW-w64 UCRT），`official C++ VM vs interpreter: 52 cases passed`。Windows 開著「智慧型應用程式控制」時，編譯出來的未簽章 `vm.exe` 會被擋下（CodeIntegrity 事件 3077），連結器的 `liblto_plugin.dll` 也會載入失敗；要先關閉這項功能，或改在 Linux／WSL 上執行。

產物：

| 檔案 | 用途 |
|---|---|
| `generated/disassembly.txt` | 完整 VM 指令反組譯，offset 以十六進位顯示 |
| `generated/constraints.txt` | 比較位置、29 個字元條件與兩條分支的輸出 |
| `generated/recovered.py` | 可直接執行的還原判定程式 |
| `generated/verification.txt` | 當次驗證結果 |

## VM 結構與指令

官方 VM 把八個暫存器存為 `regs/reg0` 到 `regs/reg7` 的檔案。PC 是 bytecode 串流的位置。分析時可把檔案內容建模為八個字串，不需要真的進行每一次磁碟讀寫。

這個模型必須保留**字串運算與數值運算的差別**：`"01" + "1"` 的拼接結果是 `"011"`，但把兩者解析為十進位數字相加，結果是 `"2"`。

| opcode | 指令 | 語義 |
|---|---|---|
| `28` | `jmp` | 從指令結束位置相對跳轉 `int(r5)` bytes |
| `29` / `2a` | `je` / `jne` | 比較 r6、r7 的字串；成立才跳轉 |
| `2b` | `jl` | 比較 r6、r7 的有號數值 |
| `2c..33` | `clear` | 對應 r0..r7 寫入空字串 |
| `3d` | `ord src,dst` | 來源字串最後一個字元的碼，寫成十進位字串 |
| `3e` | `chr src,dst` | 數值低 8 bits 轉字元 |
| `3f` | `concat left,right,dst` | 拼接兩個字串 |
| `40..47` | `zero` | 對應暫存器設為 `"0"` |
| `51` | `add left,right,dst` | 十進位有號整數相加，再寫回字串 |
| `52` / `53` | `append` / `pop` | 加上字元 `1`／刪除最後一個字元 |
| `54` | `neg` | 切換前導負號，保留其餘字元 |
| `55` / `56` / `57` | `print` / `read` / `ret` | 輸出 r4／讀取到 r0／結束 |

表中的 opcode 均為十六進位。顯式暫存器 operand 在 bytecode 中以來源在前、目的在後編碼。解碼器會拒絕未知 opcode、截斷指令及 r8 以上的編號。

## 還原過程

`solve.py` 會先將與輸入無關的運算直接求值，例如組出提示字串及數值常數。讀取 r0 時，改以符號化的 `InputTail` 表示輸入。

每次取最後一個字元，就產生 `ord(input[-1])`、`ord(input[-2])` 等符號；刪除字元只更新消耗數量。後續加法與取負號會化成單一字元的線性式，例如：

```text
125 - ord(input[-1])
100 - ord(input[-2])
...
111 - ord(input[-29])
```

在 `0x5d9` 的條件跳轉，r6 已累積這些結果的十進位文字，r7 則是 29 個 `0`。每個數字的表示至少占一個字元；要拼接成恰好 29 個零，每個式子都必須為零。這裡不能誤認成「把所有差值相加等於零」，否則不同位置的錯誤會互相抵消。

還原器確認條件涵蓋連續的 29 個尾端位置，並分別計算比較相等與不等的輸出分支。產出的可執行判定等價於：

```python
token = first_ascii_whitespace_delimited_token(text)
accepted = token.endswith(recovered_suffix)
```

產物中的預期字元來自 bytecode 的運算，求解器沒有硬編碼 flag。前綴會留在 r0 中，但後續沒有使用，因此應保留「前綴可通過」的行為。

## 驗證與限制

2026-10-04，Windows / Python 3.11.0 的實測結果：

```text
decoder/operand/control-flow checks: passed
interpreter vs recovered predicate: 548 cases passed
prefix acceptance and every single-position mutation: verified
short input: interpreter reports ord(empty); recovered check rejects safely
official C++ VM vs interpreter: 52 cases passed
```

測試包含正確 flag、所有 29 個位置的單字元改動、前綴、額外尾字元、空白 token 邊界，以及固定種子的隨機輸入。官方 VM 在臨時目錄編譯執行；Windows 只調整 `mkdir` 為 `_mkdir`，handler 保持原樣。臨時目錄隔離其 `regs/` 檔案。

模型涵蓋 ASCII 輸入、C locale 的 token 讀取與本題所用的有號 64-bit 範圍。過短輸入會在原程式遇到空字串取最後字元，超出可依賴的 C++ 語義；解譯器明確報錯，還原判定函式則安全拒絕。這部分不宣稱與原程式未定義行為等價。

此 lifter 專門辨識本題的單字元線性條件與直線輸出分支。若遇到其他 VM、複雜條件或迴圈，會拒絕分析，不會假裝產生通用還原結果。
