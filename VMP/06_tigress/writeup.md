# Tigress challenge 0000：不看 dispatcher，用實驗還原 VM 指令集並重建 C 原始碼

## 本次成果

[Tigress](https://tigress.cs.arizona.edu/) 是亞利桑那大學的學術混淆器，官方出了一組挑戰題給逆向研究用。這裡做的是 challenge 0000：每個程式的 `SECRET()` 函式都用一層 `Virtualize` 保護，dispatcher 是隨機挑的，VM 是 stack 架構。題目要求從 stripped binary 還原出 `SECRET` 的 C 原始碼，**5 個程式都要破解**才算成功。

這 5 個程式全部還原了。程式本身不知道 dispatcher 屬於哪一種，也不知道 opcode 怎麼編號，指令集是用實驗一條一條測出來的：

| 程式 | dispatcher（看反組譯得知） | opcode | VM 指令 | 路徑 | lockstep 步數 | C 與原始程式比對 |
|---|---|---|---|---|---|---|
| challenge-0 | interpolation search | 20 | 213 | 1 | 16,827 | 2,001 組輸入一致 |
| challenge-1 | binary search | 28 | 630 | 2 | 47,766 | 2,002 組輸入一致 |
| challenge-2 | if 串 | 32 | 893 | 8 | 58,252 | 2,008 組輸入一致 |
| challenge-3 | interpolation search | 20 | 294 | 1 | 23,226 | 2,001 組輸入一致 |
| challenge-4 | switch 跳躍表 | 34 | 884 | 2 | 55,098 | 2,002 組輸入一致 |

還原出來的 C 有 12 到 45 行。裡面看得到陣列、if/else 和 while 迴圈，已經沒有 VM 的痕跡。challenge-0 的完整結果：

```c
void SECRET(unsigned long input[1], unsigned long output[1])
{
    unsigned long a64[4];

    a64[0] = (0x34d870d1UL + input[0]);
    a64[1] = ((input[0] | a64[0]) | 0xffffffffd9fca98bUL);
    a64[2] = (input[0] | 0x46bc480UL);
    a64[3] = (((0x1dd9c3c5UL + input[0]) >> ((((a64[0] * 0x38bca01fUL) & 0xfUL) | 1UL) & 63)) | ((0x1dd9c3c5UL + input[0]) << ((0x40UL - (((a64[0] * 0x38bca01fUL) & 0xfUL) | 1UL)) & 63)));
    a64[3] = (a64[3] | (((a64[2] << (((a64[0] & 7UL) | 1UL) & 63)) & 0x3fUL) << 4));
    output[0] = ((a64[1] + a64[0]) * (a64[2] * (a64[3] * 0x2c7c60b7UL)));
    return;
}
```

challenge-4 的迴圈，含 32 位元半邊互換（節錄）：

```c
    v42 = 1UL;
    while (v42 < 3UL) {
        a80[(v42 + 1UL)] = (a80[(v42 + 1UL)] / 7UL);
        v32_32 = *((unsigned int *)&a80[v42] + 0);
        *((unsigned int *)&a80[v42] + 0) = *((unsigned int *)&a80[v42] + 1);
        *((unsigned int *)&a80[v42] + 1) = v32_32;
        ...
        a80[(v42 + 1UL)] = (a80[v42] - a80[(v42 - 1UL)]);
        v42 = (v42 + 2UL);
    }
```

## 來源與執行

- 挑戰頁面：<https://tigress.cs.arizona.edu/challenges.html>。0000 已經有人解開過，這裡是自己重做一次，研究用，不投稿。
- `devirt.py` 會自己下載 `tigress-challenges-Linux-x86_64.zip`。壓縮檔和 5 個 binary 都用 SHA-256 固定，只解壓到 Git 忽略的 `inputs/`。
- 這些是 Linux ELF，**從來不在本機原生執行**。只有 `SECRET` 這一段 x86 程式碼放進 Unicorn 裡跑，而且 `SECRET` 本身沒有呼叫任何外部函式（`__stack_chk_fail` 除外）。
- 實測環境：Windows 11、Python 3.11.9、`unicorn==2.1.1`、`capstone==5.0.3`、`z3-solver==4.13.0.0`、WinLibs gcc。

```powershell
VMP/.venv/Scripts/python VMP/06_tigress/devirt.py          # 5 個程式、三道關卡，約 15 秒；C 寫到 generated/
cd VMP/06_tigress; ../.venv/Scripts/python -m unittest test_devirt -v
```

## 做法

### 1. 從程式碼讀出 VM 的版面

`_start` 會把 `main` 的位址放進 `rdi`。在 `main` 裡，`mov rsi, rdx; mov rdi, rax` 之後的那個 `call` 就是 `SECRET(in, out)`。`SECRET` 的 prologue 長這樣：

```
lea rax, [rbp-S]   ; mov [rbp-SP], rax        → VM stack 與 vsp 的位置
mov qword [rbp-PC], 0x602060                  → bytecode 位址與 vpc 的位置
```

接下來第一條讀取 `[rbp-PC]` 的指令就是 **dispatch 迴圈的起點**（中間的 `jmp` 會跟過去）。之後的步驟只需要這個起點：每條 VM 指令都是「從起點出發，再回到起點」，不管中間用的是 interpolation search、binary search、if 串還是 switch。任何一步的 bytes 和預期不符，就直接報錯。

### 2. 用實驗判斷 opcode 的語意

`Machine.probe()` 會在 dispatch 起點設定我選好的狀態：bytecode 是 `[opcode, 隨機 operand]`，VM stack 放隨機值，必要時再放一塊指向資料區的記憶體。然後只執行一條 VM 指令，觀察 `pc`、`sp`、新的 stack top 和寫入的記憶體怎麼變。`classify()` 拿多組實驗結果去比對以下候選：

| 類型 | 候選 |
|---|---|
| 二元運算 | 23 種運算 × 運算元順序（`top op second` 或 `second op top`）× 各自是否 `(int)` 轉型 × 寫入寬度 64/32/16/8 |
| 一元運算 | `not`、`neg`、`!`、zero-extend 或 sign-extend 8/16/32 × 寫入寬度 |
| load、store | 大小 × 正負號 × 寫入寬度；store 再加上指標在上還是值在上 |
| push 常數 | operand 大小 × 正負號 × 寫入寬度 |
| push 位址 | 區域變數（`rbp + base + operand`）或參數（位址那一格存的是 `input` 或 `output`） |
| 跳躍 | `pc + 1 + rel32` |
| 條件分支 | 跳躍條件是「低 w 位元不為 0」或「為 0」 |
| ret | 執行完回到 `SECRET` 的呼叫端 |

實驗找出了幾個從反組譯才看得到的細節：

- **運算元順序不固定**：例如 challenge-0 的 `0x2b` 是 `second >> top`，`0x27` 是 `top + (int)second`，也就是指標加上 32 位元的 index。
- **VM stack 是 union**：比較、32 位元 push、16/8 位元 load 只寫入 slot 的低位元，高位元保留原值。所以每種運算都要多一個「寫入寬度」參數。
- **條件分支只看低 32 位元**：判斷的是 `int`，不是整個 64 位元的 slot。

為了讓這些差異能被觀察到，探測時用的資料區位址高位元不為 0（`0x5a5a5a5a8000`）。

### 3. 反組譯

`decode()` 從 `pc 0` 開始做遞迴下降，條件分支的兩邊都會走到。遇到還沒分類過的 opcode，就當場做實驗分類。這樣連從沒執行過的分支也會被解出來。

### 4. 提升成 C

1. **組成運算式樹**：在每個 basic block 內用符號 stack 組出運算式。如果 block 結束或 store 時 stack 不是空的，直接報錯，不然 load 可能會被移到 store 的另一邊。
2. **demanded-bits 化簡**：只寫入低位元的結果，如果後面的運算只用到低位元，就把保留高位元的那部分拿掉。如果有運算用到 32 位元 push 留下的 stack 殘值，提升器會拒絕輸出。
3. **還原位址**：
   - `參數(in)` 先 load 再加上 `i*8`，還原成 `input[i]`。
   - `區域位址 + (int)(i*8 + c)` 還原成陣列元素。
   - 較窄的存取落在某個 8 bytes 元素裡時，寫成 `*((unsigned short *)&a64[2] + 3)`，保持 aliasing 的正確性。
   - 在 `(int)` 裡面的常數，一律當成 32 位元有號數處理。
4. **結構化**：用 post-dominator 把條件分支整理成 if/else，回跳的邊整理成 `while`。目前只處理在迴圈開頭判斷條件、而且只有一個出口的迴圈，其他情況會報錯。

### 5. 列舉路徑

`explore()` 用 z3 在 bytecode 上做符號執行，每遇到一個條件分支，就分別檢查兩邊是否可能成立。如上表，5 個程式共有 14 條路徑，加起來**涵蓋所有已解出的指令**，每條路徑也都解出一組輸入。這一步是必要的：challenge-1 有一個分支要在 `(a0 ^ a1) == (a3 * a2)` 時才會走到，300 組隨機輸入只覆蓋了 630 條指令中的 600 條。

## 驗證關卡

`devirtualize()` 依序檢查以下三關，任何一關失敗就停止：

- **A. lockstep 逐步比對**：用每條路徑的輸入和 78 組邊界值執行原始程式。每回到 dispatch 起點一次，就拿分類出的語意預測下一步的 `pc`、`sp`、新的 stack top、load 讀到的值和 store 寫入的值，再和真實狀態比對。5 個程式共比對了 201,169 步。
- **B. 路徑涵蓋**：z3 列出的所有路徑加起來必須涵蓋全部已解出的指令。
- **C. 還原的 C 與原始程式一致**：用 gcc 編譯還原出的 C，和在 Unicorn 裡跑的原始 `SECRET` 比對 2,000 組輸入，外加每條路徑各一組輸入。在 Windows 上會把 `long` 換成 `long long` 來編譯（`for_host()`），對外的原始碼仍是 Linux LP64。

`test_devirt.py` 有 13 個測試，其中 7 個確認錯誤的模型或錯誤的輸入會被擋下。大部分對應我實際犯過的錯：

- 被改過的程式碼會被拒絕
- 條件分支看整個 64 位元
- 32 位元 push 寫入整個 slot
- 運算元順序反了
- 窄存取拆成獨立變數
- 用到 stack 殘值時不輸出 C
- 隨機輸入漏掉的分支，z3 會找到

## 過程中犯的錯

- **測試資料區的位址取錯**：一開始用 `0x30000000`，指標的高 32 位元是 0，所以看不出「保留高位元」和「清成 0」的差別，load 的寬度判斷可能會錯。改成高位元不為 0 的位址之後，才分得出 16 位元 load 會保留指標的高 48 位元。
- **條件分支當成看整個 64 位元**：challenge-1、2 的輸出因此錯了。逐步比對發現 top 是 `0x22b084b100000000` 時，實際上沒有跳。
- **32 位元 push 當成寫入整個 slot**：最終版的 lockstep 在 challenge-1 第 150 步抓到這個錯誤：真實的 top 是 `0x49d9758800000001`，模型算出 `0x1`。在這之前，我的 scratch 版本只比對最後的 C 輸出，那一關都過了，因為後面的運算只用到低 32 位元。這說明只做端到端比對看不出模型本身的錯誤。
- **窄存取拆成獨立變數**：challenge-1 把 `unsigned short` 片段的互換當成另外的變數，2,000 組輸入全部錯。
- **陣列 index 的 `-1` 寫成 `+0xffffffff`**：在 `(int)` 裡算的 `i - 1`，被我當成 64 位元常數，結果 challenge-4 的 C 一執行就崩潰。
- **operand 全部填 0，跳躍被當成 no-op**：整合成正式程式時，我用全 0 的 operand 探測，`jmp +0` 看起來就像什麼都不做。改成隨機 operand。
- **有一個測試因為死碼而失效**：「窄存取拆成獨立變數」的開關只影響純量，可是最終版把變數都辨識成陣列了，所以那個測試的結果是 0 筆錯誤。我把開關改成也套用在陣列元素上，測試現在會得到 50 筆以上的錯誤，才是真的在檢查。

## 限制

- **只做了 challenge 0000**：0001 以後還加了 superoperator、拆開的 handler、算術編碼的 handler、兩層 VM、JIT。目前的版面偵測在 0001 到 0003 的 prologue 就失敗了，這些留待之後的單元。
- **離比賽要求的「慣用寫法」還有距離**：
  - rotate 是展開成兩個位移相 OR，沒有整理成函式。
  - 型別只分 `unsigned long`、`unsigned int` 等，沒有推斷有號或無號的意圖。
  - 變數名稱是用 frame 位移取的，原本的名稱已經無法得知。
- **等價性是測試出來的，不是證明**：
  - C 和原始程式的一致性來自 2,000 組以上的輸入，加上每條路徑各一組輸入。
  - 語意模型和真實 handler 的一致性來自 20 萬步的逐步比對。
  - C 和 binary 之間沒有做 SMT 等價證明。
- **候選語意是有限的**：如果 handler 做的事不在候選清單裡（例如 superoperator），分類器會回報 `unknown` 並停止，不會猜。
- **假設 Unicorn 對整數指令的模擬是正確的**：這台電腦沒有 Linux，所以沒有拿真實 CPU 跑原始 binary 比對。不過 `SECRET` 只用到一般的整數、位移、乘除指令。
