# Tigress challenge 0004–0006：雙層 VM、VM + JIT、雙層 JIT，全部還原成 C

## 本次成果

[Tigress 挑戰](https://tigress.cs.arizona.edu/challenges.html)最難的三組，每組 5 個程式，共 15 個 stripped Linux binary。15 個的 `SECRET()` 都還原成可編譯、可讀的 C（12 到 48 行），並通過各自的驗證關卡。

| 組別 | 保護 | 還原方式 | 結果 |
|---|---|---|---|
| 0004 | Virtualize 兩次（內層 VM 的 PC 用隱式資料流初始化）＋ branch function ＋ opaque predicate | 不分析外層 VM，直接對內層 VM 做黑箱探測 | 5/5 |
| 0005 | Virtualize ＋ JIT（含隱式資料流） | 從記憶體取出 JIT 生成的直譯器，再做黑箱探測 | 5/5 |
| 0006 | JIT 兩次 | 從記憶體取出第二層 JIT 生成的原生碼，x86 提升成 C | 5/5 |

三組都沿用[單元 06](../06_tigress/writeup.md) 的 C 後端（運算式樹 → 陣列與窄存取還原 → if/else 與 while 結構化），差別只在怎麼得到那棵樹。

0004 challenge-3 的結果（外層是每條內層指令要跑 16 萬條原生指令的 VM）：

```c
void SECRET(unsigned long input[1], unsigned long output[1])
{
    unsigned long a83[4];
    unsigned int v43_32;
    unsigned long v51;

    a83[0] = ((input[0] >> 51) | (input[0] << 13));
    a83[1] = (0xfa0000000002c90cUL * (input[0] / 6UL));
    a83[2] = ((a83[1] | a83[0]) + input[0]);
    a83[3] = ((a83[1] + input[0]) >> ((1UL | (7UL & ((0x28e5fc28UL - (a83[0] - 0x2ed5cd7eUL)) >> 2))) & 63));
    a83[3] = (a83[3] >> ((1UL | (7UL & (a83[3] >> 1))) & 63));
    v51 = 0UL;
    while (v51 < 3UL) {
        a83[2] = (((7UL & a83[v51]) << 2) | a83[2]);
        v43_32 = *((unsigned int *)&a83[3] + 1);
        *((unsigned int *)&a83[3] + 1) = *((unsigned int *)&a83[3] + 0);
        *((unsigned int *)&a83[3] + 0) = v43_32;
        v51 = (2UL + v51);
    }
    output[0] = (((a83[1] * a83[0]) >> ((0x40UL - (1UL | (0xfUL & ((0x4e1a7f2UL * a83[3]) ^ a83[2])))) & 63)) | ((a83[1] * a83[0]) << ((1UL | (0xfUL & ((0x4e1a7f2UL * a83[3]) ^ a83[2]))) & 63)));
    return;
}
```

## 執行

```powershell
cd VMP/08_tigress_hard
../.venv/Scripts/python fetch.py            # 從單元 06 的壓縮檔解出 15 個 binary，逐檔核對 SHA-256
../.venv/Scripts/python solve0006.py        # 約 30 秒
../.venv/Scripts/python solve0005.py        # 約 8 分鐘（其中 2 分鐘是 z3 逾時）
../.venv/Scripts/python solve0004.py        # 約 2 小時；可加題號只跑一題，例如 solve0004.py 1（7 分鐘）
../.venv/Scripts/python -m unittest test_hard -v   # 17 個測試，約 1 分鐘
```

還原的 C 寫到 `generated/000N-K.c`，驗證摘要在 `generated/report-000N.txt`。環境同單元 06：Windows 11、Python 3.11、`unicorn==2.1.1`、`capstone==5.0.3`、`z3-solver==4.13.0.0`、`lief`、WinLibs gcc。

這些 binary **從來不在本機原生執行**。`emu.py` 把 ELF 載進 Unicorn，所有 libc 匯入函式換成 Python 替身（`strtoul`、`printf`、`malloc`、`posix_memalign`、`memcpy`、`mprotect`、`signal`／`raise` 等），從 `main` 開始跑完整支程式。

## 共用的基礎：整支程式的模擬

每個程式吃一個命令列參數、印一個數字。能把整支程式跑起來，就有了「原程式」的對照基準，所有還原結果最後都要和它比。

兩個細節：

- **`signal`／`raise`**：部分 0005、0006 程式的隱式資料流是「註冊 handler，再 `raise`」。替身同步呼叫 handler 再回到 `raise` 的呼叫端。
- **後加的 hook 不會生效**：Unicorn 把翻譯過的程式碼快取起來，之後才加的 code hook 和 `count` 上限都不會插進舊的翻譯區塊。現象是 hook 一次都沒被呼叫，但程式照常跑完、結果正確。每次加 hook 或切換計數模式後要 `ctl_remove_cache`。

## 0006：雙層 JIT

`Jit` 變換把 `SECRET` 改寫成「執行時呼叫 JIT 函式庫生成機器碼，再跳過去執行」。套兩次的結果：

```
原生 SECRET ──生成──▶ 外層 JIT 碼（14–29 KB，含隱式資料流）
外層 JIT 碼 ──生成──▶ 內層 JIT 碼（433–936 bytes）＝ 原本的 SECRET
```

做法是觀察 `posix_memalign` 配出來的可執行 buffer。跑完一次之後，第二個 buffer 就是內層 JIT 碼。外層那 14–29 KB 完全不用看。

內層碼很規律：每個 C 敘述各自編譯，值只在敘述內放在暫存器，敘述之間一律經過 frame。`x86lift.py` 對每個 basic block 做符號求值，轉成單元 06 的運算式樹。不在處理範圍內的指令直接報錯，另外有兩條保護：

- 暫存器在區塊開頭被讀取（跨區塊存活）→ 報錯。
- 某個值在一次 store **之前**從記憶體讀出、卻在 store **之後**才使用 → 報錯。否則 load 可能被搬到 store 的另一邊。

## 0005：VM + JIT

JIT 生成的是一個 5–8 KB 的 **stack VM 直譯器**（if 串 dispatch），bytecode 在 `.data`。VM 的版面不是比對程式碼得到的，而是觀察一次執行：

| 要找的東西 | 觀察方式 |
|---|---|
| dispatch 起點 | 最多 handler 結尾跳回去的位址（27–35 個 `jmp` 指向同一處） |
| vpc 槽位 | 到達起點後第一個被讀取的 8-byte frame 槽位，值必須落在 `.data` |
| vsp 槽位 | 最常被寫入「frame 內位址」的槽位 |

有了這三樣，單元 06 的方法原封不動套上去：把每個 opcode 丟進真實 handler 做實驗來判斷語意、解碼 bytecode、提升成 C。隱式資料流（把值拆成位元逐一複製）對黑箱探測沒有影響，因為探測只看「執行前後狀態怎麼變」。

## 0004：雙層 VM

```
原生碼      ＝ VM2 的直譯器（dispatch 每題不同：call／switch／direct／indirect／ifnest）
VM2 bytecode ＝ VM1 的直譯器（PC 用隱式資料流初始化）
VM1 bytecode ＝ SECRET
```

每條 VM1 指令要跑 1 萬到 16 萬條原生指令。原本以為要先還原 VM2 才碰得到 VM1，但有一個性質可以繞過去：**Tigress 把被虛擬化函式的區域變數留在原生 frame 裡**。所以 VM1 的 pc、stack pointer、stack 都是 `SECRET` 原生 frame 上的固定記憶體位置，VM1 的 bytecode 是 `.data` 裡的位元組陣列。外層 VM 怎麼實作並不重要。

全部用觀察找出來：

| 要找的東西 | 觀察方式 |
|---|---|
| `SECRET` | 第一個以 `(指向輸入值的指標, 另一個堆疊指標)` 被呼叫的函式 |
| VM1 的 pc 槽位 | 每次對 `.data` 做 1-byte 讀取時，值剛好等於讀取位址的堆疊槽位；兩層都用 byte opcode 時取讀取次數少的那組 |
| `ret` 的 opcode | 真實執行中最後取出的 opcode |
| 可重入的快照 | 對指令數做二分搜尋，停在「第一次取 opcode 之前、最後一次讀 pc 槽位」的前一條指令。在這之前的執行不依賴 bytecode，也不依賴輸入 |
| VM1 的 sp 槽位 | 探測到某個 opcode 是 `push imm64` 之後，指向那個立即值所在格子的槽位；再確認改寫它會讓 push 落在別處 |

**探測方式和 0005 不同。** 外層 VM 的 dispatch 形式不固定（direct threading 根本沒有單一起點），所以沒辦法「跑到下一次回到起點就停」。改成：

1. 還原快照，把 pc 指到 scratch 區的 `[opcode, 運算元, ret, ret, ret, …]`，直接改寫 stack 的內容和 sp。
2. 一路跑到 `SECRET` 返回。
3. 從已經返回、但內容還在的 frame 讀出 pc、sp、stack top。pc 停在哪個 `ret` 就知道這條指令多長、有沒有跳。

這需要先量出每個 opcode 的長度（不給運算元，讓它把後面的 `ret` 當運算元讀，看停在哪）；跳躍指令則用不會落在自己運算元裡的位移來測。

單元 06 的分類器有兩個假設在這裡不成立，以補充規則處理：存 `input`／`output` 指標的槽位不在 `rbp-0x400` 以內（外層 VM 讓 frame 變大，實際在 `rbp-0x8a8` 附近）；跳躍用隨機位移測試，有機會跳進自己的運算元。

## 驗證關卡

任何一關失敗就停止。

| 關卡 | 0004 | 0005 | 0006 |
|---|---|---|---|
| 生成的程式碼不隨輸入改變 | — | JIT buffer 兩次執行逐位元組相同 | 同左 |
| 語意模型對得上真實執行 | **trace**：Python 寫的 VM1 模型和真實程式並行，逐一比對取 opcode 的位址序列與每次 store 的（位址、大小、值），共 192,917 步 | **lockstep**（單元 06）：每一步比對 pc、sp、stack top、store，共 178,026 步 | 不適用（沒有 VM 模型） |
| 路徑涵蓋（z3） | 43 個區塊：42 個有解出的輸入走到，1 個證明不可達 | 27 個區塊：26 個走到，**1 個未判定** | 15 個區塊：14 個走到，1 個證明不可達 |
| gcc 編譯的 C ＝ 原 `SECRET` | 101–392 組輸入 | 2,001–2,002 組 | 2,001–2,002 組 |
| ＝ 整支原程式（含 `main`） | 每題 8 組 | 每題 16 組 | 每題 24 組 |

逐題數字見 `generated/report-000N.txt`。

「證明不可達」的兩個區塊都是條件為 `!=` 的分支的空 else（例如 0006 challenge-3 的 `a0 + a1 != a2 * a3`，z3 證明相等的情況不存在）。

## 沒有完全驗證到的部分

- **0005 challenge-2 有一個分支沒有被任何測試輸入走到。** 條件是 `(a44[1] + a44[0]) == (a44[2] ^ a44[3])`，兩邊混了乘法、除以 3 和變數旋轉，z3 在 60 秒內判不出能否成立。那一側的 4 行 C 是從 bytecode 提升的，每個 opcode 的語意都經過 lockstep 驗證，但整段沒有實際執行比對過。
- **0004 的 C 比對組數少。** 原程式每跑一次要 0.9 到 18 秒，比對設了 5 分鐘上限，所以只有 101–392 組，其中 challenge-4 的前 100 組輸入只產生 47 種不同輸出。0004 的主要證據是 trace 關卡，而不是這一關。
- **沒有真實 CPU 的對照。** 這台電腦沒有 Linux，「原程式的輸出」全部來自 Unicorn 加上我寫的 libc 替身。有檢查過的只有：換掉 `rand` 的種子後 0004 五題輸出不變。
- **等價性是測試出來的，不是證明。** 和單元 06 相同，C 與 binary 之間沒有 SMT 等價證明。

## 過程中犯的錯

- **hook 沒觸發卻沒發現原因**：0005 的版面偵測一直回報找不到 dispatch 迴圈，實際上是 hook 加在已翻譯的程式碼上。0004 的二分搜尋也因為同樣原因得到「第 2049 條指令就取了 opcode」這種不可能的數字。
- **探測碼後面留了隨機位元組**：照搬單元 06 的探測（opcode 後面接 16 個隨機位元組），在「跑到函式返回」的做法下，多出來的位元組會被當成指令執行。
- **每次執行都開著指令計數**：0004 第一題花了 25 分鐘，大部分時間耗在計數模式和反覆清快取。改成只有需要上限的探測才計數後是 7 分鐘。
- **z3 沒設時限**：0005 challenge-2 第一次跑了十幾分鐘沒有輸出。
- **涵蓋率記帳錯誤**：路徑若在兩側都未判定的分支被放棄，途中走過的區塊沒被記錄，會被歸類成「已證明不可達」。是 `test_timeout_is_reported_as_undecided_not_as_dead` 抓到的。這次 15 題沒有遇到這種情況，但邏輯已修正；0004 的報告是修正前產生的（它沒有未判定分支，結論不受影響），沒有為此重跑兩小時。

## 限制

- **只支援這三組用到的形式**：`x86lift.py` 只認 MyJIT 產生的指令樣式；0004 假設內層 VM 用 1-byte opcode（五題都是），外層 VM 若把內層的區域變數搬離原生 frame 就不適用。
- **0001–0003 沒做**：superoperator、拆開的 handler、算術編碼不在單元 06 的候選語意裡。
- **離「慣用寫法」還有距離**：rotate 是兩個位移相 OR、型別只分寬度、變數名用 frame 位移，這些和單元 06 相同。
- **0006 和 0005 的外層 JIT 沒有分析**：它只被當成「會生出內層程式碼的黑箱」，隱式資料流怎麼編進去的沒有研究。
