# VMProtect 3.x：不用 Pin，直接模擬受保護的 ELF 並自動探索路徑

## 本次成果

單元 02、03 只能重播 Salwan 事先用 Pin 錄好的 trace。想換一組輸入或找出另一條路徑，就得回到 Linux 重新錄。本單元改成在 Windows 上用 Triton **直接模擬** VMProtect 保護過的 ELF，再用 concolic execution 自動找出所有路徑：

| 樣本 | C 原始碼 | 自動找到的路徑 | SMT 等價證明 |
|---|---|---|---|
| sample1 | `x + y` | 1 | 通過 |
| sample2 | `x ^ y` | 1 | 通過 |
| sample3 | 8 步 MBA（`char`） | 1 | 通過，並證明等於 `(x ^ 92) + y` |
| sample4 | `x >= y ? x : y`（有號） | 2 | 通過 |
| sample5 | `x + y == 1001 ? x + 1 : y - 1` | 2 | 通過 |
| sample6 | `(unsigned)(x + y) < 1234 ? x + 1 : y - 1` | 2 | 通過 |

sample1、sample3 是前面單元沒有處理過的樣本。多路徑的樣本只需給一組起始輸入 `(1, 2)`，另一條路徑的輸入由 SMT solver 自動找出，例如 sample5 找到的是 `(0, 1001)`。不需要第二條 trace。

模擬器的忠實度用 Salwan 在真實 CPU 上錄的 9 條 trace 驗證：**145,070 條指令的位址和 29,083 次記憶體讀取的值全部一致**。有兩條 trace 的樣本，使用另一條 trace 學到的環境來重現，屬於交叉驗證。

## 來源與執行

- [Salwan 的研究、樣本與 trace](https://github.com/JonathanSalwan/VMProtect-devirtualization/tree/d2b26d66db59e341f179c7e326246d28c4d25491)，固定 commit `d2b26d66`。方法參考歸原作者；本單元的模擬器、環境學習、路徑探索與驗證程式為自行撰寫。
- 所有輸入都用 SHA-256 固定，由 `emulate.py` 自己下載到 Git 忽略的 `inputs/`，不執行任何第三方腳本。
- 實測環境：Windows 11、Python 3.11.9、`triton-library==1.0.0rc4`。

```powershell
VMP/.venv/Scripts/python VMP/04_emulate/emulate.py            # 六個樣本，約 1 分鐘
VMP/.venv/Scripts/python VMP/04_emulate/emulate.py sample5    # 單一樣本
cd VMP/04_emulate; ../.venv/Scripts/python -m unittest test_emulate -v
```

## 做法

### 1. 載入 ELF

樣本是非 PIE 的 x86-64 ELF，位址固定。把每個 `PT_LOAD` 段載進 Triton 的記憶體，從 `secret()` 的進入點開始逐條模擬：sample3 是 `0x4011c9`，其他樣本都是 `0x4011c0`。不需要 Linux，也不需要動態連結器，因為 `secret()` 內部沒有呼叫任何函式庫。

### 2. 找出「環境」

一開始直接模擬 sample1，前 6,852 條指令都和真實 CPU 一致，之後分岔。逐一比對讀到的記憶體值，找到三個**和輸入無關**、但 trace 快照沒有記錄的狀態：

| 狀態 | 真實 CPU | 原本的模擬器 |
|---|---|---|
| RFLAGS | `0x206`（IF=1） | `0x6` |
| `cpuid` leaf 1 | `0x806ec, 0x7100800, 0x7ffafbbf, 0xbfebfbff` | Triton 內建的固定值 |
| `0x616e00` | 指向 heap 物件的指標 | 0（檔案裡的值） |

`0x616e00` 位在 VMP 的資料段，檔案裡是 0，表示 VMP 在程式啟動時才把 heap 指標寫進去。`secret()` 執行時會從那個 heap 物件讀兩個 dword。

`learn_environment()` 會把一條 trace 跑一遍，記下 CPUID 的結果，以及「CPU 讀到、但模擬器從沒寫過」的位元組。學到的東西很少：每個樣本只有 11 到 12 個位元組，sample1、sample2 另外有 3 個位元組，是呼叫端的返回位址。

### 3. heap 物件的規則：dword = heap 位址 ⊕ K

一次只拿掉一個因素來測試，結果顯示每個樣本都**剛好只有一個** heap dword 會影響 VM 的路徑。這個 dword 在同一個樣本的兩次執行之間會變，但會隨 heap 位址一起變：

| 樣本 | heap 位址 | 關鍵 dword | dword ⊕ (uint32)heap |
|---|---|---|---|
| sample4 trace.1 | `0x11aaeb0` | `0xb6793a91` | `0xb7639421` |
| sample4 trace.2 | `0xcfaeb0` | `0xb7ac3a91` | `0xb7639421` |
| sample6 trace.1 | `0x180deb0` | `0x53e17860` | `0x5261a6d0` |
| sample6 trace.2 | `0x1435eb0` | `0x5322f860` | `0x5261a6d0` |

所以從一次執行學到的環境，可以搬到任何 heap 位址使用：只要把關鍵 dword 跟著重新加密鑰（`relocate_heap()`）。交叉驗證就是這樣做的：把 A 執行的環境搬到 B 執行的 heap 位址，再要求 B 的每一次讀取都一致。測試 `test_unkeyed_relocation_is_rejected` 確認，如果搬家時忘了重新加密鑰，B 就無法重現。

改用 Triton 內建的 CPUID 也會在同一處分岔，所以 K 很可能跟 CPUID 有關，例如 VMP 的硬體綁定。這一點**沒有證明**：要不靠 trace 就算出 K，得模擬 VMP 的啟動程式，這不在本單元範圍內。

### 4. 未定義旗標要照真實 CPU 的行為

Intel SDM 規定某些指令執行後部分旗標是「未定義」。Triton 會保留舊值，但 VMP 會用 `pushfq` 把旗標存起來，之後讀回來繼續計算，所以這些位元必須和錄製用的 CPU 一致。用 trace 驗證後採用兩條規則：

- `AND`／`OR`／`XOR`／`TEST` 執行後，AF 清成 0。
- `MUL`／`IMUL` 執行後，SF、ZF、PF 依照**乘積的低半部**計算，AF 清成 0。

第二條是用資料選出來的：13 次乘法全部在 sample3。「全部清成 0」的規則在 sample3 的第 12,202 條指令出錯（真實 CPU 的 PF=1）；「依照低半部計算」的規則讓 9 條 trace 全部一致。這些旗標用 AST 指定，不是寫死成具體值，所以如果它們跟輸入有關，路徑條件不會漏掉這層關係。

### 5. 自動探索路徑

`Explorer.run()` 用一個自訂的呼叫狀態開始：任選的 `rsp`、一個哨兵返回位址，`rdi`／`rsi` 設成符號變數 `x`、`y`。sample3 的參數是 `char`，所以用 8 位元變數再做符號延伸。以下兩種情況會被當成分支點：

- **讀寫的位址跟輸入有關**：這就是 VMP 的虛擬分支（下一個 VIP 從兩個相鄰的堆疊格之一取出），條件是 `lea == 實際位址`。
- **Triton 記錄的 path constraint 跟輸入有關**：原生的 `jcc`，或目標位址跟輸入有關的間接跳躍。

每跑完一條路徑，就對每個分支點詢問 solver：「前面的條件都成立，只有這一個不成立，有沒有解？」有解就把那組輸入加入佇列。佇列空了，探索就結束。

自動找到的虛擬分支：

| 樣本 | 分支指令 | 兩條路徑的輸入 |
|---|---|---|
| sample4 | `0x8ba706 mov rax, qword ptr ss:[rbx]`（第 13,952 條） | `(1, 2)`、`(0x400, 0x800003ff)` |
| sample5 | `0x85bbbe mov rax, qword ptr ss:[rdx]`（第 11,870 條） | `(1, 2)`、`(0, 0x3e9)` |
| sample6 | `0x8a5bb1 mov rbx, qword ptr ss:[r9]`（第 10,725 條） | `(1, 2)`、`(0, 0x18044241)` |

sample5 的分支位址和單元 03 從 trace 找到的相同。

## 驗證關卡

`verify()` 依序檢查以下項目，任何一項失敗都會停止：

1. 每條路徑的輸入滿足它自己的路徑條件。
2. **涵蓋完整**：「所有路徑條件的 OR 不成立」是 UNSAT，也就是沒有任何輸入落在已探索的路徑之外。
3. **與 C 原始碼等價**：把路徑用 `ite` 串起來合併後，「合併結果 ≠ C 原始碼」是 UNSAT。C 的語意是依 gcc／x86-64 手寫：sample3 用有號 `char` 參數和會溢位繞回的 32 位元 `int`。
4. 合併後的 AST 在邊界值與隨機輸入上的求值結果，和 Python 寫的 C 參考實作一致。
5. 另外重新模擬 6 組輸入（不經過合併），結果也和 C 一致。

`test_emulate.py` 有 11 個測試，其中 5 個確認錯誤的結果會被擋下：少一條路徑、拿另一個樣本的原始碼來比對、路徑不滿足自己的條件、heap 搬家但沒重新加密鑰、trace 的進入點不對。其餘測試涵蓋兩條旗標規則、heap 的 XOR 規則，以及 sample5 的兩條路徑能自動找到。

## 限制

- **環境還是需要一條 trace**：CPUID 和 K 是從錄好的 trace 學來的。學到之後，任何新輸入都可以在 Windows 上模擬；但這兩個常數本身還不能只靠 binary 算出來。
- **未定義旗標的規則只在這顆 CPU 上驗證過**（CPUID 簽章 `0x806ec`）。trace 裡沒有出現的其他未定義旗標情況（例如位移超過 1 位時的 OF、`BSF`／`BSR`），模擬器沒有特別處理。探索新路徑時如果碰到這些情況，結果就不保證跟真實 CPU 一樣。
- **範圍是純函式**：兩個整數參數、一個回傳值，沒有副作用，函式內也不呼叫函式庫。
- **證明的對象是模擬模型**：SMT 證明的是「模擬器在這些規則下產生的運算式」等於 C 原始碼。它和真實 CPU 的關聯，來自上面那 145,070 條指令的逐條比對，而不是形式證明。
- `generated/*.ll` 是 Triton 直接提升出來、沒有最佳化的 LLVM IR，沒有另外編譯或驗證，只當作參考輸出。
