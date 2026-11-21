# VMProtect 3.x：從兩條 trace 自動還原虛擬分支

## 本次成果

第 02 單元只能處理單一路徑的純函式。本單元處理**有 `if/else` 的 VMProtect 保護函式**：從兩條執行 trace 自動找出虛擬分支、合併成 `ite(條件, 路徑1, 路徑2)`，再用 SMT 證明合併結果與 C 原始碼等價。

| 樣本 | 原始碼 | 虛擬分支 | 結果 |
|---|---|---|---|
| sample4 | `x >= y ? x : y`（有號數） | `0x8ba706`，第 13,952 條 | ✅ SMT 證明與原始碼等價 |
| sample5 | `x + y == 1001 ? x + 1 : y - 1` | `0x85bbbe`，第 11,870 條 | ✅ SMT 證明與原始碼等價 |
| sample6 | `x + y < 1234u ? x + 1 : y - 1` | `0x8a5bb1`，第 10,725 條 | ✅ SMT 證明與原始碼等價 |

與 Salwan 原始腳本的差別：他用經驗特徵（`popfq` 的 CF、`cmp reg,reg` 的 AF）找分支，並對每個樣本手動傳入 `--vbraddr 0x80d905 --vbrflag af`，合併後只以 `opt -O3` 的輸出目視比對。本單元**不需任何手動位址或旗標**，每一步都有可以失敗的檢查。

過程中還發現一件事：Salwan 公開的 sample4 去虛擬化結果是錯的，所有異號輸入都會算錯，見〈與原作 sample4 結果的比較〉。

## 來源與環境

- [Salwan VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization/tree/d2b26d66db59e341f179c7e326246d28c4d25491)，固定 commit `d2b26d66db59e341f179c7e326246d28c4d25491`。trace、原始碼與方法歸原作者；本單元的重播、分支偵測、合併與驗證程式為自行撰寫。
- 使用的 trace：`sample{4,5,6}.vmp.trace.{1,2}`，SHA-256 固定於 `fetch_samples.py` 與 `merge.py`。
- 實測：2026-11-21，Windows 11、Python 3.11.9、`triton-library==1.0.0rc4`。

從倉庫根目錄執行：

```powershell
python VMP/fetch_samples.py multipath
VMP/.venv/Scripts/python VMP/03_multipath/merge.py             # sample4、5、6
VMP/.venv/Scripts/python VMP/03_multipath/merge.py --diagnose  # 只重播並列出差異，不做合併與證明
VMP/.venv/Scripts/python -m unittest discover -s VMP/03_multipath -p "test_*.py"
```

> 注意：上游檔案是 LF 換行。在 Windows 用 `git clone`（`core.autocrlf=true`）取得的檔案會變成 CRLF，SHA-256 會不同。下載器直接取 raw 位元組；本單元的雜湊另以 `git cat-file blob` 交叉核對過。

## VMP 的虛擬分支長什麼樣子

VMProtect 不把原始 `jcc` 翻成原生 `jcc`。它把兩個候選的下一個 VIP（虛擬指令指標）放進虛擬堆疊的兩個相鄰槽位，再用條件**算出要讀哪個槽位**：

```text
sample4  0x8ba706  mov rax, qword ptr ss:[rbx]   ; rbx = 基底 + 8 × (條件位元)
sample5  0x85bbbe  mov rax, qword ptr ss:[rdx]
sample6  0x8a5bb1  mov rbx, qword ptr ss:[r9]
```

所以在 trace 裡，分支的特徵是：**有一條指令的記憶體位址依賴輸入**。Triton 的 `MemoryAccess.getLeaAst()` 會給出位址的 AST；只要它被符號化，就是候選分支點。sample2（無分支，第 02 單元）這樣的指令數為 0；sample4、5、6 的每條 trace 都剛好 1 個，且兩條 trace 位置相同。

該 trace 的路徑條件就是「位址 == 本次實際讀到的值」。sample5 的條件經 z3 化簡（僅供閱讀）：

```text
(not (= (bvnot (bvadd (_ bv1001 32) (bvnot (bvadd y x)))) (_ bv0 32)))
```

由於 `~(1001 + ~s) = s − 1001`，這就是 `x + y ≠ 1001`，即 trace 1（輸入 4, 5）走的 else 路徑。VMP 用 NOT/ADD 組出減法，是常見的 VM ALU 手法。

## 驗證關卡

`merge_and_verify()` 依序檢查；任一關失敗就停止，不輸出 `.ll`：

1. 每條 trace **剛好一個**分支點，且兩條的指令位址相同。零個或多個都代表需要更多 trace 或更完整的路徑模型。
2. 兩條 trace 的實際輸入各自滿足自己的路徑條件。
3. **覆蓋完整**：以 SMT 求出「另一側」的位址值，再證明位址**只可能是這兩個值**；否則是多路分派，兩條 trace 不夠。
4. trace 2 的條件 ≡ ¬(trace 1 的條件)。
5. 每條路徑在自己的條件下等於 C 原始碼；合併後的 `ite` 整體與原始碼的 SMT 不等式為 **UNSAT**。
6. 邊界值、trace 與反側輸入，加上固定種子的 1,024 組隨機值的數值比對（Python 參考實作，與 SMT oracle 分開撰寫）。

`test_merge.py` 用合成 AST 確認驗證器會拒絕：兩路徑結果對調、兩條 trace 走同一側、三路分派、分支點缺少或多餘、條件與自身輸入矛盾、兩條 trace 分支指令不同。另有測試把重播器依賴的 Triton API 行為固定下來（見坑 3），以及未定義旗標表。

2026-11-21 實測輸出（節錄）：

```text
== sample4: int secret(int x, int y) { return x >= y ? x : y; }
virtual branch: 0x8ba706 `mov rax, qword ptr ss:[rbx]` (trace 1 #13952, trace 2 #13952)
branch address values: 0x7ffcb909bf38 (trace 1), 0x7ffcb909bf30 (other side); exactly two feasible
trace 2 condition == NOT trace 1 condition: proved
each path == C source under its own condition: proved
SMT: merged != C source is UNSAT, for 32-bit x/y
edge/random evaluations: 1031 passed
LLVM IR: 261 instructions (unoptimized; optionally run `opt -S -O3`)
== sample5: ... SMT: merged != C source is UNSAT ... LLVM IR: 154 instructions
== sample6: ... SMT: merged != C source is UNSAT ... LLVM IR: 204 instructions
```

`generated/<sample>/` 存放 `recovered.ll` 與完整 `verification.txt`。IR 未經 LLVM 最佳化；本機未安裝 `opt`。

## 重播時踩到的坑

### 1. trace 混入程式輸出

`sample5.vmp.trace.2` 的開頭有 `zenity: command not found`、`This application is protected with unregistered version of VMProtect.`、`> 1001`。Pin 錄製時 stdout/stderr 與 trace 寫進同一檔案。重播器略過非 `r:`／`mr:`／`i:` 的行並列出筆數；檔案以 SHA-256 固定，不會把損壞的紀錄誤當成雜訊。

另外，trace 實際記錄的輸入與 Salwan README 的命令不一致：sample5 是 `(4, 5)` 與 `(1000, 1)`，不是 `(1, 2)` 與 `(0, 1001)`。本單元一律以 trace 第一個暫存器快照的 EDI/ESI 為準。

### 2. 第二條 trace 繼承第一條的符號狀態

同一個 Triton context 重播兩條 trace 時，trace 1 留下的符號記憶體會讓 trace 2 出現假的分支點（探測時 trace 2 一度出現三個）。每條 trace 開始前呼叫 `concretizeAllMemory()`／`concretizeAllRegister()`，只保留共用的符號變數 `x`、`y`，並重新綁定到該 trace 的輸入。

### 3. 修正旗標時，順序錯了會悄悄丟掉 SF（sample4 的根本原因）

VMP 的 handler 常以 `pushfq` 把旗標存到堆疊、再 `pop` 讀出。trace 不含 RFLAGS，而 `TEST/AND/OR/XOR` 後的 AF 未定義，所以讀回時的 AF 可能和 Triton 的模型不同。第 02 單元的做法是只修正 AF 這個位元、保留其他位元的 AST，寫法是：

```python
ctx.assignSymbolicExpressionToMemory(ctx.newSymbolicExpression(fixed), memory)  # 1. 指定修正後的 AST
ctx.setConcreteMemoryValue(memory, observed)                                     # 2. 同步具體值
```

**在 `triton-library 1.0.0rc4` 中，第 2 步會把該記憶體具體化，第 1 步的 AST 被丟掉。** 結果整個旗標字變成常數，裡面依賴輸入的 SF、ZF 全部消失。`test_merge.py` 的 `TritonApiAssumptionTests` 固定了這個行為。

sample4 正好踩中：比較 `x - y` 後的旗標字在第 13,063 條 `pushfq` 時仍依賴輸入（模型值 `0x212`），第 13,065 條 `pop` 讀回的錄製值是 `0x202`，只差 AF。修正後卻成了常數 `0x202`。之後 VM 選槽位時，只剩下由 x、y 符號位元推導出的部分，z3 化簡的槽位位元變成：

```text
b = (sign(x) == sign(y)) OR ((sign(x) == 0) == (sign(~x + y) == 1))
```

同號時恆為 1，等於少了 SF 項。驗證器在第 4 關（「trace 2 是 trace 1 的補集」）拒絕。把順序對調（先 `setConcreteMemoryValue`，再指定修正後的 AST）後，三個樣本全部通過。第 02 單元的 `replay.py` 已同步修正；sample2 是純 XOR，修正前後輸出相同。

**怎麼找到的**：用一般手法定位失敗：

1. 確認兩條 trace 在分支點確實讀了不同槽位（相對入口 RSP 為 `-0x30` 與 `-0x38`），因此是模型錯，不是分支點找錯。
2. 重播 trace 1 時**只收集**每一步符號暫存器的 AST，重播結束後一次代入 trace 2 的輸入 `(0, 0)`，與 trace 2 的錄製值比對（堆疊位址換算為相對入口 RSP），找出第一個預測錯誤：第 13,503 條 `and rdi, rax`。
3. 從那裡逆向追蹤寫入同一槽位的 store：`[rbp+8]` ← `r8 = 0x202`（具體）← VM 暫存器槽位 ← 第 13,065 條 `pop` 的結果是具體值，而上一條 `pushfq` 寫入的是符號值。

一個要避免的錯誤：在重播**途中**呼叫 `setConcreteVariableValue()` 代入其他輸入求值，會改動該變數來源暫存器的具體值；為了還原而呼叫 `setConcreteRegisterValue()`，又會讓暫存器失去 AST。這兩種做法都會干擾重播，一開始的幾次診斷因此得到錯誤的「沒有不一致」結論。

### 4. 未定義旗標的過期 AST（防禦性處理）

Triton 對架構上未定義的旗標不做更新，會留著前一條指令（常是 `cmp`）依賴輸入的 AST，但硬體已經換掉這個值。`undefined_flags()` 依 Intel SDM 的表格（`TEST/AND/OR/XOR` 的 AF、`BT*` 的 OF/SF/AF/PF、`SHL` 等在 count ≠ 1 時的 OF……），在指令執行當下把這些旗標具體化，報告中的 `stale symbolic flags dropped` 會列出次數。`PUSHFQ` 寫入值與錄製值不同時，只允許修正當時處於未定義狀態的位元，其他符號差異一律中止。

消融實驗：關閉這項處理後，sample4、5、6 仍全部通過。所以它**不是**這三個樣本成功的關鍵，而是一種保守的建模：避免把硬體已覆蓋的值當成輸入相依。它的代價是：如果某個 CPU 實際上保留了「未定義」旗標，而程式又依賴它，這項處理會丟失那個相依性；不過驗證關卡仍會發現由此造成的錯誤。

## 與原作 sample4 結果的比較

Salwan 倉庫的 `devirt/sample4.O3.ll`：

```llvm
%6 = xor i32 (and (sub x, y), (not (xor x, y))), (and (not x), y)
%8 = select (icmp slt %6, 0), y, x
```

以 10 萬組隨機輸入與原始碼比對：**同號 0 / 50,062 錯，異號 49,938 / 49,938 全錯**，例如 `secret(0, -1)` 應為 `0`，該式給出 `-1`。他的 README 只展示 sample5，sample4 沒有附驗證。

原作的 `sync_memory()` 在值不一致時一律呼叫 `setConcreteMemoryValue()`，也就是坑 3 的情形：符號記憶體被具體化。這**很可能**就是錯誤的來源，但原作使用不同的 Triton 版本（commit `05b05cf`），本單元沒有在該版本上重現，因此不下定論。

## 範圍與限制

- 只使用 Salwan 既有的 trace。樣本是 Linux ELF；本機沒有 WSL/Pin，**未錄製新 trace，也未執行受保護程式**。
- 方法限定兩路分支、無輸入相依記憶體存取（分支點以外）、無原生 `jcc`、無符號化的原生控制流程目標；遇到就中止。
- SMT 證明的對象是**重播模型產生的表達式**。坑 3 正說明了：模型本身可能出錯，而且不會報錯。這裡的等價證明之所以有意義，是因為 oracle 取自原始碼、而且合併的每個前提都另外檢查過；不能推論成整個受保護程式的正確性證明。
- 每個樣本以 SHA-256 綁定自己的原始碼 oracle，避免誤用到其他 trace。
- 下一步（需要 Linux 與 Pin）：從路徑條件解出新輸入、自動錄製新 trace，處理兩條以上路徑。
