# VMProtect 3.x：從 12,462 條指令還原 XOR 函式

## 本次成果

對 Jonathan Salwan 公開的 `sample2.vmp.trace` 做本地符號重播，得到：

```text
recovered expression: (bvxor x y)
SMT: recovered != (x XOR y) is UNSAT, for 32-bit x/y
edge/random evaluations: 1088 passed (raw and synthesized ASTs)
```

這是商用 VMProtect 保護樣本的真實研究軌跡。此次還原輸出是函式的表達式與 LLVM IR，使用作者既有 trace；没有在本機執行受保護 ELF 或錄製新 trace。

## 來源與環境

- [原始研究、範例與限制](https://github.com/JonathanSalwan/VMProtect-devirtualization/tree/d2b26d66db59e341f179c7e326246d28c4d25491)。方法與資料歸 Jonathan Salwan；本單元自行撰寫重播與驗證程式。
- 固定 commit：`d2b26d66db59e341f179c7e326246d28c4d25491`。
- Trace SHA-256：`735c076fdaf56cbdd6b80e0a66d88c76479f258faaf8bdaff1bec7662a63f443`。
- 實測：Windows、Python 3.11.0、`triton-library==1.0.0rc4`。
- Triton 是[二進位分析函式庫](https://github.com/JonathanSalwan/Triton)，不是 GPU 編譯器。

從倉庫根目錄執行：

```powershell
python VMP/fetch_samples.py vmp
python -m venv VMP/.venv
VMP/.venv/Scripts/python -m pip install -r VMP/02_vmp_trace/requirements.txt
VMP/.venv/Scripts/python VMP/02_vmp_trace/replay.py
```

可比對作者的原始腳本：

```powershell
VMP/.venv/Scripts/python VMP/02_vmp_trace/inputs/attack_vmp.py --trace1 VMP/02_vmp_trace/inputs/sample2.vmp.trace --symsize 4
```

下載器只下載、不執行第三方腳本。上面的基準命令已在本次環境執行，同樣得到 XOR 與 LLVM IR。所有第三方輸入保留在 Git 忽略的 `inputs/` 中。

## 重播如何還原

本單元處理的 trace 有三種紀錄：暫存器快照 `r`、記憶體讀取 `mr`、機器指令 `i`。地址與數值是十六進位；指令／存取長度欄位是十進位。

1. 建立 x86-64 Triton context，載入具體快照。
2. 在第一條指令前把 `EDI`、`ESI` 標成 32-bit 符號 `x`、`y`。雖然在 Windows 重播，來源 trace 使用 Linux x64 SysV ABI，不能改成 Windows 的 RCX/RDX。
3. 逐指令執行。與輸入無關的 VM bookkeeping 可具體求值；輸入相依的運算留下 AST。
4. 取最終 EAX 的 AST，獲得此軌跡的輸入／輸出關係。
5. 經 Triton synthesis 化簡，得到 `bvxor`，再提升成 LLVM IR。

`generated/recovered.ll` 的實測內容：

```llvm
define i32 @__triton(i32 %SymVar_1, i32 %SymVar_0) {
entry:
  %0 = xor i32 %SymVar_0, %SymVar_1
  ret i32 %0
}
```

這份 IR 沒有 VMP dispatcher 或虛擬堆疊。此次未將 IR 編譯或回填到原 binary，參數名稱及排序也不代表恢復了原始原始碼符號。

## 重播差異的處理

本次有 20 次具體暫存器同步、1,221 次具體記憶體同步，後者包含 5 次 AF 修正。`AND/OR/XOR/TEST` 後的 AF 旗標未定義，而作者的暫存器快照不包含完整 RFLAGS；重播與錄製時的該 bit 可能不同。

程式追蹤邏輯運算後 `PUSHFQ` 寫入的位置，只有在仍有效的該 8-byte 區域、且差異恰為 AF 的 `0x10` 時，才依錄製值修正該 bit；其餘 AST 位元保留。其他符號暫存器或記憶體差異直接中止。這避免靜默捨棄一般輸入相依狀態。報告會列出修正次數。

> 2026-11-21 修正：原本先指定修正後的 AST、再呼叫 `setConcreteMemoryValue()`。在 `triton-library 1.0.0rc4` 中，後者會把記憶體具體化，所以「其餘 AST 位元保留」實際上沒有生效。現已改為先同步具體值、再指定 AST。sample2 沒有虛擬分支，修正前後輸出相同；這個 bug 在第 03 單元的 sample4（有號比較）造成錯誤的分支條件，細節見 [第 03 單元題解](../03_multipath/writeup.md#3-修正旗標時順序錯了會悄悄丟掉-sfsample4-的根本原因)。

這個處理屬於特定 trace 的重播模型，不代表所有樣本都能只靠這些快照精確重建 CPU 行為。

## 驗證範圍

`verify()` 對**尚未 synthesis 的原始輸出 AST** 與 `x XOR y` 提交不等式，SMT 返回 UNSAT。隨後對 synthesis 的結果再次驗證，避免只測化簡結果而漏掉前面流程。

另以 8 個邊界值的笛卡兒積（64 組）及固定種子的 1,024 組隨機值，檢查兩種 AST 的求值結果。驗證器的反例測試會確認錯誤的加法表達式被拒絕，且存在輸入相依路徑條件時不會宣稱單軌跡足夠。

2026-10-04 實測：

```text
instructions replayed: 12462
recorded result (x=1, y=2): 3
concrete snapshot synchronizations: registers=20, memory=1221
undefined AF snapshot corrections: 5
recovered expression: (bvxor x y)
edge/random evaluations: 1088 passed (raw and synthesized ASTs)
```

SMT 證明的是**重播模型產生的表達式**在 32-bit 輸入上等價於 XOR。具體化的環境、記憶體地址以及 trace 外的路徑仍是模型假設，因此不能把這項證明擴張成整個受保護程式的全面正確性證明。這個樣本沒有留下符號化路徑條件；一般多分支函式需多條 trace、路徑約束與合併策略。

本工具刻意以 SHA-256 限定 sample2，避免將固定的 ABI、返回值與 XOR 驗證條件誤用在別的程式。未來擴充時應先建立其他樣本的輸入／輸出模型，再增加路徑探索與 native 驗證。
