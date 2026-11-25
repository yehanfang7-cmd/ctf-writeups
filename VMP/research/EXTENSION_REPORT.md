# VMProtect 相關研究比較與 MBA 案例擴充報告

本輪把公開 VMP 案例由四組擴充為五組，新增混合布林算術（Mixed Boolean Arithmetic，MBA）案例 sample3。重播 25,085 條指令後，取得輸入到低 8 位元輸出的表達式，通過 SMT 等價檢查及全部 65,536 組位元組輸入的本機執行比對。成果是可驗證的語義還原；目前最佳化結果仍有 47 條 LLVM 指令，尚未自動化簡成最短公式。

## 相關研究比較

以下區分作者對方法的說明與本專案實測。文獻比較不構成工具效能排名；本機未執行 NoVmp 或重跑 Tigress 的完整評測。

| 研究或工具 | 方法與輸入 | 輸出或主要目標 | 本課題的使用方式 |
|---|---|---|---|
| Salwan、Bardin、Potet，DIMVA 2018 | 符號路徑探索、污點資訊與再編譯 | 去除虛擬機細節並恢復程式行為 | 採用其對正確性與路徑完整性的區分，作為驗證設計依據 |
| Salwan VMProtect 公開研究 | 分析受保護純函式的執行 trace | 符號表達式及 LLVM IR | 重用固定版本的公開樣本，另外建立本地驗證流程 |
| NoVmp | 靜態分析已解包的 VMProtect x64 程式，使用 VTIL | 最佳化 VTIL，另有實驗性 x64 再編譯 | 作為靜態路線對照，尚無本地成功率或耗時資料 |
| 本專案 | 固定公開 trace、輸入輸出契約與機器語義模型 | 還原 IR、目的檔、實際函式呼叫及驗證證據 | 五組案例的白箱基準，並保留旗標消融與錯誤反例 |

DIMVA 2018 論文第 3.6 節區分特定輸入的正確性與對所有輸入的完整性；路徑未覆蓋或記憶體具體化不當會限制結論。本課題因此分別記錄路徑條件、模型等價與原生執行結果。[原始論文](https://triton-library.github.io/files/DIMVA2018-deobfuscation-salwan-bardin-potet.pdf)

Salwan 的 VMP 實驗指出可執行路徑數和輸入相依記憶體存取是限制；本課題不能把少量 trace 的成功推廣成任意程式的完整還原。[原作者方法與限制](https://github.com/JonathanSalwan/VMProtect-devirtualization#conclusion-and-limitations)

NoVmp README 的支援聲明是 x64 VMP 3.0 至 3.5，輸入需已解包，且再編譯功能列為實驗性。這是作者文件的範圍，不代表本輪已驗證該工具，也不代表 VMP 3.5 是目前最新版本。[NoVmp 原始倉庫](https://github.com/can1357/NoVmp)

Tigress 專案可提供另一種虛擬化器的案例與方法對照，但它的保護架構與 VMP 不同。後續若使用 Tigress，應獨立列為跨虛擬化器實驗，不能混入 VMP 成功案例數。[Tigress 研究實作](https://github.com/JonathanSalwan/Tigress_protection)

## 新增案例與研究契約

sample3 取自固定 commit `d2b26d66db59e341f179c7e326246d28c4d25491`。原始函式為 `char secret(char x, char y)`，內含多層乘法、加法、遮罩與位元運算。[案例原始碼](https://github.com/JonathanSalwan/VMProtect-devirtualization/blob/d2b26d66db59e341f179c7e326246d28c4d25491/vmp_binaries/samples-source/sample3.c)

本輪驗證的輸出契約為：

```text
result_bits = ((x_bits XOR 92) + y_bits) mod 256
```

驗證的是 8 位元位元模式；若外部介面將它解讀成有號 char，128 至 255 的模式需再轉為負數。例如輸入 `(0, 36)` 的輸出模式是 128，有號解讀為 -128。不能直接把 EAX 的全部 32 位元當成原始 char 回傳值的契約。

原始 MBA 含可能超出有號 int 範圍的中間運算。本輪參考模型明確採 32 位元回繞，再截取低 8 位元；不主張原始 C 在所有編譯器與溢位設定下均有相同語義。

## 實驗流程

1. 從固定來源下載原始 C、trace 與上游參考 IR，逐檔核對 SHA-256。
2. 沿用本地多路徑重播器，但此次只分析一條 trace；若發現輸入相依記憶體位址即停止單路徑實驗。
3. 把輸入 EDI、ESI 符號化為兩個 32 位元變數，從 EAX 的 AST 取低 8 位元作為結果。
4. SMT 查詢還原結果是否可能不同於上述契約。只有 UNSAT 才算通過；原生路徑限制亦由重播器檢查。
5. 將實際還原 AST 輸出為 LLVM IR，經 O3 最佳化、產生目的檔及組合語言，再編譯為可呼叫函式。
6. 依 LLVM 實際形參名稱綁定輸入，窮舉全部位元組輸入，與簡式及逐步 MBA 回繞模型分別比對。

參考公式只用於驗證，沒有拿來替換還原 AST 或生成受測的 LLVM 函式。下載的上游 IR 保留作參考材料，本輪未把它作為本地還原函式的產生來源。

## 實測結果

| 指標 | 結果 |
|---|---:|
| 重播指令數 | 25,085 |
| trace 記錄的輸入 | x = 1，y = 2 |
| 輸入相依記憶體位址候選數 | 0 |
| 低 8 位元 SMT 等價檢查 | UNSAT |
| 位元組輸入窮舉 | 65,536 組全通過 |
| 高輸入位元補充檢查 | 75 組全通過 |
| 最佳化前 LLVM 指令數，含 ret | 144 |
| 最佳化後 LLVM 指令數，含 ret | 47 |

sample3 在初次獨立試跑中輸出的形參順序為 `[SymVar_1, SymVar_0]`，完整流程重跑時則為 `[SymVar_0, SymVar_1]`，兩次均通過完整輸入域比對。前者記錄保留在 `generated/extension-probe/mba/results.json`；後者見本輪執行目錄的 `mba/results.json`。先前新增的依名稱映射可處理這兩種順序：實際倒序時傳入 y、x，正序時傳入 x、y。不能把型別皆為 i32 視為順序正確的證據。

65,536 組測試覆蓋的是兩個 8 位元輸入的整個定義域，不是原始 EXE 的全部可能環境。75 組補充測試讓輸入高位帶入不同模式，檢查原生呼叫的低位元契約；SMT 查詢則針對符號表達式的 32 位元輸入模型。

## 研究貢獻與尚未解決的問題

本輪新增的是現有研究工程的案例與驗證覆蓋，不是首次破解這個公開案例。可交付的增量是 8 位元輸出契約、完整有限輸入域的原生比對，以及與先前參數順序修正相接的實際案例。

語義還原與公式簡化應分開評估：SMT 及執行比對已支持功能等價，47 條最佳化指令則顯示仍有簡化空間。不能把已知參考公式寫進輸出，就聲稱工具自動恢復了最短公式；也不能將動態 trace 長度與靜態 IR 長度相除，當成效能加速倍數。

下一項值得實作的研究是「位元寬度正規化與有反例回饋的 MBA 簡化」：先保留原始還原 AST，讓簡化器提出候選公式，再由 SMT 證明候選等價；同時用未參與開發的案例檢查泛化能力。這是本輪結果導出的研究建議，尚未完成該演算法。

獨立錄製新 VMP trace、三條以上路徑、自動處理迴圈及輸入相依記憶體仍未納入本輪成果。

## 重現與證據位置

一鍵入口 `VMP/research/start.ps1` 現已加入 sample3，並保留原四組基準、原生比對、18 項回歸測試及旗標可靠性實驗。完整本輪結果與實際產物目錄見 [執行記錄](RESULTS.md)；早一輪的旗標與上游比較分析見 [可靠性報告](REPORT.md)。

每次執行目錄的 `mba/` 保存 `results.json`、`recovered.ll`、`optimized.ll`、`recovered.obj` 和 `recovered.s`；`downloads.tsv` 保存來源與雜湊，`environment.json` 保存環境。本輪 SHA-256 如下：

| 材料 | SHA-256 |
|---|---|
| sample3.c | `d66a8f75fed8968abef1dc44e62eb0b4962ab3107c5829b732599a1c59c29d47` |
| sample3.vmp.trace | `8dbd08069f095f64966dfe960e350a872e8a0eef6cd0177ecd6db60a1346d846` |
| sample3.O3.ll | `14670bbd7830937ff774caec1c20543516a550a8de71951b313ea8ee23e2080d` |
