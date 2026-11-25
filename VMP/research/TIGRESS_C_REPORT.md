# Tigress VM-0 C 函式重建與編譯驗證報告

報告時間：2026-11-25T20:33:56.476693+08:00。

本輪從既有 VM-0 還原 IR 重建 C，成功 5 / 5 個樣本。
輸出是可編譯的整數運算與 if/else 資料流函式，並非原始 C 結構的完整恢復。

| 樣本 | C 行數 | if/else 數 | 新一輪三方比對組數 | 結果 |
|---|---:|---:|---:|---|
| tigress-0-challenge-0 | 55 | 0 | 336 | 通過 |
| tigress-0-challenge-1 | 103 | 1 | 337 | 通過 |
| tigress-0-challenge-2 | 312 | 7 | 343 | 通過 |
| tigress-0-challenge-3 | 54 | 0 | 336 | 通過 |
| tigress-0-challenge-4 | 120 | 1 | 337 | 通過 |

## 方法與驗證

輸入為上一輪實際從 ELF 符號執行產生的 optimized.ll。逐個 LLVM 整數運算轉成 uint64_t C，select 轉成 if/else；支援明確列出的位元運算、比較、非零常數除法及 funnel shift，未知指令即拒絕。

使用 Zig 0.13.0 所附 C 編譯器，以 C11、O2、Wall、Wextra、Werror 編譯成目的檔，載入後執行。另重新以 Unicorn 模擬原始 ELF，並執行前輪 LLVM 函式，每組輸入比較這三個結果。新增的固定種子隨機輸入不沿用舊觀測值作答案。

C 編譯輸出為 x86-64 Linux ELF 可重定位目的檔，不需 Linux 作業系統。LLVM RuntimeDyld 載入其機器碼，在 Windows 以明確的 Win64 至 SysV 呼叫介面轉接後實際執行；這不是對 Linux ELF 程式的作業系統原生執行。

整數加減乘採 uint64_t 回繞；funnel shift 的零位移另處理以避免 C 位移 64 位元的未定義行為。一般位移超過寬度時有明確回傳值；這是 C 的總函式化處理，不是宣稱保留 LLVM poison 行為。有效來源輸入仍須靠比對檢查。[LLVM 語義](https://llvm.org/docs/LangRef.html#llvm-fshl-intrinsic)

## 成果範圍

每個 recovered.c 可獨立閱讀，包含 uint64_t recovered(uint64_t input)，亦附 BUILD_CLI 條件下的命令列包裝。本輪實際驗證的是函式目的檔，未編譯該命令列包裝，也未使用 gcc。

原本展開的 IR 不保留足夠資訊以證明原始程式是否有迴圈。因此未自行發明迴圈或原始變數名稱；產生的 C 仍有暫存值與資料流特徵。if/else 對應 LLVM select，不能據此聲稱已恢復原始程式的分支布局。

官方要求可讀 C 並保留高階結構；目前增加的是 C 重建與實際編譯驗證，仍不能宣稱正式完成官方 source recovery。Unicorn 與 Triton 共用載入及外部函式假設；有限測試亦不是對整個 64 位元定義域的獨立證明。[官方規則](https://tigress.cs.arizona.edu/challenges.html)

## 產物與重現

來源實驗：`generated/tigress/20261124T220043144138Z`。

本輪產物：`generated/tigress-c/20261125T123248782832Z`。每個樣本含 recovered.c、實際編譯的 recovered.obj、建置日誌與逐筆比對。
一鍵入口為 start_tigress_c.ps1；預設使用最近一次五個樣本均成功的 Tigress 執行結果。

## 轉換器回歸測試

四項專用測試：通過。funnel shift 與 signed comparison 案例分別以 O0 和 O2 編譯 C，與 LLVM 執行結果比較；另驗證未知呼叫及非常數除數會被拒絕。完整記錄見 tests.txt。
