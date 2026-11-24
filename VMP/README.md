# VM 與 VMProtect 還原實驗

這個專區沿用專案的「可執行腳本 + 繁中題解」形式，練習從虛擬化程式恢復可讀、可驗證的邏輯。

## 已完成單元

| 單元 | 類型 | 本地實作與驗證 | 題解 |
|---|---|---|---|
| [01 — openECSC 2024 fsvm](01_fsvm/) | 自製 VM CTF，並非 VMProtect | 557 條 VM 指令 → 29 個字元約束 → Python 判定函式；548 組模型比對及 52 組官方 C++ VM 比對通過 | [題解](01_fsvm/writeup.md) |
| [02 — VMProtect sample2](02_vmp_trace/) | 真正 VMP 3.x 公開研究樣本 | 重播 12,462 條 x64 指令 → `x ^ y` → LLVM IR；還原表達式通過 SMT 與 1,088 組值測試 | [題解](02_vmp_trace/writeup.md) |
| [03 — VMProtect 多路徑](03_multipath/) | 同上，sample4／5／6（含 `if/else`） | 每樣本兩條 trace → 自動找出虛擬分支 → 合併成 `ite` → 與 C 原始碼 SMT 等價證明（含有號比較）；發現原作 sample4 結果對異號輸入全錯 | [題解](03_multipath/writeup.md) |
| [04 — VMProtect 直接模擬](04_emulate/) | 同上，sample1–6；不用 Pin | 在 Windows 直接模擬 ELF、學習執行環境、concolic 自動探索路徑；6 個樣本與 C 原始碼 SMT 等價，145,070 條指令與真實 CPU trace 一致 | [題解](04_emulate/writeup.md) |
| [05 — Flare-On 5 #12 suspicious_floppy](05_floppy/) | CTF 三層 VM（x86 → Subleq → RSSB） | 逐層建模並與下層 lockstep 比對、提升公式、窮舉 G 求解；求出全部解（flag 及後接 1–2 個任意字元），真實 x86 確認 | [題解](05_floppy/writeup.md) |
| [06 — Tigress challenge 0000](06_tigress/) | Tigress VM 挑戰，5 個程式、5 種 dispatcher | 不依賴 dispatcher 類型的黑箱 opcode 分類 → bytecode 反組譯 → 提升為 C；201,169 步 lockstep 一致、z3 列舉 14 條路徑、每個程式 2,000 組以上輸入與原始 `SECRET` 一致 | [題解](06_tigress/writeup.md) |

驗證日期：01、02 為 2026-10-04，03 為 2026-11-21（02 於同日修正旗標同步順序，輸出不變）。02、03 使用作者既有 trace，尚未自行執行受保護 ELF、錄製新 trace 或重建整個 EXE。

## 快速執行

以下命令從倉庫根目錄執行；下載器固定上游 commit，逐檔檢查 SHA-256。原始樣本、第三方原始碼、環境及生成產物不加入 Git。

```powershell
# Python 3.10+；單元 01 只用標準函式庫
python VMP/fetch_samples.py all
python VMP/01_fsvm/solve.py
python VMP/01_fsvm/verify.py

# 可選：用 g++ 編譯官方 VM，做獨立比對
python VMP/01_fsvm/verify.py --native

# Windows / Python 3.11 的實測環境
python -m venv VMP/.venv
VMP/.venv/Scripts/python -m pip install -r VMP/02_vmp_trace/requirements.txt
VMP/.venv/Scripts/python VMP/02_vmp_trace/replay.py
VMP/.venv/Scripts/python -m unittest discover -s VMP/02_vmp_trace -p "test_*.py"
VMP/.venv/Scripts/python VMP/03_multipath/merge.py
VMP/.venv/Scripts/python -m unittest discover -s VMP/03_multipath -p "test_*.py"
```

Linux 可將虛擬環境 Python 路徑改成 `VMP/.venv/bin/python`。`triton-library==1.0.0rc4` 是動態二進位分析函式庫；安裝時不要替換成同名 GPU 編譯器套件 `triton`。其他 OS/Python 版本須確認該固定版本有相容 wheel。

每個單元的 `generated/` 中會產生還原程式及驗證報告。下載資料缺失時腳本會報錯；重新執行 `fetch_samples.py` 即可。既存檔案若 hash 不符，下載器會停止，不覆蓋使用者資料。

## 學習順序

1. 從既有 [SUBLEQ](../FlareOn/Fo4/writeup.md#c11--covfefe)、[巢狀 OISC](../FlareOn/Fo5/writeup.md#c12--suspicious_floppy) 理解 VM 狀態與指令。
2. 在單元 01 看懂 bytecode → 解碼 → 部分求值 → 字元約束 → 判定函式。
3. 在單元 02 看懂 native trace → 符號執行 → 輸出表達式 → LLVM IR。
4. 在單元 03 看懂 VMP 如何以「依賴輸入的位址」實作虛擬分支，以及兩條 trace 如何合併、證明完整覆蓋；並看重播模型如何在不報錯的情況下出錯。
5. 後續再增加自動路徑探索（需 Linux＋Pin 錄製新 trace）、Windows crackme 與 native code 回填。這些目前屬後續方向，未標示為已完成題解。

## 延伸資料與適用邊界

| 資料 | 用途 | 邊界 |
|---|---|---|
| [Salwan VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | 單元 02、03 的樣本來源，符號執行與 LLVM 還原 | 純函式、小型控制流程研究；不可推論能還原任意 VMP 程式 |
| [NoVmp](https://github.com/can1357/NoVmp) | 靜態還原到 VTIL | README 指定 x64 VMP 3.0–3.5，需已脫殼輸入，native 重編譯屬實驗功能；未在本專案實測 |
| [aftermathlabs/vmp2](https://github.com/aftermathlabs/vmp2) | handler、bytecode 與 VMP2 工具鏈研究 | 已封存；作者指出依賴 handler 固定特徵的脆弱性；未在本專案實測 |
| [VMP-devirtualize-project](https://github.com/banda59/VMP-devirtualize-project) | 後續 Windows x86/x64 練習樣本候選 | 尚未下載執行或驗證其重建流程 |
| [fsvm 符號執行文章](https://blog.deobfuscate.io/using-symbolic-execution-for-devirtualisation) | VM 自製指令集還原觀念 | 本專案另外核對官方 C++ 原始碼、自行實作並實測；沒有直接採用文章輸出的偽 C |
| [看雪：用 P-code 做 VMP 還原](https://bbs.kanxue.com/thread-292911.htm) | 中文 IR 分析讀物 | Android/ARM 場景，需區分自製 VM 與商用 VMProtect |

## 資料來源

題目和第三方工具的權利歸各自作者。`fetch_samples.py` 直接從原倉庫取得指定版本，`inputs/` 不納入本倉庫；各單元題解記錄來源、版本與限制。新增的腳本是本專案的教學實作，並非通用脫殼或通用 VMP 還原器。
