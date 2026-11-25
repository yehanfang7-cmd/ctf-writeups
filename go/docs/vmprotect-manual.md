# vmprotect-manual.md — VMProtect 人工加殼指引(規格書 §7)

> 這一步需要 **VMProtect 商業授權**,且必須人工操作。CC 已把前置做好(把最敏感決策隔離成可被標記的原生函式),以下是你(本機)要做的事。**不要假裝已完成。**

---

## 0. 為什麼 Go + VMProtect 要這樣做

VMProtect 的 `VMProtectBegin/VMProtectEnd` 標記必須夾住**同一個原生函式內**的機器碼。純 Go 函式無法可靠地被這對巨集包住(Go 的呼叫慣例、堆疊、GC 安全點與 cgo thunk 會讓標記錯位)。而且 garble 會把 Go 符號全部改名,導致加殼時**在 GUI 裡按函式名選取也選不到**。

因此本專案採「garble 不動 C」的策略:把**最敏感的單一決策**下放成原生 cgo 函式 `vmp.CriticalCombine`(`internal/vmp/vmp_sdk.go`),標記直接寫在 C 裡:

```c
static uint64_t native_combine(uint64_t a, uint64_t b, uint64_t c) {
    VMProtectBegin("CriticalCombine");
    ... // 授權三片段折算
    VMProtectEnd();
    return x;
}
```

garble 不會改寫 C,`VMProtectBegin` 的標記位元組原封不動留在二進位裡,VMProtect 載入後能**自動偵測這對標記**並精準虛擬化其間的碼。

---

## 1. 要標記的函式

| 函式 / 標記名 | 位置 | 建議保護等級 | 理由 |
|---------------|------|--------------|------|
| `CriticalCombine`(已有 SDK 標記) | `internal/vmp/vmp_sdk.go` 的 `native_combine` | **Virtualization** | 單點最敏感:授權最終決策的折算 |
| `core.ComputeSignal` 的值錢部分 | `internal/core/core.go` | **Virtualization** | 核心演算法;**首選其實是搬後端(層5)** |
| `license.parseToken` | `internal/license/license.go` | **Mutation** | token 驗證;次要,用變異提高閱讀成本 |
| `guard` 完整性/反調試關鍵判斷 | `internal/guard/*` | **Mutation** | 不要全虛擬化(含 cgo thunk,會慢) |

> 若 `core.ComputeSignal` 要被 VMProtect 標記,建議也比照 `CriticalCombine`,把演算法核心下放成一個 cgo C 函式並加 `VMProtectBegin("ComputeSignal")`,否則 garble 改名後難以在 GUI 定位。

## 2. ⚠️ 絕對不要虛擬化的東西

- **Go runtime / GC / scheduler / channel / map / 反射** 相關程式碼。
- 大範圍、熱路徑、迴圈密集的函式。
- 整個 package 或整支 exe。

> 虛擬化會讓被保護碼慢**數十倍**。Go 的 runtime 一旦被虛擬化,GC 與排程會爆慢甚至死鎖。**只保護上面表列的關鍵小函式。**

## 3. 建置前置(用 SDK 標記版)

```powershell
# 1) 準備 VMProtect SDK,讓 cgo 找得到標頭與 lib
$env:CGO_CFLAGS  = "-IC:\VMProtect\SDK\C"
$env:CGO_LDFLAGS = "C:\VMProtect\SDK\C\VMProtectSDK64.lib"

# 2) 先跑層3 code-gen,再用 -tags vmprotect 編(讓 vmp_sdk.go 生效)
go run .\tools\securegen
garble -literals -tiny build -tags vmprotect -ldflags "-s -w" -trimpath -o bin\sentinel_garbled.exe .\cmd\sentinel
```

> 沒有 SDK 時,預設 build 走 `vmp_stub.go` 的純 Go 等價實作,程式照常運作、只是沒有 VM 保護。兩版 `CriticalCombine` 結果 bit 級一致。

## 4. ⚠️ 人工加殼步驟(VMProtect GUI / CLI)

1. 安裝並授權 VMProtect。
2. 載入 `bin\sentinel_garbled.exe`。
3. VMProtect 會自動列出偵測到的 `VMProtectBegin` 標記(如 `CriticalCombine`)。逐一設為上表的保護等級。
4. 開啟設定:
   - **反調試(Anti-Debug)**:開(user-mode + kernel-mode)。
   - **反虛擬機(Anti-VM)**:視分發對象決定(會誤傷雲端/VDI 使用者)。
   - **記憶體保護(Memory Protection)** / **Import Protection**:開。
   - **Pack the Output**:可開,但會增加防毒誤報(見 §9)。
5. 匯出加殼後 exe:`bin\sentinel_vmp.exe`。

## 5. 加殼後:回填完整性基準(層 4)

VMProtect 會改寫 `.text`,所以完整性基準**必須在加殼後**才計算回填:

```powershell
powershell -File scripts\backfill-integrity.ps1 -Path bin\sentinel_vmp.exe
# 或透過 orchestrator:
powershell -File scripts\build.ps1 -VMProtect bin\sentinel_vmp.exe
```

> runtime 讀的是**磁碟檔**的 `.text`,不是記憶體,所以 VMProtect 執行期自解密不影響比對;改動磁碟上的 exe 位元組才會觸發。

## 6. 回歸測試

```powershell
$tok = go run .\tools\mocklicense mint
.\bin\sentinel_vmp.exe --token $tok      # 應為 full precision 數值
.\bin\sentinel_vmp.exe                    # 無 token → 降級數值,無錯誤訊息
```

確認功能正常、未被加殼弄壞,再進到 §9 簽章。

## 7. 順序提醒

```
garble 版 → VMProtect 加殼 → 回填完整性基準 → 程式碼簽章
```

簽章要在**最後**;簽章會在檔尾加憑證表,但 runtime 由檔尾往前搜 magic,仍找得到完整性 trailer。
