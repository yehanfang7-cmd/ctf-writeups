# sentinel — Go 防逆向 / 防 AI 反編譯 示範專案

依 `go-hardening-spec.md` 實作的**多層疊加**硬化範例。一個帶「授權驗證 + 核心演算法」的 Windows Go 應用,逐層套上規格書所有**可自動化**的防護,並為人工層(VMProtect、簽章)備好前置與指引。

> 原則:本地軟體沒有「不可破解」。目標是把自動化逆向在靜態階段讀不出語意、在動態階段流程卡死,成本從「幾小時自動」拉到「數週人工」。最強的一層是**把值錢的邏輯搬後端**(層 5)。

## 專案是什麼

`sentinel` 計算一個「signal score」(假想的值錢演算法)。只有在**授權有效**且**執行環境未被篡改/調試**時才跑完整精度;否則**靜默**走「看似合理但錯誤」的降級路徑——不報錯、不給 AI 語意線索。

```
unlicensed:  signal=0.2500000000   # 降級(假邏輯)
licensed:    signal=0.2790152624   # full precision
tampered:    signal=0.2500000000   # 完整性失敗 → 靜默降級
```

## 快速開始

```powershell
# 需求:Go 1.27+、MinGW gcc(cgo)、garble(go install mvdan.cc/garble@latest)

# 開發用(純 go build,不混淆,快速迭代)
powershell -File scripts\build.ps1 -Dev

# 硬化 build(層 1+2+3)
powershell -File scripts\build.ps1
#   -> bin\sentinel_garbled.exe

# 層 4:加殼後回填完整性基準(無 VMProtect 時直接對 garble 版回填亦可)
powershell -File scripts\backfill-integrity.ps1 -Path bin\sentinel_garbled.exe

# 跑跑看
$tok = go run .\tools\mocklicense mint
.\bin\sentinel_garbled.exe --token $tok     # 授權 → full precision
.\bin\sentinel_garbled.exe                   # 無授權 → 靜默降級
```

## 層對應表

| 層 | 內容 | 程式碼 / 腳本 |
|----|------|---------------|
| 1 | 編譯瘦身 `-s -w -trimpath` | `scripts/build.ps1` |
| 2 | garble `-literals -tiny` | `scripts/build.ps1` |
| 3 | 自訂 AES-GCM 字串加密 + code-gen | `internal/secure/`、`internal/appsecrets/`、`tools/securegen/`、`build/secrets.src.json` |
| 4 | 反調試 / 完整性 / 擴散延遲靜默 | `internal/guard/`、`internal/license/`、`scripts/backfill-integrity.ps1` |
| 5 | 後端化(協定 + 薄殼 + 離線容忍) | `internal/license/online.go`、`internal/device/`、`tools/mocklicense/`、`docs/backend-architecture.md` |
| 6 | VMProtect 虛擬化(前置) | `internal/vmp/`、`docs/vmprotect-manual.md` |
| §9 | 簽章 + 防毒誤報掃描 | `scripts/scan-virustotal.ps1` |

逐層完成狀態與驗收清單:**`docs/hardening-report.md`**。

## 檔案地圖

```
cmd/sentinel/            demo 應用進入點
internal/secure/         層3 執行期 AES-GCM 解密 + 金鑰混合(keymix)
internal/appsecrets/     層3 產生的密文(secrets_gen.go,由 securegen 重生)
internal/license/        授權:擴散三片段、延遲靜默反應、線上/離線驗證
internal/guard/          層4 cgo 反調試 + .text 完整性自檢(+ 非 Windows stub)
internal/core/           ★值錢的核心演算法(層6 虛擬化 / 層5 後端化 首選)
internal/vmp/            層6 VMProtect 標記的原生函式(stub + SDK 兩版)
internal/device/         層5 裝置指紋(HMAC)
tools/securegen/         層3 build 前字串加密 code-gen
tools/mocklicense/       層5 本機測試用 license server + token minter
scripts/                 build / 完整性回填 / VirusTotal 掃描
docs/                    hardening-report、vmprotect-manual、backend-architecture
sensitive-strings.txt    §1 敏感字串盤點
critical-funcs.txt       §1 關鍵函式盤點
```

## 重要前提(規格書 §0、§11)

- 本地任何金鑰都等於已洩露;`build/secrets.src.json` 裡的 `LICENSE_SALT`、`DEVICE_HMAC_SECRET` 只是 demo 方便。**正式版長期金鑰必須由 server 下發。**
- 每做完一層都要**回歸測試**(`go test ./...`、跑 exe 比對授權/未授權/篡改三種輸出)。
- garble **不做控制流平坦化**;控制流靠層 6 的 VMProtect 補。
- 真實環境別把含真實密鑰的 build 上傳 VirusTotal。

## 回歸測試

```powershell
go test ./...        # 授權/未授權/篡改 token/缺特徵 四種情境(單元)

# 端對端驗收(自動跑完 §10 可機器驗證項,逐項 PASS/FAIL,有 FAIL 則 exit 1)
powershell -File scripts\verify.ps1          # 驗 garble 版
powershell -File scripts\verify.ps1 -Dev     # 驗 plain 版(字串掃描項轉為資訊性)
```

`verify.ps1` 會:build → 回填完整性 → 鑄 token → 跑未授權/授權/篡改三情境並斷言輸出分歧 →
掃描符號/路徑/敏感明文洩漏。可直接接進 CI。
