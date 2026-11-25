# hardening-report.md — Go 防逆向分層狀態報告

> 專案:`sentinel`(示範用「授權驗證 + 核心演算法」Go 應用)
> 目標平台:`GOOS=windows GOARCH=amd64`、`CGO_ENABLED=1`
> 工具鏈(本機已驗證):Go 1.27.4、garble v0.18.0、MinGW-w64 gcc 16.2(cgo)
> 產出:`go build ./cmd/sentinel` → `sentinel.exe`

## 狀態總覽

| 層 | 內容 | 狀態 | 自動化? |
|----|------|------|---------|
| 1 | 編譯瘦身 `-s -w -trimpath` | ✅ 完成 | ✅ CC |
| 2 | garble `-literals -tiny` 混淆 | ✅ 完成 | ✅ CC |
| 3 | 自訂字串加密(AES-GCM + code-gen) | ✅ 完成 | ✅ CC |
| 4 | 反調試 / 反篡改 / 擴散延遲靜默 | ✅ 完成 | ✅ CC |
| 5 | 核心邏輯後端化(協定 + 薄殼) | ✅ 骨架完成 | ✅ CC(需真實 server) |
| 6 | VMProtect 虛擬化 | ⚠️ 前置完成,加殼待人工 | ⚠️ 前置 CC / 加殼人工 |
| 7(§9) | 程式碼簽章 + 防毒誤報 | ⚠️ 掃描腳本完成,簽章待人工 | ⚠️ 掃描 CC / 簽章人工 |

全部 7 項驗收(§10)目前狀態見本檔末尾。

---

## 層 1 — 編譯瘦身 ✅

- 實作:`-ldflags "-s -w" -trimpath`(整合進 `scripts/build.ps1` 與 garble 指令)。
- 驗證:garble 版 exe 掃不到使用者名稱 `twkk5`、不含 `OneDrive\Desktop\code` 原始碼路徑、無 `sentinel/internal/...` 套件路徑。
  - 對照組:**未混淆** 的 `go build` 版仍含 `twkk5`、`ComputeSignal`、`parseToken` → 證明瘦身+garble 有效。

## 層 2 — garble ✅

- 指令:`garble -literals -tiny build -ldflags "-s -w" -trimpath -o bin\sentinel_garbled.exe ./cmd/sentinel`
- 驗證:`ComputeSignal`、`CriticalCombine`、`parseToken` 等函式名在 garble 版中**掃不到**。
- ⚠️ 已知弱點(規格書 §3.2):FLARE 的 **GoStringUngarbler** 能自動還原 garble `-literals` 的字串。
  → 因此本專案**不依賴** garble 保護關鍵字串,改用層 3。

## 層 3 — 自訂字串加密 ✅

- 設計:關鍵字串明文只存在於 `build/secrets.src.json`(**不編譯進程式**)。
  `tools/securegen` 於 build 前把每條字串用 **AES-256-GCM** 加密,產生 `internal/appsecrets/secrets_gen.go`(只含密文)。
- 金鑰分片(規格書要求「金鑰不要單一常數、片段分散」):
  - `fragA`、`fragC` + salt 在 `internal/secure/keymix`
  - `fragB` **每次 build 隨機重生**,寫在產生的 `appsecrets` 裡 → 兩份 build 不共用金鑰
  - 執行期以 `keymix.Derive()` 用 SHA-256 混合三片段成 AES 金鑰
- 用完即清:`secure.With()` 解密後把明文交給 callback,回來即 `wipe()` 覆寫(`//go:noinline` 防最佳化消除)。敏感比對走 `Secret.Equal`/`Reveal`,明文不以 string 外洩。
- 驗證:`api.sentinel-licensing`、`feature.algo.full_precision`、`s3nt1nel::grant`、`d3v1ce-fp` 在 **plain 版與 garble 版都掃不到**(明文根本沒進二進位)→ GoStringUngarbler 類工具無從施力。
- 限界:此層只提高靜態分析成本。真正長期金鑰應由 server 下發(層 5)。

## 層 4 — 反調試 / 反篡改 / 擴散延遲靜默 ✅

透過 cgo(`internal/guard`,`//go:build windows && cgo`;另有非 Windows stub):

1. **反 debugger**(原生 C,動態解析避免 IAT 露餡):
   - `IsDebuggerPresent`、`CheckRemoteDebuggerPresent`
   - `NtQueryInformationProcess`:`ProcessDebugPort(7)`、`ProcessDebugFlags(0x1f)`、`ProcessDebugObjectHandle(0x1e)`
   - 時間差偵測:緊湊迴圈計時,被單步會異常拉長(門檻 50ms,保守避免誤判)
2. **反篡改(完整性自檢)**:
   - 執行期用 `debug/pe` 讀自身磁碟檔 `.text` 區段算 SHA-256,與**加殼後回填**的基準比對。
   - 基準由 `scripts/backfill-integrity.ps1` 在 build/加殼之後,把 `magic(8)+hash(32)` 附加到檔尾(runtime 由檔尾往前搜 magic → 簽章/overlay 加在後面也不怕)。
   - magic 以 XOR 混淆存放,避免「自己的常數」被誤判成 trailer。
   - **實測**:翻動 garble 版 `.text` 一個 byte → 完整性失敗 → 核心輸出靜默退化(`0.2790…`→`0.2500`),**不報錯、不退出崩潰**。
3. **關鍵設計原則(規格書 §5.4,全部落實)**:
   - 授權**非單點 `if licensed`**:拆成 `fragSig / fragFeat / fragEnv` 三片段,在**不同位置**各自設定,最後經 `vmp.CriticalCombine` 折算成一個等式比對。
   - **延遲觸發**:驗證失敗不立刻崩;`Observe()` 從不相干的核心運算點倒數,耗盡才靜默 `os.Exit(0)`(偽裝正常結束,非崩潰)。
   - **靜默假邏輯**:失敗時 `ComputeSignal` 走「看似合理但錯誤」的降級路徑,錯誤訊息一律 opaque(`errors.New("x")`),不給 AI 語意線索。

## 層 5 — 核心邏輯後端化 ✅(骨架)

- 詳見 `docs/backend-architecture.md`。
- 已實作可編譯的協定骨架 `internal/license/online.go`:
  - **線上驗證**:POST `{token, nonce, fingerprint, ts}`;伺服器須回**原樣 nonce**(防重放)+ 簽章。
  - **憑證綁定**:`VerifyPeerCertificate` 對 `LICENSE_PUBKEY_PIN` 做 pinning。
  - **裝置指紋**:`device.Fingerprint()` 對機器屬性做 HMAC,原始識別不外洩。
  - **離線容忍**:成功後寫帶簽章、綁指紋、有寬限期(預設 72h)的 grant 快取;斷網時於寬限內可用。快取被手改 features/expiry 會因 HMAC 不符而失效。
- 本機測試用 `tools/mocklicense serve` 當 server double(與 client 共用 `LICENSE_SALT`)。
- ⚠️ 待正式化:把 `core.ComputeSignal` 的真正值錢部分**移到 server**,本地只留呼叫殼;HMAC stand-in 換成伺服器非對稱簽章 + 真實 TLS pinning。

## 層 6 — VMProtect 虛擬化 ⚠️(前置完成,加殼待人工)

- **CC 前置(完成)**:把最敏感的單一決策隔離成原生 cgo 函式 `vmp.CriticalCombine`,並以 `VMProtectBegin("CriticalCombine")/VMProtectEnd()` 標記(`internal/vmp/vmp_sdk.go`,`-tags vmprotect`)。預設 build 走純 Go 等價實作(`vmp_stub.go`),無 SDK 也能編。
  - 為什麼用原生函式而非在 Go 外包 SDK 巨集:VMProtect 標記必須夾在**同一個原生函式內**的機器碼;純 Go 函式無法可靠地被標記。把關鍵邏輯下放 C、garble 又不動 C → 標記能存活且精準。
- **人工步驟**:見 `docs/vmprotect-manual.md`(要虛擬化/變異哪些函式、Go runtime 不可大範圍虛擬化的警告、加殼後再回填完整性基準)。

## 層 7 / §9 — 程式碼簽章 + 防毒誤報 ⚠️

- **CC 完成**:`scripts/scan-virustotal.ps1` —— 用 VirusTotal API 掃最終 exe、整理誤報報告(需 `VT_API_KEY`)。
- **人工**:用程式碼簽章憑證(EV 最佳)對最終 exe 簽章,否則 SmartScreen 會擋;分發前在乾淨 Windows 環境完整回歸。

---

## 建置順序(規格書 §8,已由 `scripts/build.ps1` 實作)

```
原始碼
 └ (層3) securegen 重生加密字串(每次 build 換金鑰)
   └ (層4) 反調試/完整性程式碼已就位(cgo)
     └ (層1+2) garble -literals -tiny build -ldflags "-s -w" -trimpath → sentinel_garbled.exe
       └ (層6) ⚠️ VMProtect 加殼(人工)                                 → sentinel_vmp.exe
         └ (層4) 完整性基準 hash 回填 backfill-integrity.ps1
           └ (§9) ⚠️ 程式碼簽章(人工)                                  → sentinel_signed.exe
```

## §10 驗收清單 — 目前狀態

- [x] `strings` 掃不到關鍵函式名、路徑、敏感字串(garble 版實測通過)
- [x] GoStringUngarbler 類工具無法還原關鍵字串(關鍵字串走層 3 自訂加密,明文不進二進位)
- [x] 篡改 exe 位元組後完整性檢查觸發(實測:`.text` 翻一 byte → 靜默降級)
- [x] 授權判斷非單點、無明文錯誤訊息(三片段擴散 + opaque error + 延遲 `exit 0`)
- [x] 核心邏輯已虛擬化**入口就緒**(`vmp.CriticalCombine` 標記)/ 後端化協定骨架完成
- [~] 用 debugger 附加時走假邏輯 — 程式碼已就位(`guard` cgo 反調試折入 `fragEnv`);**待在真機用 x64dbg 實附加回歸**
- [~] 核心邏輯確認不在本地 — **待把 `ComputeSignal` 值錢部分實際搬 server**(目前為離線 demo 保留在本地)
- [~] 加殼後功能完整回歸 — **待實機跑過 VMProtect**
- [~] 最終 exe 已簽章、誤報已評估 — **待人工簽章;掃描腳本已備**
- [x] 產出 `hardening-report.md` 記錄每層狀態(本檔)

圖例:`[x]` 完成並驗證 /`[~]` 程式碼/工具就緒,待人工或真實環境驗證。

> 可機器驗證的 `[x]` 項由 `scripts/verify.ps1` 自動回歸(build → 回填完整性 → 三情境斷言 → 洩漏掃描),
> 有任何一項 FAIL 即 `exit 1`,可直接接 CI。最近一次本機執行:**ALL CHECKS PASSED**。
