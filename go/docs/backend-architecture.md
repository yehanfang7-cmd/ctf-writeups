# backend-architecture.md — 第 5 層核心邏輯後端化設計

> 規格書 §6、§11:**最強的一層其實是後端化。** AI 再強也只能分析它拿得到的東西;本地沒有的程式碼,逆向本地檔案永遠拿不到。能聯網就把核心搬後端,CP 值遠高於拚命加殼。

## 1. 先問自己:哪段邏輯最值錢?能不能不放本地?

本專案的答案:

| 邏輯 | 現況 | 建議 |
|------|------|------|
| `core.ComputeSignal`(核心演算法) | 離線 demo 暫留本地 | **搬後端**:本地送輸入、後端回結果 |
| 授權核發 / 特徵解鎖 | 本地 token 驗證(demo) | **後端核發**,本地只驗簽章 |
| 定價 / 計費 | 無 | 若有,一律後端 |
| 長期金鑰 | `LICENSE_SALT` 等(demo) | **後端下發**,本地不內嵌 |

## 2. 薄殼 / 後端分界

```
┌────────────── 本地 sentinel.exe(薄殼)──────────────┐
│  輸入蒐集、UI、快取、裝置指紋                           │
│  授權:驗伺服器簽章回應(不含核發邏輯)                 │
│  核心:呼叫 server /compute,只拿結果                   │
└───────────────┬────────────────────────────────────┘
                │ HTTPS + 憑證綁定 + nonce + 指紋
┌───────────────▼────────────── 伺服器(值錢的東西都在這)┐
│  授權核發、ComputeSignal 真正實作、定價、金鑰保管        │
└─────────────────────────────────────────────────────┘
```

本地即使被完全還原,拿不到 server 上的演算法與金鑰 → 破了也沒用。

## 3. 線上授權協定(已於 `internal/license/online.go` 實作骨架)

### 請求
```json
POST {API_ENDPOINT}{LICENSE_VERIFY_PATH}
{ "token": "...", "nonce": "<16B 隨機>", "fingerprint": "<HMAC>", "ts": 1700000000 }
```

### 回應(伺服器簽章)
```json
{ "ok": true, "nonce": "<原樣回傳>", "features": ["feature.algo.full_precision"],
  "exp": 1790000000, "sig": "<簽章>" }
```

### 防護要素(皆已在骨架落實)
- **防重放**:client 產 `nonce`,伺服器必須**原樣回傳**;不符即拒。正式版再加 `ts` 時窗 + 伺服器端 nonce 去重。
- **憑證綁定(pinning)**:`VerifyPeerCertificate` 比對 `LICENSE_PUBKEY_PIN`(SPKI SHA-256),擋中間人/自簽代理。
- **裝置指紋**:`device.Fingerprint()` 對機器屬性做 HMAC,伺服器只看到不可逆 tag,可綁授權到裝置。
- **離線容忍**:成功後寫 grant 快取(綁指紋、帶 `exp` 與寬限 `until`、HMAC 防手改),預設 72h 寬限;斷網時於寬限內仍可用,兼顧體驗與安全。

## 4. demo → 正式版 的差異(務必替換)

| 項目 | demo 現況 | 正式版 |
|------|-----------|--------|
| 回應簽章 | HMAC + 共用 `LICENSE_SALT` | 伺服器**非對稱**私鑰簽章;本地只存公鑰 |
| token | 本地 HMAC 驗證 | 伺服器核發的簽章授權;本地驗公鑰 |
| 核心演算法 | 本地 `ComputeSignal` | 真正值錢部分只在 server |
| TLS pinning | mock 為 HTTP 跳過 | 真 HTTPS,pin SPKI(建議 pin 中繼 CA 以利輪替) |
| nonce 去重 | 僅 echo 比對 | 伺服器端儲存已用 nonce + 時窗 |

## 5. 本機測試

```powershell
# 1) 啟動 mock server(與 client 共用 LICENSE_SALT 以便 demo)
go run .\tools\mocklicense serve :8099
# 2) 讓 client 指向它並走線上路徑
$env:SENTINEL_LICENSE_URL = "http://127.0.0.1:8099/license/verify"
.\bin\sentinel_plain.exe --online --token (go run .\tools\mocklicense mint)
```

## 6. 結論(規格書 §11)

後端化買的是**根本性**的保護:本地沒有的東西無法被逆向。加殼只是買時間;後端化是把值錢的東西從戰場上撤走。**先後端化,再對剩下的薄殼加殼。**
