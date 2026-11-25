# 07 — minivm：自己做一個 VM 保護器，再從 binary 把它拆掉

前面六個單元都是**拆別人的 VM**。這個單元反過來：從一份教學用的小型 VM 保護器（[`original/`](original/)，含它的 [README](original/README.md)）出發，先檢查它實際保護了什麼，修好之後，再站在攻擊者的位置，只拿出貨的 binary 把秘密演算法還原成 C。

## 結果

| 項目 | 原始版 `original/vm.c` | 修正後的出貨版 `vm.c` |
|---|---|---|
| binary 裡找得到秘密常數 | 4 個常數全部找得到，各兩份 | 0 個 |
| `VM_DISASM=1` 直接印出明文 bytecode | 會 | 不會（只在 `SELFTEST` 版） |
| `./vm abc` | 當成 0，照樣輸出 | 拒絕，exit 1 |
| 竄改或截斷的 bytecode | 界外讀寫（未定義行為） | 回傳錯誤碼 |
| 200 組輸入與獨立寫的 Python 版本一致 | — | 是（出貨版和 `SELFTEST` 版都是） |
| 只拿 binary 還原出秘密 | 不用拆 VM，反組譯 `secret_reference` 就是答案 | `attack.py` 4.6 秒還原成 C，編譯後與 binary 一致 |

秘密演算法（MurmurHash 風格的 finalizer）：

```c
h = x;
h ^= 0x5bd1e995;
h *= 0x100000001b3;
h ^= h >> 15;
h += 0x9e3779b97f4a7c15;
h  = rotl64(h, 13);
h *= 0xff51afd7ed558ccd;
h ^= h >> 33;
return h;
```

`attack.py` 只看 `vm.exe` 還原出來的：

```c
uint64_t secret(uint64_t x) {
    uint64_t t0 = (x ^ 0x5bd1e995ULL) * 0x100000001b3ULL;
    uint64_t t1 = rotl64((t0 ^ (t0 >> 15)) + 0x9e3779b97f4a7c15ULL, 13) * 0xff51afd7ed558ccdULL;
    return t1 ^ (t1 >> 33);
}
```

## 執行方式

需要 Python 3.10+ 和 gcc（Windows 用 WinLibs；`CC` 環境變數可指定編譯器）。全部只用標準函式庫，產物都寫進 Git 忽略的 `generated/`。

```powershell
python VMP/07_minivm/build.py        # 組譯、加密、編譯出貨版和 SELFTEST 版，檢查洩漏與正確性
python VMP/07_minivm/attack.py       # 只拿 generated/vm.exe，把秘密還原成 C
cd VMP/07_minivm; python -m unittest test_minivm -v   # 9 個測試，約 12 秒
```

| 檔案 | 角色 |
|---|---|
| `isa.h` | 指令集、滾動金鑰 XOR、直譯器；不含任何秘密常數 |
| `reference.h` | 秘密演算法的原生版本，只給 `gen.c` 和 `SELFTEST` 版用 |
| `gen.c` | 建置期：組譯 → 與 reference 比對 2,006 組輸入 → 加密 → 輸出 `generated/blob.h` |
| `vm.c` | 出貨程式：加密 blob + 直譯器；`-DSELFTEST` 才多出原生對照和 `VM_DISASM` |
| `build.py` | 建置並檢查：binary 裡有沒有秘密常數、輸出對不對、壞參數會不會被拒絕 |
| `attack.py` | 攻擊方：掃描 → 解密 → 提升為 C → 用 binary 本身確認 |
| `original/` | 收到的原始版本，當作對照組，不修改 |

## 一、原始版保護了什麼

原始 README 的第 6 節說「✅ 擋得住直接靜態反組譯」。實際編譯原始版（WinLibs gcc，`-O2`），用 `objdump -d` 搜尋秘密常數：

```
mov    $0x5bd1e995,%edx              ← assemble_secret() 的 emit 呼叫
movabs $0x100000001b3,%rdx
movabs $0x9e3779b97f4a7c15,%rdx
movabs $0xff51afd7ed558ccd,%rdx
...
xor    $0x5bd1e995,%r9               ← secret_reference()：原生演算法直接攤開
movabs $0x100000001b3,%rax
movabs $0x9e3779b97f4a7c15,%rax
movabs $0xff51afd7ed558ccd,%rax
```

有三個地方把答案留在 binary 裡：

1. **`secret_reference()` 每次都編進去**。它是「出貨時會拿掉」的自我驗證，但沒有任何編譯開關包住，`main` 每次都會呼叫。反組譯這個函式就是答案，連 VM 都不必看。
2. **組譯器在執行期才跑**。`main` 的註解寫「建置期：組譯 + 加密（真實情境會離線先做好）」，但程式碼實際上是當場呼叫 `assemble_secret()`。binary 裡從來沒有加密 blob，只有一串 `emit` 呼叫，常數和指令順序都是立即值。接著的加密和解密緊挨著做，對逆向者沒有任何阻擋。
3. **`VM_DISASM=1` 會印出明文 bytecode**，連反組譯器的 opcode 名稱字串都在 binary 裡。設一個環境變數就拿到全部。

另外還有幾個小問題：反組譯的位址用十進位（`%04zu`），旁邊的 operand 卻是 `0x…`，`0010` 很容易被看成 16 進位；`SHR`/`SHL` 的位移量 ≥ 64 是未定義行為；堆疊沒有邊界檢查；`strtoull` 不檢查，`./vm abc` 等於 `./vm 0`。

## 二、修正

**把建置期和出貨真的分開。** `gen.c` 負責組譯、比對、加密，輸出只有位元組的 `blob.h`；出貨的 `vm.c` 只 include `isa.h` 和 `blob.h`。`reference.h` 和 bytecode 傾印只在 `-DSELFTEST` 時編進去。出貨版再加 `-s` 去掉符號。

**怎麼確認沒洩漏。** `build.py` 直接在 binary 的位元組裡找：每個常數的完整 little-endian 形式，以及 64 位元常數各自的高、低 32 位元（編譯器可能把一個 64 位元常數拆成兩條指令載入），再加上 `VM_DISASM`、`MISMATCH!`、`INPUT` 這些除錯字串。

| binary | 大小 | 找到的東西 |
|---|---|---|
| 原始版 | 64,629 bytes | 4 個常數及其 32 位元片段、`VM_DISASM`、`MISMATCH!`、`INPUT` |
| 出貨版（`-s`） | 21,504 bytes | 無 |
| `SELFTEST` 版 | 64,368 bytes | 4 個常數及其片段、`VM_DISASM`、`MISMATCH!` |

`SELFTEST` 版和原始版是偵測器的對照組：同一個偵測器在它們身上找得到全部常數，所以出貨版的「無」是有意義的。

第一次跑時，出貨版被找到 `MISMATCH`。追下去發現是 MinGW 執行環境裡的 `X86_TUNE_MEMORY_MISMATCH_STALL`，和我們無關，改成比對 `MISMATCH!` 才精確。

**直譯器加固。** 每條指令先檢查堆疊深度、operand 是否完整、位移量是否 < 64，錯誤一律回傳錯誤碼（`VM_BAD_OP`、`VM_TRUNCATED`、`VM_UNDERFLOW`、`VM_OVERFLOW`、`VM_BAD_SHIFT`、`VM_NO_HALT`），不再讀寫界外。`gen.c` 在組譯時就拒絕 ≥ 64 的位移量。位址改用 16 進位顯示。輸入改成只接受完整的非負整數。

## 三、攻擊：只拿出貨的 binary

修好之後，binary 裡沒有明文常數了。但金鑰和解密方法還是在同一個 binary 裡，README 自己也說擋不住動態分析。這裡實際做一次，而且只用靜態掃描加上執行 binary 本身。

**威脅模型**（Kerckhoffs 原則）：攻擊者知道 minivm 怎麼運作，也就是指令集和滾動 XOR 的形式（`k = k*31 + 17`），但不知道金鑰、blob 在哪裡、bytecode 算的是什麼。

1. **掃描**：對檔案的每個位移，第一個 byte 只有 13 種金鑰能把它解成合法 opcode，就試這 13 種。每個候選一邊解密一邊檢查：opcode 都合法、位移量 < 64、堆疊不會不夠用、以 `HALT` 結束、至少 4 條指令。21,504 bytes × 13 種金鑰，只有 **1 個**候選通過：檔案位移 `0x30c0`，金鑰 `0xa5`，17 條指令。
2. **提升**：模擬堆疊，把每個被 `DUP` 的非葉節點值取名（`t0`、`t1`），其餘組成運算式。就是上面那段 C。
3. **確認**：靜態找到的東西不能直接相信。用攻擊者自己寫的直譯器跑還原出的 bytecode，和**執行 binary 本身**的輸出比對 100 組輸入；再把還原的 C 編譯起來比對一次。兩者都一致。

整個攻擊約 4.6 秒，大部分時間花在啟動 100 次 binary。

## 四、驗證

`test_minivm.py` 的 9 個測試。每個「通過」都配了一個會失敗的對照組，避免測試其實什麼都沒檢查：

| 測試 | 檢查 | 對照組 |
|---|---|---|
| 出貨版沒有明文秘密 | 偵測器在出貨版找不到東西 | 同一個偵測器在原始版和 `SELFTEST` 版找到全部 4 個常數 |
| 出貨版忽略 `VM_DISASM` | 設了環境變數，輸出仍只有一個數字 | 原始版印出 `PUSH 0x5bd1e995` |
| 出貨版算得對 | 47 組輸入（10 進位、16 進位交錯）與 Python 版本一致 | — |
| 壞參數被拒絕 | `abc`、空字串、`-1`、`12x`、`0x`、超過 64 位元，全部 exit 1 | 原始版把 `abc` 當成 0 |
| 直譯器拒絕壞 bytecode | 11 種情況各回傳對應的錯誤碼；`SHL 63`、`SUB` 的正常結果也對 | — |
| `gen.c` 拒絕寬位移 | 把 `a_shr(a, 33)` 改成 64，`gen` 拒絕並 exit 1 | — |
| 攻擊還原出秘密 | 1 個候選、金鑰 `0xa5`；還原的 C 編譯後與 binary 一致 | — |
| 攻擊不依賴金鑰 | 用金鑰 `0x3c` 重新建置，攻擊照樣找到並確認 | — |
| 攻擊信 binary，不信掃描 | 在檔尾附加一個常數差 1 的假 blob（另一把金鑰）；掃描找到 2 個，只有真的那個和 binary 一致 | 假 blob 格式完全正確，只靠掃描無法分辨 |

## 五、限制與下一步

- **攻擊假設知道指令集**。只要每次建置都隨機打亂 opcode 編號（原始 README 擴充方向第 1 項），`attack.py` 的掃描就失效了。那時要改用單元 06 的做法：不看編號，實際跑一條指令，從效果判斷語意。
- **加密本身沒有變強**。拿掉明文洩漏之後，剩下的保護就是「blob 被 XOR 過」。金鑰仍在 binary 裡，第三節就是證明。
- **常數本身就是指紋**。`0xff51afd7ed558ccd` 是 MurmurHash3 的招牌常數，只要 bytecode 被還原，就認得出來。原始 README 的擴充方向第 3 項（常數拆解）處理的就是這件事。
- **只在 Windows + WinLibs gcc 上驗證過**。程式碼是可攜的 C，但其他編譯器和最佳化等級下，「binary 裡沒有常數」需要重新跑 `build.py` 確認，例如編譯器可能把整個解密和直譯過程在編譯期算完。
- **等價是測試出來的，不是證明**。出貨版與 Python 版本、還原的 C 與 binary，都是在固定的一批輸入上比對。
