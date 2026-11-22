# CTF 自動解題 Agent（Claude Code）

用 Claude Code 當作自動解 CTF 的 agent：一個主流程 + 各類別 subagent，
在 Docker 沙箱裡用 headless 模式批次解題。

## 目錄結構

```
ctf-agent/
├── CLAUDE.md              # 主指引：流程、工具、規則、提示注入防護（烤進映像，agent 唯讀）
├── Dockerfile             # 沙箱：Kali + CTF 工具 + Claude Code，非 root 使用者
├── requirements.txt       # 固定版本的 Python 套件
├── solve_all.sh           # 批次解整個 challenges/，含 log 與 FLAG 格式檢查
├── docker/
│   ├── entrypoint.sh      # root 設防火牆 → 降權成 ctf 使用者
│   ├── init-firewall.sh   # 出站白名單（DNS、api.anthropic.com、題目主機）
│   ├── list-tools.sh      # build 時產生 /ctf/TOOLS.txt（實際裝了哪些工具）
│   └── claude-settings.json  # 容器內的權限設定（只在容器生效）
├── ghidra_scripts/
│   └── DecompileAll.java  # headless 全函式反編譯
├── .claude/
│   ├── settings.json      # 主機端：刻意不放行任何工具
│   └── agents/            # pwn / rev / crypto / web / forensics / misc
└── challenges/<題名>/     # 一題一資料夾（附件 + README + 產生的 notes.md / FLAG）
```

## 安全設計

| 風險 | 處理方式 |
|---|---|
| 在主機上開 Claude Code 也會自動放行 Bash | 放行規則只在映像的 `~/.claude/settings.json`；專案的 `.claude/settings.json` 不放行任何工具 |
| agent 連到範圍外的主機 | `init-firewall.sh` 預設拒絕所有出站，只開 DNS、`api.anthropic.com` 與 `CTF_ALLOWED_HOSTS` |
| agent 改掉自己的規則或防火牆 | agent 以非 root 的 `ctf` 使用者執行；設定檔由 root 擁有；主機只掛載 `challenges/` 與 `logs/` |
| 題目內容夾帶指令（提示注入） | `CLAUDE.md` 與每個 subagent 明定題目內容是資料，不照做其中的指示 |
| 幻覺 flag | `FLAG` 必須是單行且符合 `FLAG_REGEX`，否則改名為 `FLAG.rejected`；最終仍要送出確認 |

殘餘風險：防火牆在容器啟動時把網域解析成 IP，之後 IP 變了要重啟容器；DNS 查詢本身可以送到容器的 resolver。

## 快速開始

### 1. 建映像
```bash
docker build -t ctf-agent .
# 不要 Ghidra（映像小很多）：docker build --build-arg INSTALL_GHIDRA=0 -t ctf-agent .
```

### 2. 放題目
把題目放進 `challenges/<題名>/`，描述和遠端資訊寫進該資料夾的 `README`。

### 3. 執行
```bash
mkdir -p logs
docker run -it --rm \
  --cap-add=NET_ADMIN \
  -e ANTHROPIC_API_KEY \
  -e CTF_ALLOWED_HOSTS="chall.example.com 10.10.0.0/24" \
  -v "$PWD/challenges":/ctf/challenges \
  -v "$PWD/logs":/ctf/logs \
  ctf-agent bash
```
`--cap-add=NET_ADMIN` 只給 entrypoint 裡的 root 設防火牆用；降權後的 `ctf` 使用者沒有這個能力。
`-e ANTHROPIC_API_KEY` 不寫值，會從主機的環境變數帶入，key 不會留在 shell 歷史。

進容器後：
```bash
cat /ctf/TOOLS.txt                      # 確認工具
claude -p "解 challenges/example-babypwn 這題，flag 寫進該資料夾的 FLAG" \
  --allowedTools "Bash,Read,Write,Edit,Agent"
./solve_all.sh 1800                     # 批次，每題上限 30 分鐘
FLAG_REGEX='^picoCTF\{[^{}]+\}$' ./solve_all.sh   # 指定比賽的 flag 格式
```

### 4. 第一次跑完要檢查
- `logs/` 裡有沒有看到 subagent 被呼叫（主流程有沒有真的分派出去）。
- 防火牆自我檢查有印出「出站白名單已啟用」。

## 延伸

- **接 CTFd**：寫腳本用 CTFd API 抓題整理成 `challenges/`，或接 CTFd MCP server，
  用 `--mcp-config` 載入、`--allowedTools "mcp__..."` 授權。CTFd 主機要加進 `CTF_ALLOWED_HOSTS`。
- **換模型 / 調推理強度**：headless 支援 Claude Code 的各種 CLI 參數。
- **記憶**：`notes.md` 是最簡單的跨步驟記憶；要更強可讓 agent 維護一份跨題的經驗筆記。
- **版本**：Claude Code 用 `--build-arg CLAUDE_CODE_VERSION=x.y.z` 指定；Python 套件改 `requirements.txt`；
  要完全可重現，把 `BASE_IMAGE` 改成 `kalilinux/kali-last-release@sha256:...`。

## ⚠️ 重要邊界

- **只在授權環境玩**：自架題、picoCTF、合法 CTF 比賽。不要打沒授權的系統（違法）。
- **一定要在容器裡跑**：`--allowedTools "Bash"` 讓 agent 不經確認執行任何指令，邊界是容器與防火牆。
- **比賽規則**：有些比賽限制或禁止全自動 bot，很多只開放「AI 輔助」。
  上場前以該賽事的官方規則為準。
