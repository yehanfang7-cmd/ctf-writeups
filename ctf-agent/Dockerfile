# CTF agent 沙箱。設定檔烤進映像（root 擁有、agent 唯讀），只有 challenges/ 與 logs/ 從主機掛載。
# kali-last-release 是每季快照，比 kali-rolling 穩定；要完全可重現，請改成 @sha256 digest。
ARG BASE_IMAGE=kalilinux/kali-last-release
FROM ${BASE_IMAGE}

ARG CLAUDE_CODE_VERSION=2.1.330
ARG INSTALL_GHIDRA=1
ENV DEBIAN_FRONTEND=noninteractive

# 系統工具（CLAUDE.md 的工具清單以 build 時產生的 /ctf/TOOLS.txt 為準）
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    gdb radare2 binutils ltrace strace checksec patchelf \
    binwalk foremost exiftool steghide sleuthkit tshark john fcrackzip \
    sqlmap nmap netcat-openbsd curl wget git \
    file xxd unzip p7zip-full build-essential ruby ruby-dev \
    nodejs npm \
    iptables ipset dnsutils ca-certificates \
    && if [ "$INSTALL_GHIDRA" = "1" ]; then apt-get install -y --no-install-recommends ghidra; fi \
    && rm -rf /var/lib/apt/lists/*

RUN gem install --no-document one_gadget zsteg

# Python 套件裝在 venv，固定版本（見 requirements.txt）
COPY requirements.txt /opt/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/requirements.txt
ENV PATH="/opt/venv/bin:${PATH}"

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

# agent 以非 root 的 ctf 使用者執行，改不到防火牆與設定檔
RUN useradd -m -s /bin/bash ctf
COPY --chown=ctf:ctf docker/claude-settings.json /home/ctf/.claude/settings.json
COPY docker/init-firewall.sh docker/entrypoint.sh docker/list-tools.sh /usr/local/bin/
COPY CLAUDE.md solve_all.sh /ctf/
COPY .claude/agents/ /ctf/.claude/agents/
COPY ghidra_scripts/ /ctf/ghidra_scripts/
RUN chmod 755 /usr/local/bin/init-firewall.sh /usr/local/bin/entrypoint.sh /usr/local/bin/list-tools.sh /ctf/solve_all.sh \
    && /usr/local/bin/list-tools.sh > /ctf/TOOLS.txt \
    && mkdir -p /ctf/challenges /ctf/logs && chown ctf:ctf /ctf/challenges /ctf/logs

# 只留必要連線，關掉非必要遙測
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
WORKDIR /ctf
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]

# 用法見 README.md「快速開始」。
