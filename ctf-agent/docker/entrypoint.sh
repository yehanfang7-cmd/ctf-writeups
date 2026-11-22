#!/usr/bin/env bash
# 以 root 設防火牆，再降權成 ctf 使用者執行指令。
# CTF_FIREWALL=0 可關掉防火牆（不建議；只在除錯網路時用）。
set -euo pipefail

if [ "$(id -u)" = "0" ]; then
  if [ "${CTF_FIREWALL:-1}" != "0" ]; then
    /usr/local/bin/init-firewall.sh
  else
    echo "[entrypoint] 警告：CTF_FIREWALL=0，容器沒有出站限制" >&2
  fi
  exec runuser -u ctf -- "$@"
fi
exec "$@"
