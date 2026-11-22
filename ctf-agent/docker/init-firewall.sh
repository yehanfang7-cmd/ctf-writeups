#!/usr/bin/env bash
# 出站白名單：只允許 DNS、Anthropic API、以及 CTF_ALLOWED_HOSTS 列出的題目主機。
# 以 root 在 entrypoint 執行（需要 docker run --cap-add=NET_ADMIN）。agent 是非 root，改不了規則。
#   CTF_ALLOWED_HOSTS="chall.example.com 10.10.0.0/24 1.2.3.4"   # 空白分隔：主機名、IP 或 CIDR
set -euo pipefail

ALLOW_DOMAINS="api.anthropic.com ${CTF_EXTRA_DOMAINS:-}"

ipset create ctf-allow hash:net -exist
ipset flush ctf-allow

add_target() {
  local target="$1" ip
  if [[ "$target" =~ ^[0-9.]+(/[0-9]+)?$ ]]; then
    ipset add ctf-allow "$target" -exist
    return
  fi
  local ips
  ips="$(dig +short A "$target" | grep -E '^[0-9.]+$' || true)"
  if [ -z "$ips" ]; then
    echo "[firewall] 無法解析 $target" >&2
    return 1
  fi
  for ip in $ips; do ipset add ctf-allow "$ip" -exist; done
  echo "[firewall] 允許 $target -> $(echo $ips | tr '\n' ' ')"
}

for target in $ALLOW_DOMAINS ${CTF_ALLOWED_HOSTS:-}; do
  add_target "$target"
done

# 只動 filter 表的 OUTPUT；不清 nat 表，否則 Docker 內建 DNS（127.0.0.11）會壞掉。
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for ns in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | grep -E '^[0-9.]+$'); do
  iptables -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT
done
iptables -A OUTPUT -m set --match-set ctf-allow dst -j ACCEPT
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited
iptables -P OUTPUT DROP

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -F OUTPUT 2>/dev/null || true
  ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
  ip6tables -P OUTPUT DROP 2>/dev/null || true
fi

# 自我檢查：白名單外要連不到、API 要連得到
if curl -s --max-time 5 https://example.com >/dev/null; then
  echo "[firewall] 失敗：仍可連到 example.com" >&2
  exit 1
fi
if ! curl -s --max-time 10 -o /dev/null https://api.anthropic.com; then
  echo "[firewall] 警告：連不到 api.anthropic.com" >&2
fi
echo "[firewall] 出站白名單已啟用"
