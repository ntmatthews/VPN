#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="/etc/scale2vpn"
readonly IPSEC_DIR="/etc/ipsec.d"

fail() {
    printf 'Scale2VPN: %s\n' "$*" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run this installer as root (for example: sudo ./install.sh)"
[[ -r /etc/os-release ]] || fail "cannot identify the operating system"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] \
    || fail "Scale2VPN requires Debian 13; found ${PRETTY_NAME:-an unsupported system}"
if ! command -v python3 >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3
fi
[[ -f "${SCRIPT_DIR}/scale2vpn" && -f "${SCRIPT_DIR}/scale2vpn-firewall" \
    && -f "${SCRIPT_DIR}/scale2vpn-firewall.service" && -f "${SCRIPT_DIR}/scale2vpn-console.py" \
    && -f "${SCRIPT_DIR}/scale2vpn-console.service" ]] \
    || fail "Scale2VPN scripts and service units must be alongside install.sh"

while :; do
    read -r -p "Public server address (DNS name, IPv4, or IPv6): " endpoint
    if python3 -c '
import ipaddress, re, sys
value = sys.argv[1]
try:
    ipaddress.ip_address(value)
    valid = True
except ValueError:
    valid = len(value) <= 253 and not value.endswith(".") and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in value.rstrip(".").split(".")
    )
sys.exit(0 if valid else 1)
' "${endpoint}"; then
        break
    fi
    printf 'Enter a valid DNS name, IPv4 address, or IPv6 address.\n' >&2
done

server_identity="$(python3 - "${endpoint}" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    ipaddress.ip_address(value)
    print(value)
except ValueError:
    print(f"@{value}")
PY
)"
public_interface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
[[ "${public_interface}" =~ ^[A-Za-z0-9_.:-]+$ ]] \
    || fail "could not detect the outbound IPv4 interface"
public_interface_v6="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
[[ "${public_interface_v6}" =~ ^[A-Za-z0-9_.:-]+$ ]] \
    || fail "dual-stack VPN requires an outbound IPv6 route"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y strongswan-starter strongswan-pki libcharon-extra-plugins iptables openssl python3

[[ -d "${IPSEC_DIR}" ]] || fail "strongSwan did not create ${IPSEC_DIR}"
[[ ! -e "${IPSEC_DIR}/scale2vpn.conf" && ! -e "${IPSEC_DIR}/scale2vpn.secrets" \
    && ! -e "${IPSEC_DIR}/scale2vpn_devices.conf" && ! -e "${CONFIG_DIR}/server.json" ]] \
    || fail "Scale2VPN strongSwan configuration already exists; refusing to overwrite it"

ensure_include() {
    local file="$1"
    local include="$2"
    grep -Eq "^[[:space:]]*include[[:space:]]+${include//\*/\\*}([[:space:]]|$)" "${file}" \
        || printf '\ninclude %s\n' "${include}" >> "${file}"
}

ensure_include /etc/ipsec.conf '/etc/ipsec.d/*.conf'
ensure_include /etc/ipsec.secrets '/etc/ipsec.d/*.secrets'

install -d -m 700 \
    "${CONFIG_DIR}" "${CONFIG_DIR}/ca" "${CONFIG_DIR}/devices" \
    "${IPSEC_DIR}/certs" "${IPSEC_DIR}/cacerts" "${IPSEC_DIR}/private"
umask 077

ula_hex="$(openssl rand -hex 5)"
ipv6_pool="fd${ula_hex:0:2}:${ula_hex:2:4}:${ula_hex:6:4}::/64"

pki --gen --type rsa --size 4096 --outform pem > "${CONFIG_DIR}/ca/root-key.pem"
pki --self --ca --lifetime 3650 \
    --in "${CONFIG_DIR}/ca/root-key.pem" --dn "CN=Scale2VPN Root CA" --outform pem \
    > "${CONFIG_DIR}/ca/root-cert.pem"
pki --gen --type rsa --size 3072 --outform pem > "${CONFIG_DIR}/ca/intermediate-key.pem"
pki --pub --in "${CONFIG_DIR}/ca/intermediate-key.pem" \
    | pki --issue --cacert "${CONFIG_DIR}/ca/root-cert.pem" --cakey "${CONFIG_DIR}/ca/root-key.pem" \
        --dn "CN=Scale2VPN Intermediate CA" --flag ca --lifetime 3000 --outform pem \
        > "${CONFIG_DIR}/ca/intermediate-cert.pem"
pki --gen --type rsa --size 3072 --outform pem > "${IPSEC_DIR}/private/scale2vpn-server-key.pem"
pki --pub --in "${IPSEC_DIR}/private/scale2vpn-server-key.pem" \
    | pki --issue --cacert "${CONFIG_DIR}/ca/intermediate-cert.pem" \
        --cakey "${CONFIG_DIR}/ca/intermediate-key.pem" --dn "CN=${endpoint}" \
        --san "${endpoint}" --san localhost --san 127.0.0.1 \
        --flag serverAuth --lifetime 1825 --outform pem \
        > "${IPSEC_DIR}/certs/scale2vpn-server-cert.pem"
cat "${IPSEC_DIR}/certs/scale2vpn-server-cert.pem" "${CONFIG_DIR}/ca/intermediate-cert.pem" \
    > "${IPSEC_DIR}/certs/scale2vpn-console-chain.pem"
install -m 644 "${CONFIG_DIR}/ca/root-cert.pem" "${IPSEC_DIR}/cacerts/scale2vpn-root.pem"
install -m 644 "${CONFIG_DIR}/ca/intermediate-cert.pem" "${IPSEC_DIR}/cacerts/scale2vpn-intermediate.pem"
chmod 600 "${CONFIG_DIR}/ca/"*-key.pem "${IPSEC_DIR}/private/scale2vpn-server-key.pem"
chmod 644 "${IPSEC_DIR}/certs/scale2vpn-server-cert.pem" "${IPSEC_DIR}/certs/scale2vpn-console-chain.pem"

cat > "${IPSEC_DIR}/scale2vpn.conf" <<EOF
conn scale2vpn-ikev2-device-template
    keyexchange=ikev2
    auto=ignore
    type=tunnel
    left=%any
    leftauth=pubkey
    leftid=${server_identity}
    leftcert=scale2vpn-server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0,::/0
    right=%any
    rightid=%any
    rightauth=pubkey
    rightca="CN=Scale2VPN Intermediate CA"
    rightsourceip=10.77.0.0/24,${ipv6_pool}
    rightdns=1.1.1.1,2606:4700:4700::1111
    rightsendcert=never
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048!
    esp=aes256-sha256,aes128-sha256!
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=30s
EOF
printf '# Generated device connections are managed by the Scale2VPN console.\n' \
    > "${IPSEC_DIR}/scale2vpn_devices.conf"
cat > "${IPSEC_DIR}/scale2vpn.secrets" <<'EOF'
: RSA scale2vpn-server-key.pem
EOF
chmod 600 "${IPSEC_DIR}/scale2vpn.conf" "${IPSEC_DIR}/scale2vpn_devices.conf" \
    "${IPSEC_DIR}/scale2vpn.secrets"

python3 - "${CONFIG_DIR}/server.json" "${endpoint}" "${ipv6_pool}" <<'PY'
import json
import os
import sys

path, endpoint, ipv6_pool = sys.argv[1:]
with open(path, "w", encoding="utf-8") as output:
    json.dump({
        "display_name": "Scale2VPN",
        "server_address": endpoint,
        "remote_id": endpoint,
        "ipv6_pool": ipv6_pool,
    }, output, indent=2)
    output.write("\n")
os.chmod(path, 0o600)
PY
printf '{}\n' > "${CONFIG_DIR}/devices.json"
printf '%s\n' "${public_interface}" > "${CONFIG_DIR}/public-interface"
printf '%s\n' "${public_interface_v6}" > "${CONFIG_DIR}/public-interface-v6"
printf '%s\n' "${ipv6_pool}" > "${CONFIG_DIR}/ipv6-pool"
chmod 600 "${CONFIG_DIR}/devices.json" "${CONFIG_DIR}/public-interface" \
    "${CONFIG_DIR}/public-interface-v6" "${CONFIG_DIR}/ipv6-pool"

console_password="$(openssl rand -hex 24)"
printf '%s' "${console_password}" | sha256sum | awk '{print $1}' \
    > "${CONFIG_DIR}/console-password.sha256"
chmod 600 "${CONFIG_DIR}/console-password.sha256"

install -m 755 "${SCRIPT_DIR}/scale2vpn" /usr/local/bin/scale2vpn
install -m 755 "${SCRIPT_DIR}/scale2vpn-firewall" /usr/local/sbin/scale2vpn-firewall
install -d -m 755 /usr/local/lib/scale2vpn
install -m 755 "${SCRIPT_DIR}/scale2vpn-console.py" /usr/local/lib/scale2vpn/console.py
install -m 644 "${SCRIPT_DIR}/scale2vpn-firewall.service" /etc/systemd/system/scale2vpn-firewall.service
install -m 644 "${SCRIPT_DIR}/scale2vpn-console.service" /etc/systemd/system/scale2vpn-console.service
cat > /etc/sysctl.d/90-scale2vpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.${public_interface_v6}.accept_ra=2
EOF
sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable --now scale2vpn-firewall.service
systemctl enable --now strongswan-starter.service
systemctl enable --now scale2vpn-console.service

printf '\nScale2VPN dual-stack IKEv2 is running.\n'
printf 'Server address / remote ID: %s\n' "${endpoint}"
printf 'Web console: https://127.0.0.1:8443 (use SSH port forwarding)\n'
printf 'Console username: admin\nConsole password (shown once): %s\n' "${console_password}"
printf 'Allow UDP ports 500 and 4500 through your cloud firewall/router.\n'
