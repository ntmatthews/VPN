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
[[ -f "${SCRIPT_DIR}/scale2vpn" && -f "${SCRIPT_DIR}/scale2vpn-console.py" \
    && -f "${SCRIPT_DIR}/scale2vpn-console.service" ]] \
    || fail "Scale2VPN scripts and service units must be alongside install.sh"

while :; do
    read -r -p "Public VPN DNS name (required for trusted HTTPS, e.g. vpn.example.com): " endpoint
    if python3 -c '
import ipaddress, re, sys
value = sys.argv[1].lower().rstrip(".")
labels = value.split(".")
valid = len(value) <= 253 and len(labels) >= 2 and all(
    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
    for label in labels
)
try:
    ipaddress.ip_address(value)
    valid = False
except ValueError: pass
sys.exit(0 if valid else 1)
' "${endpoint}"; then
        endpoint="${endpoint,,}"
        endpoint="${endpoint%.}"
        break
    fi
    printf 'Enter a public DNS name (not an IP address) with at least two valid labels.\n' >&2
done

read -r -p "Let's Encrypt contact email: " letsencrypt_email
python3 - "${letsencrypt_email}" <<'PY'
import re
import sys

if not re.fullmatch(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+", sys.argv[1].strip()):
    raise SystemExit("Enter a valid email address for Let's Encrypt certificate notices.")
PY

server_identity="$(python3 - "${endpoint}" <<'PY'
import sys

print(f"@{sys.argv[1]}")
PY
)"
console_cert_name="$(python3 - "${endpoint}" <<'PY'
import hashlib
import sys

suffix = hashlib.sha256(sys.argv[1].encode("ascii")).hexdigest()[:16]
print(f"s2vpn-{suffix}")
PY
)"
public_interface="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
public_interface_v6="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
[[ -z "${public_interface}" || "${public_interface}" =~ ^[A-Za-z0-9_.:-]+$ ]] \
    || fail "invalid outbound IPv4 interface"
[[ -z "${public_interface_v6}" || "${public_interface_v6}" =~ ^[A-Za-z0-9_.:-]+$ ]] \
    || fail "invalid outbound IPv6 interface"
[[ -n "${public_interface}" || -n "${public_interface_v6}" ]] \
    || fail "could not detect an outbound IPv4 or IPv6 route; a public route is required"

read -r -p "SSH TCP port to keep open in UFW [22]: " ssh_port
ssh_port="${ssh_port:-22}"
[[ "${ssh_port}" =~ ^[0-9]{1,5}$ ]] && (( 10#${ssh_port} >= 1 && 10#${ssh_port} <= 65535 )) \
    || fail "SSH port must be a number from 1 to 65535"
ssh_port=$((10#${ssh_port}))

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y strongswan-starter strongswan-pki libcharon-extra-plugins ufw openssl python3 git certbot

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

ipv4_pool=""
ipv6_pool=""
vpn_subnets=()
vpn_pools=()
dns_servers=()
if [[ -n "${public_interface}" ]]; then
    ipv4_pool="10.77.0.0/24"
    vpn_subnets+=("0.0.0.0/0")
    vpn_pools+=("${ipv4_pool}")
    dns_servers+=("1.1.1.1")
fi
if [[ -n "${public_interface_v6}" ]]; then
    ula_hex="$(openssl rand -hex 5)"
    ipv6_pool="fd${ula_hex:0:2}:${ula_hex:2:4}:${ula_hex:6:4}::/64"
    vpn_subnets+=("::/0")
    vpn_pools+=("${ipv6_pool}")
    dns_servers+=("2606:4700:4700::1111")
fi
IFS=,
left_subnets="${vpn_subnets[*]}"
right_pools="${vpn_pools[*]}"
right_dns="${dns_servers[*]}"
unset IFS

pki --gen --type rsa --size 4096 --outform pem > "${CONFIG_DIR}/ca/root-key.pem"
pki --self --ca --lifetime 3650 \
    --in "${CONFIG_DIR}/ca/root-key.pem" --dn "CN=Scale2VPN Root CA" --outform pem \
    > "${CONFIG_DIR}/ca/root-cert.pem"
openssl x509 -in "${CONFIG_DIR}/ca/root-cert.pem" -noout -ext basicConstraints \
    | grep -q 'CA:TRUE' || fail "generated Root CA certificate is missing CA:TRUE"
pki --gen --type rsa --size 3072 --outform pem > "${CONFIG_DIR}/ca/intermediate-key.pem"
pki --pub --in "${CONFIG_DIR}/ca/intermediate-key.pem" \
    | pki --issue --cacert "${CONFIG_DIR}/ca/root-cert.pem" --cakey "${CONFIG_DIR}/ca/root-key.pem" \
        --dn "CN=Scale2VPN Intermediate CA" --ca --lifetime 3000 --outform pem \
        > "${CONFIG_DIR}/ca/intermediate-cert.pem"
openssl x509 -in "${CONFIG_DIR}/ca/intermediate-cert.pem" -noout -ext basicConstraints \
    | grep -q 'CA:TRUE' || fail "generated Intermediate CA certificate is missing CA:TRUE"
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
    leftsubnet=${left_subnets}
    right=%any
    rightid=%any
    rightauth=pubkey
    rightca="CN=Scale2VPN Intermediate CA"
    rightsourceip=${right_pools}
    rightdns=${right_dns}
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

python3 - "${CONFIG_DIR}/server.json" "${endpoint}" "${server_identity}" \
    "${ipv4_pool}" "${ipv6_pool}" "${left_subnets}" "${right_dns}" <<'PY'
import json
import os
import sys

path, endpoint, server_identity, ipv4_pool, ipv6_pool, routes, dns = sys.argv[1:]
families = []
if ipv4_pool:
    families.append("ipv4")
if ipv6_pool:
    families.append("ipv6")
with open(path, "w", encoding="utf-8") as output:
    json.dump({
        "display_name": "Scale2VPN",
        "server_address": endpoint,
        "console_domain": endpoint,
        "remote_id": server_identity,
        "ipv4_pool": ipv4_pool or None,
        "ipv6_pool": ipv6_pool or None,
        "routes": routes.split(","),
        "dns": dns.split(","),
        "families": families,
    }, output, indent=2)
    output.write("\n")
os.chmod(path, 0o600)
PY
printf '{}\n' > "${CONFIG_DIR}/devices.json"
printf '%s\n' "${public_interface}" > "${CONFIG_DIR}/public-interface"
printf '%s\n' "${public_interface_v6}" > "${CONFIG_DIR}/public-interface-v6"
printf '%s\n' "${ipv4_pool}" > "${CONFIG_DIR}/ipv4-pool"
printf '%s\n' "${ipv6_pool}" > "${CONFIG_DIR}/ipv6-pool"
chmod 600 "${CONFIG_DIR}/devices.json" "${CONFIG_DIR}/public-interface" \
    "${CONFIG_DIR}/public-interface-v6" "${CONFIG_DIR}/ipv4-pool" "${CONFIG_DIR}/ipv6-pool"

console_password="$(openssl rand -hex 24)"
printf '%s' "${console_password}" | sha256sum | awk '{print $1}' \
    > "${CONFIG_DIR}/console-password.sha256"
chmod 600 "${CONFIG_DIR}/console-password.sha256"

install -m 755 "${SCRIPT_DIR}/scale2vpn" /usr/local/bin/scale2vpn
install -d -m 755 /usr/local/lib/scale2vpn
install -m 755 "${SCRIPT_DIR}/scale2vpn-console.py" /usr/local/lib/scale2vpn/console.py
install -m 644 "${SCRIPT_DIR}/scale2vpn-console.service" /etc/systemd/system/scale2vpn-console.service

cat > /etc/sysctl.d/90-scale2vpn.conf <<EOF
$(if [[ -n "${public_interface}" ]]; then printf '%s\n' 'net.ipv4.ip_forward=1'; fi)
$(if [[ -n "${public_interface_v6}" ]]; then
    printf '%s\n' 'net.ipv6.conf.all.forwarding=1' 'net.ipv6.conf.default.forwarding=1'
    printf 'net.ipv6.conf.%s.accept_ra=2\n' "${public_interface_v6}"
fi)
EOF
sysctl --system >/dev/null

ufw_ipv6="no"
[[ -z "${public_interface_v6}" ]] || ufw_ipv6="yes"
sed -i "s/^IPV6=.*/IPV6=${ufw_ipv6}/" /etc/default/ufw

python3 - "${ipv4_pool}" "${public_interface}" "${ipv6_pool}" "${public_interface_v6}" <<'PY'
import sys
from pathlib import Path

begin = "# BEGIN SCALE2VPN NAT"
end = "# END SCALE2VPN NAT"
families = (
    (Path("/etc/ufw/before.rules"), sys.argv[1], sys.argv[2]),
    (Path("/etc/ufw/before6.rules"), sys.argv[3], sys.argv[4]),
)
for path, pool, interface in families:
    text = path.read_text(encoding="utf-8")
    start = text.find(begin)
    if start >= 0:
        finish = text.find(end, start)
        if finish < 0:
            raise SystemExit(f"Unterminated Scale2VPN NAT block in {path}")
        finish += len(end)
        text = text[:start] + text[finish:]
    if pool and interface:
        block = (
            f"{begin}\n*nat\n:POSTROUTING ACCEPT [0:0]\n"
            f"-A POSTROUTING -s {pool} -o {interface} -j MASQUERADE\n"
            f"COMMIT\n{end}\n"
        )
        text = block + text
    path.write_text(text, encoding="utf-8")
PY

ufw allow "${ssh_port}/tcp"
ufw allow 500/udp
ufw allow 4500/udp
ufw limit 8443/tcp
ufw allow 80/tcp comment "Scale2VPN ACME validation"
if [[ -n "${ipv4_pool}" ]]; then
    ufw route allow in on "${public_interface}" out on "${public_interface}" from "${ipv4_pool}" to any
fi
if [[ -n "${ipv6_pool}" ]]; then
    ufw route allow in on "${public_interface_v6}" out on "${public_interface_v6}" from "${ipv6_pool}" to any
fi
ufw --force enable

printf 'Requesting a trusted certificate for %s; DNS must resolve to this VPS and inbound TCP 80 must be reachable and unused.\n' "${endpoint}"
certbot certonly --standalone --non-interactive --agree-tos \
    --email "${letsencrypt_email}" --cert-name "${console_cert_name}" --domain "${endpoint}"
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/scale2vpn-reload-console <<'EOF'
#!/bin/sh
set -eu
cert_name="$(/usr/bin/python3 -c 'import hashlib, json; domain=json.load(open("/etc/scale2vpn/server.json"))["console_domain"]; print("s2vpn-"+hashlib.sha256(domain.encode()).hexdigest()[:16])')"
[ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/${cert_name}" ] || exit 0
exec /usr/bin/systemctl restart scale2vpn-console.service
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/scale2vpn-reload-console
systemctl enable --now certbot.timer

systemctl daemon-reload
systemctl enable --now strongswan-starter.service
systemctl enable --now scale2vpn-console.service

printf '\nScale2VPN IKEv2 and the management console are running.\n'
printf 'Server address / remote ID: %s\n' "${endpoint}"
printf 'Trusted HTTPS console: https://%s:8443\n' "${endpoint}"
printf 'Console username: admin\nConsole password (shown once): %s\n' "${console_password}"
printf 'UFW allows SSH on TCP %s, HTTP validation on TCP 80, IKEv2 on UDP 500/4500, and the rate-limited console on TCP 8443.\n' "${ssh_port}"
printf 'Also permit those ports in your VPS provider firewall/security group.\n'
