# Scale2VPN by Hyperforge Studios

Scale2VPN is a lightweight, self-hosted VPN for Debian 13. Its Scale2VPN-owned management plane provisions devices, manages access, and reports live connection state; strongSwan provides the standards-based IKEv2 tunnel transport. It uses per-device X.509 certificates and a small Python HTTPS console, with no containers or database. IPv4-only, IPv6-only, and dual-stack VPS networks are supported.

The network's internal name is `s2vpn`. Legal business name: Nathan Thomas Matthews, doing business as Hyperforge Studios in North Carolina.

## Install

Copy or clone the project to a fresh Debian 13 VPS with at least one public IP route and a public DNS name, then run:

```sh
cd scale2vpn
sudo ./install.sh
```

The installer asks for the public VPN DNS name, a Let's Encrypt contact email, and the SSH port to preserve. Before running it, point the DNS A/AAAA records to the VPS (remove any stale or unreachable AAAA record), allow inbound TCP port `80` from the internet, and ensure no other service occupies port `80` during validation. The DNS name is used as the VPN server identity and console hostname. The installer detects available public address families and configures only those; dual stack is optional. It creates a private Root CA, an Intermediate CA (MID), and the IKEv2 server certificate, enables forwarding/NAT for available client address families, and starts IKEv2.

The installer obtains a publicly trusted HTTPS certificate from Let's Encrypt for the web console and enables automatic renewal. The IKEv2 device trust chain remains separate and is signed by the Scale2VPN private Root/MID CAs. The installer installs and enables UFW, allowing the selected SSH port, HTTP validation TCP port `80`, IKEv2 UDP ports `500` and `4500`, and rate-limited HTTPS console TCP port `8443`. It adds UFW forwarding/NAT rules for the VPN address pools. Also allow these ports in the VPS provider's external firewall/security group.

## Web console

Open `https://<public-dns-name>:8443`. Browsers trust the console's Let's Encrypt certificate automatically; no private CA import is needed for the website. Sign in as `admin` with the one-time password printed by the installer. To reset it:

```sh
sudo scale2vpn reset-console-password
```

## Add a device

In the console, enter a **Display Name** and create a device profile. Each device gets a unique certificate identity. The console displays and packages:

- **Display Name**
- **Server Address**
- **Remote ID** (the server's IKE identity)
- **Local ID** (the device's IKE identity)
- **Certificate authentication** with a Root CA, Intermediate CA (MID), and device/leaf certificate

Download the ZIP immediately. It contains an encrypted PKCS#12 identity and the Root, Intermediate, and device certificates. The console displays the PKCS#12 import password once; it is not recoverable later. Private device keys are generated temporarily and are not retained on the server. Create a replacement device profile if a download is lost.

The server trusts the Root and Intermediate CAs. Device certificates are individually restricted by Local ID; revoking a device removes its allowed IKEv2 connection and attempts to disconnect its current session. Install/trust the private Root CA on client devices and import the supplied identity bundle when configuring IKEv2 certificate authentication. This private VPN trust chain is separate from the public Let's Encrypt certificate used by the browser console.

Use the profile values when creating the client VPN:

- **Display Name:** the name assigned in the console
- **Server Address / Remote ID:** the two values shown in the device profile
- **Local ID:** the device-specific identity shown in the profile
- **Authentication:** certificate; import/select `device.p12` with its one-time password
- **Trust:** install `root-ca.pem`; the intermediate and device certificates are included in the bundle
- **Traffic:** use the full-tunnel routes shown by the console for the server's available address families

## Networking and operations

- Available IPv4 and/or IPv6 full-tunnel routes are configured automatically. IPv6 uses a randomly generated ULA pool with NAT66 when IPv6 egress is available.
- The dashboard shows VPN service state, provisioned devices, established sessions, device connection state, address families, and tunnel routes.
- The dashboard can start or stop the IKEv2 service; the management console stays available either way.
- The console certificate is renewed by `certbot.timer`; a deploy hook restarts the console after renewal. Keep TCP port `80` reachable for HTTP validation.
- `sudo scale2vpn on` / `sudo scale2vpn off` starts or stops IKEv2; the console stays available.
- `sudo scale2vpn status` shows IKEv2, console, and device connection status.
- `sudo scale2vpn device status` lists provisioned devices and whether they are connected.
- `sudo scale2vpn create "Display Name"` creates a device profile. The encrypted ZIP and one-time import password are saved/shown for root under `/root/scale2vpn-devices/`.
- `sudo scale2vpn delete <device-id>` revokes a device after a typed confirmation; `device status` lists device IDs.
- `sudo scale2vpn reset` restarts IKEv2. `sudo scale2vpn reset console` changes the console admin password.
- `sudo scale2vpn sync` updates Scale2VPN program files without changing VPN settings, certificates, or devices. `sudo scale2vpn auto sync` enables daily updates; `sudo scale2vpn auto sync off` disables them.
- `sudo scale2vpn uninstall` prompts for confirmation, removes Scale2VPN configuration/device data and its UFW rules, and keeps UFW enabled and system packages installed.
- Server service: `sudo systemctl status strongswan-starter`
- Web console: `sudo systemctl status scale2vpn-console`
- Firewall rules: `sudo ufw status verbose`
- The console is public on TCP `8443`; use a strong generated password and keep the system updated.
- CA keys and server private keys are in `/etc/scale2vpn/ca/` and `/etc/ipsec.d/private/`; protect these files and back them up securely.

The installer is for a fresh deployment and does not remove a pre-existing VPN configuration.

## Updating

To apply the current program files from a checkout to an already installed server, run from the project directory:

```sh
sudo ./scale2vpn update --source .
```

This deploys the checkout's console, command, and service unit and restarts the console. It does not change VPN settings, certificates, or issued devices. After updating, reload the console page before submitting forms; the console now uses a secure CSRF token instead of rejecting browser requests based on mismatched Origin/Host formatting. Once this update is published on `main`, future updates can be downloaded directly with:

```sh
sudo scale2vpn update
```

The updater requires network access to GitHub and `git`. The installer includes `git` for new deployments. Check the service if an update fails to start:

```sh
sudo systemctl status scale2vpn-console
sudo journalctl -u scale2vpn-console --since today
```

### Enable Let's Encrypt on an existing installation

After updating the program files, configure a public DNS hostname that resolves to the VPS and is reachable on inbound TCP port `80`:

```sh
sudo scale2vpn tls setup admin.example.com admin@example.com
```

The console can use a separate hostname from the IKEv2 server address. The command obtains the certificate, enables automatic renewal, opens the UFW HTTP-validation rule, and restarts the console. Existing VPN server addresses, identities, certificates, and devices are not changed. IP addresses and `localhost` cannot receive these public DNS certificates.

## Brand

- Product: **Scale2VPN**
- Public name: **Scale2VPN by Hyperforge Studios**
- Legal business name: **Nathan Thomas Matthews, doing business as Hyperforge Studios**, North Carolina
- Internal network identifier: `s2vpn`
