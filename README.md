# Scale2VPN

Scale2VPN is a lightweight, self-hosted IKEv2 VPN for Debian 13. It uses strongSwan, per-device X.509 certificates, a small HTTPS console, and no containers or database. It works with IPv4-only, IPv6-only, and dual-stack VPS networks.

## Install

Copy or clone the project to a fresh Debian 13 VPS with at least one public IP route, then run:

```sh
cd scale2vpn
sudo ./install.sh
```

The installer asks for the server's public DNS name, IPv4 address, or IPv6 address and the SSH port to preserve. It detects available public address families and configures only those; dual stack is optional. It creates a Root CA, an Intermediate CA (MID), and a server certificate, enables forwarding/NAT for available client address families, and starts IKEv2.

The installer installs and enables UFW, allowing the selected SSH port, IKEv2 UDP ports `500` and `4500`, and rate-limited HTTPS console TCP port `8443`. It adds UFW forwarding/NAT rules for the VPN address pools. Also allow these ports in the VPS provider's external firewall/security group.

## Web console

The HTTPS console listens on public interfaces for the available IP families at port `8443`. Its certificate is issued for the server address entered during installation. Copy the public Root CA certificate securely and trust it in your OS/browser:

```sh
ssh user@your-vpn-server 'sudo cat /etc/scale2vpn/ca/root-cert.pem' > scale2vpn-root-ca.pem
```

Open `https://<server-address>:8443` (bracket IPv6 literals, for example `https://[2001:db8::1]:8443`). Sign in as `admin` with the one-time password printed by the installer. To reset it:

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

The server trusts the Root and Intermediate CAs. Device certificates are individually restricted by Local ID; revoking a device removes its allowed IKEv2 connection and attempts to disconnect its current session. Install/trust the Root CA on client devices and import the supplied identity bundle when configuring IKEv2 certificate authentication.

Use the profile values when creating the client VPN:

- **Display Name:** the name assigned in the console
- **Server Address / Remote ID:** the two values shown in the device profile
- **Local ID:** the device-specific identity shown in the profile
- **Authentication:** certificate; import/select `device.p12` with its one-time password
- **Trust:** install `root-ca.pem`; the intermediate and device certificates are included in the bundle
- **Traffic:** use the full-tunnel routes shown by the console for the server's available address families

## Networking and operations

- Available IPv4 and/or IPv6 full-tunnel routes are configured automatically. IPv6 uses a randomly generated ULA pool with NAT66 when IPv6 egress is available.
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
