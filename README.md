# Scale2VPN

Scale2VPN is a lightweight, self-hosted, dual-stack IKEv2 VPN for Debian 13. It uses strongSwan, per-device X.509 certificates, a small HTTPS console, and no containers or database.

## Install

Copy or clone the project to a fresh Debian 13 server with public IPv4 and IPv6 routes, then run:

```sh
cd scale2vpn
sudo ./install.sh
```

The installer asks for a public DNS name, IPv4 address, or IPv6 address. A DNS name with both A and AAAA records is recommended. It creates a Root CA, an Intermediate CA (MID), and a server certificate, configures IPv4 and IPv6 forwarding/NAT, and starts the IKEv2 service. Allow UDP ports `500` and `4500` through the server's cloud firewall or router.

## Web console

The HTTPS console listens only on `127.0.0.1:8443`. Use SSH port forwarding from your workstation:

```sh
ssh -L 8443:127.0.0.1:8443 user@your-vpn-server
```

Then copy the public Root CA certificate to your workstation and trust it in your OS/browser:

```sh
ssh user@your-vpn-server 'sudo cat /etc/scale2vpn/ca/root-cert.pem' > scale2vpn-root-ca.pem
```

Open `https://127.0.0.1:8443`. Sign in as `admin` with the one-time password printed by the installer. To reset it:

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
- **Traffic:** use full-tunnel IPv4 and IPv6 (`0.0.0.0/0` and `::/0`)

## Networking and operations

- Both `0.0.0.0/0` and `::/0` are routed through the VPN. IPv6 uses a randomly generated ULA pool with NAT66 to the server's IPv6 egress.
- Server service: `sudo systemctl status strongswan-starter`
- Web console: `sudo systemctl status scale2vpn-console`
- Forwarding/NAT rules: `sudo systemctl status scale2vpn-firewall`
- Console is loopback-only by default; do not expose port `8443` directly to the Internet.
- CA keys and server private keys are in `/etc/scale2vpn/ca/` and `/etc/ipsec.d/private/`; protect these files and back them up securely.

The installer is for a fresh deployment and does not remove a pre-existing VPN configuration.
