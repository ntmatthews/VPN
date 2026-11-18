import io
import importlib.util
import json
import stat
import tempfile
import unittest
import zipfile
from http.client import HTTPMessage
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scale2vpn-console.py"
SPEC = importlib.util.spec_from_file_location("scale2vpn_console", MODULE_PATH)
console = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(console)


class ConsoleValidationTests(unittest.TestCase):
    def test_csrf_requires_matching_cookie_and_form_tokens(self):
        token = "secure-token"
        self.assertTrue(console.valid_csrf_token(token, token))
        self.assertFalse(console.valid_csrf_token(token, "attacker-token"))
        self.assertFalse(console.valid_csrf_token("", token))
        self.assertFalse(console.valid_csrf_token(token, ""))

    def test_console_csrf_cookie_is_secure_and_reused(self):
        handler = object.__new__(console.ConsoleHandler)
        handler.headers = HTTPMessage()

        token, cookie_header = handler.get_csrf_cookie()
        self.assertRegex(token, r"^[A-Za-z0-9_-]{40,50}$")
        self.assertIn("Secure", cookie_header[1])
        self.assertIn("HttpOnly", cookie_header[1])
        self.assertIn("SameSite=Strict", cookie_header[1])

        handler.headers["Cookie"] = f"__Host-scale2vpn_csrf={token}"
        reused_token, set_cookie = handler.get_csrf_cookie()
        self.assertEqual(reused_token, token)
        self.assertIsNone(set_cookie)

    def test_device_connection_is_bound_to_its_local_identity(self):
        config = console.render_devices_config(
            {
                "a" * 24: {
                    "local_id": "s2v-0123456789ab",
                    "display_name": "Phone",
                    "created": "2026-11-15 12:00:00 UTC",
                }
            }
        ).decode()

        self.assertIn("conn scale2vpn-device-" + "a" * 24, config)
        self.assertIn("rightid=@s2v-0123456789ab", config)
        self.assertIn("also=scale2vpn-ikev2-device-template", config)
        self.assertIn("auto=add", config)

    def test_invalid_device_id_is_rejected(self):
        with self.assertRaises(RuntimeError):
            console.render_devices_config(
                {"not-a-safe-id": {"local_id": "s2v-0123456789ab"}}
            )

    def test_device_status_uses_established_connection_state(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            devices_file = Path(temporary_dir) / "devices.json"
            connected_id = "a" * 24
            disconnected_id = "b" * 24
            devices_file.write_text(json.dumps({
                connected_id: {
                    "display_name": "Phone",
                    "local_id": "s2v-0123456789ab",
                    "created": "2026-11-15 12:00:00 UTC",
                },
                disconnected_id: {
                    "display_name": "Tablet",
                    "local_id": "s2v-abcdef012345",
                    "created": "2026-11-15 12:01:00 UTC",
                },
            }), encoding="utf-8")
            statusall = (
                f"scale2vpn-device-{connected_id}: #1, ESTABLISHED, IKEv2\n"
                f"scale2vpn-device-{disconnected_id}: %any...%any IKEv2\n"
            )
            with mock.patch.object(console, "DEVICES_FILE", devices_file), \
                    mock.patch.object(console, "ipsec_service_active", return_value=True), \
                    mock.patch.object(console, "run_tool", return_value=statusall.encode()):
                rows = console.device_status_rows()

        self.assertEqual([row[2] for row in rows], ["connected", "disconnected"])

    def test_dashboard_shows_branding_and_live_device_state(self):
        handler = object.__new__(console.ConsoleHandler)
        response = {}
        handler.send_html = lambda status, title, body, headers=None: response.update(
            status=status, title=title, body=body, headers=headers
        )
        handler.get_csrf_cookie = lambda: ("csrf-token", None)
        devices = [
            (
                "a" * 24,
                {
                    "display_name": "Phone",
                    "local_id": "s2v-0123456789ab",
                    "created": "2026-11-15 12:00:00 UTC",
                },
                "connected",
            )
        ]
        with mock.patch.object(console, "load_server", return_value={
            "server_address": "vpn.example.test",
            "console_domain": "admin.example.test",
            "remote_id": "@vpn.example.test",
            "routes": ["0.0.0.0/0"],
            "families": ["ipv4"],
        }), mock.patch.object(console, "ipsec_service_active", return_value=True), \
                mock.patch.object(console, "device_status_rows", return_value=devices):
            console.ConsoleHandler.dashboard(handler)

        rendered = console.page(response["title"], response["body"])
        self.assertEqual(response["status"], 200)
        self.assertIn("Scale2VPN by Hyperforge Studios", rendered)
        self.assertIn("Nathan Thomas Matthews, doing business as Hyperforge Studios", rendered)
        self.assertIn("Connected now</div><div class=\"stat-value\">1", rendered)
        self.assertIn("https://admin.example.test:8443", rendered)
        self.assertIn('name="action" value="stop"', rendered)
        self.assertIn("Phone", rendered)
        self.assertIn("connected", rendered)

    def test_dashboard_vpn_control_uses_systemd_and_reports_result(self):
        handler = object.__new__(console.ConsoleHandler)
        handler.path = "/vpn"
        notices = []
        commands = []
        handler.require_auth = lambda: True
        handler.read_form = lambda: {"csrf_token": "token", "action": "stop"}
        handler.require_csrf = lambda token: token == "token"
        handler.dashboard = lambda notice="": notices.append(notice)
        with mock.patch.object(
            console, "run_tool", side_effect=lambda args, **kwargs: commands.append(args) or b""
        ):
            handler.do_POST()

        self.assertEqual(commands, [["systemctl", "stop", "strongswan-starter.service"]])
        self.assertEqual(notices, ["VPN service stopped."])

    def test_console_lets_encrypt_requires_a_public_dns_name(self):
        self.assertEqual(console.validate_dns_name(" VPN.Example.Test. "), "vpn.example.test")
        self.assertTrue(console.valid_contact_email("admin@example.test"))
        with self.assertRaises(ValueError):
            console.validate_dns_name("203.0.113.4")
        with self.assertRaises(ValueError):
            console.validate_dns_name("localhost")
        self.assertFalse(console.valid_contact_email("not-an-email"))

    def test_console_tls_paths_preserve_legacy_certificates_and_use_lets_encrypt(self):
        self.assertEqual(console.console_tls_paths({}), (console.SERVER_CERT, console.SERVER_KEY))
        with mock.patch.object(console, "LETSENCRYPT_DIR", Path("/etc/letsencrypt/live")):
            certificate, private_key = console.console_tls_paths(
                {"console_domain": "admin.example.test"}
            )
        self.assertEqual(
            certificate,
            Path("/etc/letsencrypt/live")
            / console.letsencrypt_certificate_name("admin.example.test")
            / "fullchain.pem",
        )
        self.assertEqual(
            private_key,
            Path("/etc/letsencrypt/live")
            / console.letsencrypt_certificate_name("admin.example.test")
            / "privkey.pem",
        )

    def test_tls_setup_issues_public_cert_and_installs_renewal_hook(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            server_file = root / "server.json"
            server_file.write_text(json.dumps({
                "server_address": "vpn.example.test",
                "remote_id": "@vpn.example.test",
            }), encoding="utf-8")
            certificate_dir = root / "live" / console.letsencrypt_certificate_name(
                "admin.example.test"
            )
            certificate_dir.mkdir(parents=True)
            (certificate_dir / "fullchain.pem").write_text("certificate", encoding="ascii")
            (certificate_dir / "privkey.pem").write_text("private key", encoding="ascii")
            hook_path = root / "renewal-hooks" / "scale2vpn-reload-console"
            commands = []

            def record_command(args, *, input_data=None, timeout=60):
                commands.append(args)
                return b""

            with mock.patch.object(console.os, "geteuid", return_value=0), \
                    mock.patch.object(console.shutil, "which", return_value="/usr/bin/certbot"), \
                    mock.patch.object(console, "SERVER_FILE", server_file), \
                    mock.patch.object(console, "LETSENCRYPT_DIR", root / "live"), \
                    mock.patch.object(console, "TLS_RENEWAL_HOOK", hook_path), \
                    mock.patch.object(console, "run_tool", side_effect=record_command):
                domain = console.configure_console_tls(
                    "ADMIN.Example.Test", "admin@example.test"
                )
            updated_server = json.loads(server_file.read_text(encoding="utf-8"))
            self.assertEqual(domain, "admin.example.test")
            self.assertEqual(updated_server["console_domain"], "admin.example.test")
            self.assertIn(
                ["certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
                 "--email", "admin@example.test", "--cert-name",
                 console.letsencrypt_certificate_name("admin.example.test"),
                 "--domain", "admin.example.test"],
                commands,
            )
            self.assertIn(["systemctl", "enable", "--now", "certbot.timer"], commands)
            self.assertIn(["systemctl", "restart", "scale2vpn-console.service"], commands)
            hook = hook_path.read_text(encoding="utf-8")
            self.assertIn("RENEWED_LINEAGE", hook)
            self.assertTrue(stat.S_IMODE(hook_path.stat().st_mode) & stat.S_IXUSR)

    def test_display_name_limits_and_trims_whitespace(self):
        self.assertEqual(console.validate_display_name("  Tablet  "), "Tablet")
        with self.assertRaises(ValueError):
            console.validate_display_name(" " * 3)
        with self.assertRaises(ValueError):
            console.validate_display_name("x" * 65)
        with self.assertRaises(ValueError):
            console.validate_display_name("phone\n<bad>")

    def test_device_issue_and_revoke_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            ca_dir = root / "ca"
            devices_dir = root / "devices"
            runtime_dir = root / "runtime"
            ca_dir.mkdir()
            devices_dir.mkdir()
            runtime_dir.mkdir()
            for name in ("intermediate-cert.pem", "intermediate-key.pem", "root-cert.pem"):
                (ca_dir / name).write_bytes(b"test certificate")
            server_file = root / "server.json"
            server_file.write_text(json.dumps({
                "server_address": "vpn.example.test",
                "remote_id": "vpn.example.test",
                "routes": ["0.0.0.0/0"],
                "families": ["ipv4"],
            }), encoding="utf-8")
            devices_file = root / "devices.json"
            devices_file.write_text("{}\n", encoding="utf-8")
            connections_file = root / "scale2vpn_devices.conf"
            connections_file.write_text("# generated\n", encoding="utf-8")

            def fake_run_tool(args, *, input_data=None, timeout=60):
                if args[0] == "pki":
                    if "--gen" in args:
                        return b"private-key"
                    if "--pub" in args:
                        return b"public-key"
                    if "--issue" in args:
                        return b"leaf-certificate"
                if args[0] == "openssl":
                    Path(args[args.index("-out") + 1]).write_bytes(b"encrypted-pkcs12")
                    return b""
                if args[0] == "ipsec":
                    return b""
                raise AssertionError(f"Unexpected tool command: {args}")

            with mock.patch.multiple(
                console,
                SERVER_FILE=server_file,
                CA_DIR=ca_dir,
                DEVICES_DIR=devices_dir,
                DEVICES_FILE=devices_file,
                DEVICES_CONFIG=connections_file,
                RUNTIME_DIR=runtime_dir,
            ), mock.patch.object(console, "run_tool", side_effect=fake_run_tool):
                device_id, device, token = console.issue_device("Tablet")
                self.assertEqual(device["display_name"], "Tablet")
                self.assertIn(f"rightid=@{device['local_id']}", connections_file.read_text())
                self.assertTrue((devices_dir / f"{device_id}.pem").exists())
                self.assertEqual(list(devices_dir.iterdir()), [devices_dir / f"{device_id}.pem"])

                bundle_data = console.PENDING_DOWNLOADS[token]["bundle"]
                with zipfile.ZipFile(io.BytesIO(bundle_data)) as bundle:
                    self.assertEqual(
                        set(bundle.namelist()),
                        {
                            "profile.txt",
                            "device.p12",
                            "device-cert.pem",
                            "intermediate-ca.pem",
                            "root-ca.pem",
                        },
                    )
                    profile = bundle.read("profile.txt").decode()
                    self.assertIn("Display Name: Tablet", profile)
                    self.assertIn("Server Address: vpn.example.test", profile)
                    self.assertIn("Remote ID: vpn.example.test", profile)
                    self.assertIn(f"Local ID: {device['local_id']}", profile)
                    self.assertIn("CA certificate (root): root-ca.pem", profile)
                    self.assertIn("MID certificate (intermediate): intermediate-ca.pem", profile)
                    self.assertIn("Device certificate (leaf): device-cert.pem", profile)
                    self.assertIn("Tunnel routes: 0.0.0.0/0", profile)

                console.revoke_device(device_id)
                self.assertEqual(json.loads(devices_file.read_text()), {})
                self.assertNotIn(f"rightid=@{device['local_id']}", connections_file.read_text())
                self.assertFalse((devices_dir / f"{device_id}.pem").exists())
                console.PENDING_DOWNLOADS.pop(token, None)


if __name__ == "__main__":
    unittest.main()
