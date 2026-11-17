import io
import importlib.util
import json
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
