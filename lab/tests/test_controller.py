"""Regressions for the manual lab shell helpers."""

import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller import (ManualForwarder, ManualForwarderHandler, SandboxSuite,
                        manual_listen_port, parse_manual_publish)


class ManualShellTests(unittest.TestCase):
    def test_publish_accepts_loopback_forms(self):
        self.assertEqual(parse_manual_publish("8080"), ("127.0.0.1", 8080))
        self.assertEqual(parse_manual_publish("127.0.0.1:8080"), ("127.0.0.1", 8080))
        self.assertEqual(parse_manual_publish("localhost:8080"), ("127.0.0.1", 8080))
        self.assertEqual(parse_manual_publish(":8080"), ("127.0.0.1", 8080))

    def test_publish_rejects_non_loopback_and_invalid_ports(self):
        for value in ("0.0.0.0:8080", "192.0.2.10:8080", "8080:80",
                      "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_manual_publish(value)

    def test_listen_port_is_read_from_the_generated_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yaml"
            path.write_text("listen: 0.0.0.0:8443\n")
            self.assertEqual(manual_listen_port(path), 8443)

    def test_listen_port_requires_the_generated_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yaml"
            path.write_text("listen: 8080\n")
            with self.assertRaises(ValueError):
                manual_listen_port(path)

    def test_shell_container_stays_on_front_and_unprivileged(self):
        class Lab:
            project = "kunato-lab-test"
            input = Path("/tmp/kunato-lab-input")
            manifest = {"images": {"python": {"id": "python-image"},
                                   "sqlmap": {"id": "sqlmap-image"}}}

            def front_network(self):
                return f"{self.project}_front"

        args = SandboxSuite.manual_shell_command(Lab(), "python")
        self.assertEqual(args[args.index("--network") + 1], "kunato-lab-test_front")
        self.assertEqual(args[args.index("--user") + 1], "65532:65532")
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop", args)
        self.assertEqual(args[-1], "python-image")

    def test_ffuf_shell_mounts_the_prepared_binary(self):
        class Lab:
            project = "kunato-lab-test"
            input = Path("/tmp/kunato-lab-input")
            manifest = {"images": {"python": {"id": "python-image"}}}

            def front_network(self):
                return f"{self.project}_front"

        args = SandboxSuite.manual_shell_command(Lab(), "ffuf")
        self.assertIn("/tmp/kunato-lab-input/ffuf:/usr/local/bin/ffuf:ro", args)
        self.assertEqual(args[-1], "python-image")

    def test_loopback_forwarder_relays_bytes(self):
        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self):
                while data := self.request.recv(65536):
                    self.request.sendall(data)

        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        echo.daemon_threads = True
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        forwarder = ManualForwarder(("127.0.0.1", 0), ManualForwarderHandler)
        forwarder.target = echo.server_address
        threading.Thread(target=forwarder.serve_forever, daemon=True).start()
        try:
            with socket.create_connection(forwarder.server_address, timeout=2) as client:
                client.sendall(b"manual-forwarder")
                self.assertEqual(client.makefile("rb").read(16), b"manual-forwarder")
        finally:
            forwarder.shutdown()
            forwarder.server_close()
            echo.shutdown()
            echo.server_close()


if __name__ == "__main__":
    unittest.main()
