import json
import socket
import subprocess
import sys
import threading
import unittest


class CliIntegrationTests(unittest.TestCase):
    def test_real_tcp_check_against_loopback_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        accepted = threading.Event()

        def serve_once():
            try:
                connection, _address = server.accept()
                accepted.set()
                connection.close()
            finally:
                server.close()

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        completed = subprocess.run(
            [
                sys.executable,
                "ip_reachability_checker.py",
                "127.0.0.1",
                "--tcp-port",
                str(port),
                "--timeout",
                "1",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        thread.join(timeout=2)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(accepted.is_set())
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["reachable"], 1)
        self.assertEqual(payload["results"][0]["ip"], "127.0.0.1")
        self.assertEqual(payload["results"][0]["method"], "tcp")
        self.assertEqual(payload["results"][0]["status"], "reachable")

    def test_invalid_timeout_and_file_fail_cleanly(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            path.write_bytes(b"\xff")
            for options in (["--file", str(path)],
                            ["127.0.0.1", "--timeout", "nan"],
                            ["127.0.0.1", "--timeout", "inf"]):
                with self.subTest(options=options):
                    completed = subprocess.run(
                        [sys.executable, "ip_reachability_checker.py", *options],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn("Configuration error:", completed.stderr)
                    self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
