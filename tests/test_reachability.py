import errno
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ip_reachability_checker import (
    ConfigurationError,
    ReachabilityResult,
    build_ping_command,
    check_icmp,
    check_tcp,
    collect_targets,
    exit_code_for,
    normalize_ip,
    render_json,
    validate_options,
)


class TargetValidationTests(unittest.TestCase):
    def test_normalize_ipv4_and_ipv6(self):
        self.assertEqual(normalize_ip(" 192.0.2.10 "), "192.0.2.10")
        self.assertEqual(normalize_ip("2001:db8::1"), "2001:db8::1")

    def test_rejects_hostname_cidr_and_shell_like_input(self):
        for value in ("example.com", "192.0.2.0/24", "127.0.0.1;echo bad", ""):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                normalize_ip(value)

    def test_collect_targets_deduplicates_and_reads_comments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "targets.txt"
            path.write_text("# example\n192.0.2.10\n\n2001:db8::1\n", encoding="utf-8")
            targets = collect_targets(["192.0.2.10"], path)
            self.assertEqual(targets, ["192.0.2.10", "2001:db8::1"])

    def test_target_file_accepts_utf8_bom(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "targets.txt"
            path.write_bytes(b"\xef\xbb\xbf192.0.2.10\n")
            self.assertEqual(collect_targets([], path), ["192.0.2.10"])


class PingCommandTests(unittest.TestCase):
    def test_linux_command_is_shell_free_and_bounded(self):
        self.assertEqual(
            build_ping_command("192.0.2.10", 2, 1.2, "Linux"),
            ["ping", "-4", "-c", "2", "-W", "2", "192.0.2.10"],
        )

    def test_windows_ipv6_command(self):
        command = build_ping_command("2001:db8::1", 3, 0.5, "Windows")
        self.assertEqual(command[:6], ["ping", "-6", "-n", "3", "-w", "500"])
        self.assertEqual(command[-1], "2001:db8::1")

    def test_macos_uses_ping6_for_ipv6(self):
        self.assertEqual(
            build_ping_command("2001:db8::1", 1, 1, "Darwin"),
            ["ping6", "-c", "1", "2001:db8::1"],
        )


class IcmpResultTests(unittest.TestCase):
    def test_return_code_zero_is_reachable_without_parsing_stdout(self):
        runner = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0)
        result = check_icmp("192.0.2.10", runner=runner, system_name="Linux")
        self.assertEqual(result.status, "reachable")

    def test_return_code_one_is_unreachable(self):
        runner = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1)
        result = check_icmp("192.0.2.10", runner=runner, system_name="Linux")
        self.assertEqual(result.status, "unreachable")

    def test_missing_ping_is_controlled_error(self):
        def runner(*args, **kwargs):
            raise FileNotFoundError

        result = check_icmp("192.0.2.10", runner=runner, system_name="Linux")
        self.assertEqual(result.status, "error")
        self.assertNotIn("192.0.2.10", result.detail)


class TcpResultTests(unittest.TestCase):
    def test_network_unreachable_is_classified_as_unreachable(self):
        def connector(*args, **kwargs):
            raise OSError(errno.ENETUNREACH, "network unreachable")

        result = check_tcp("192.0.2.10", 443, connector=connector)
        self.assertEqual(result.status, "unreachable")
        self.assertEqual(exit_code_for([result]), 1)

    def test_local_resource_error_is_classified_as_error(self):
        def connector(*args, **kwargs):
            raise OSError(errno.EMFILE, "too many open files")

        result = check_tcp("192.0.2.10", 443, connector=connector)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.detail, "TCP check failed locally")
        self.assertEqual(exit_code_for([result]), 2)


class CliSemanticsTests(unittest.TestCase):
    def test_validate_options_rejects_port_and_worker_overreach(self):
        args = SimpleNamespace(tcp_port=0, count=2, timeout=1, workers=8)
        with self.assertRaises(ConfigurationError):
            validate_options(args)
        args = SimpleNamespace(tcp_port=443, count=2, timeout=1, workers=33)
        with self.assertRaises(ConfigurationError):
            validate_options(args)

    def test_json_and_exit_codes(self):
        results = [
            ReachabilityResult("127.0.0.1", "tcp", "reachable", 0.1, "port 1"),
            ReachabilityResult("192.0.2.10", "icmp", "unreachable", 1.0),
        ]
        payload = render_json(results)
        self.assertIn('"reachable": 1', payload)
        self.assertEqual(exit_code_for(results), 1)
        self.assertEqual(exit_code_for([ReachabilityResult("127.0.0.1", "icmp", "error")]), 2)


if __name__ == "__main__":
    unittest.main()
