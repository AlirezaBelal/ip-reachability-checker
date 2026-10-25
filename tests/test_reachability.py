import errno
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ip_reachability_checker import (
    ConfigurationError,
    MAX_FILE_LINES,
    MAX_LINE_LENGTH,
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

    def test_file_errors_are_configuration_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.txt"
            for content in (b"", b"# comment\n\n", b"\xff"):
                path.write_bytes(content)
                with self.subTest(content=content), self.assertRaises(ConfigurationError):
                    collect_targets([], path)
            path.unlink()
            with self.assertRaises(ConfigurationError):
                collect_targets([], path)
            with patch.object(Path, "open", side_effect=PermissionError):
                with self.assertRaises(ConfigurationError):
                    collect_targets([], path)

    def test_target_limit_stops_consuming_file(self):
        def targets():
            for number in range(257):
                yield f"192.0.{number // 256}.{number % 256}"
            self.fail("Read past the unique target limit")

        with patch("ip_reachability_checker._iter_file_targets", return_value=targets()):
            with self.assertRaisesRegex(ConfigurationError, "at most 256"):
                collect_targets([], Path("unused"))

    def test_file_validation_stops_at_first_invalid_target(self):
        def targets():
            yield "not-an-ip"
            self.fail("Read past invalid input")

        with patch("ip_reachability_checker._iter_file_targets", return_value=targets()):
            with self.assertRaises(ConfigurationError):
                collect_targets([], Path("unused"))


class BoundedFileInputTests(unittest.TestCase):
    def test_file_line_budget_applies_to_duplicates(self):
        # Previously, an arbitrary number of duplicate IPs could be consumed.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicates.txt"
            path.write_text("127.0.0.1\n" * (MAX_FILE_LINES + 1), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "exceeds 4096 lines"):
                collect_targets([], path)

    def test_file_line_budget_applies_to_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comments.txt"
            path.write_text("# ignored\n" * MAX_FILE_LINES + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "exceeds 4096 lines"):
                collect_targets([], path)

    def test_file_accepts_limit_with_a_valid_final_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exact.txt"
            path.write_text("# comment\n" * (MAX_FILE_LINES - 1) + "127.0.0.1\n", encoding="utf-8")
            self.assertEqual(collect_targets([], path), ["127.0.0.1"])

    def test_rejects_long_line_before_attempting_ip_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "long.txt"
            path.write_text("# initial\n" + "x" * (MAX_LINE_LENGTH + 1) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "line 2 exceeds 512 characters"):
                collect_targets([], path)

    def test_comment_with_maximum_characters_and_crlf_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.txt"
            path.write_bytes(("#" + "x" * (MAX_LINE_LENGTH - 1) + "\r\n127.0.0.1\r\n").encode())
            self.assertEqual(collect_targets([], path), ["127.0.0.1"])


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

    def test_ping_process_timeout_is_not_a_local_operational_error(self):
        def runner(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        result = check_icmp("192.0.2.10", runner=runner, system_name="Linux")
        self.assertEqual(result.status, "unreachable")
        self.assertEqual(result.detail, "ping timed out")

    def test_nonstandard_ping_exit_is_operational_error(self):
        runner = lambda command, **kwargs: subprocess.CompletedProcess(command, 2)
        result = check_icmp("192.0.2.10", runner=runner, system_name="Linux")
        self.assertEqual(result.status, "error")
        self.assertEqual(exit_code_for([result]), 2)

    def test_short_response_timeout_allows_packet_spacing(self):
        for system in ("Linux", "Windows", "Darwin"):
            def runner(command, **kwargs):
                # Ten loopback packets need roughly nine seconds at default spacing.
                if kwargs["timeout"] < 10:
                    raise subprocess.TimeoutExpired(command, kwargs["timeout"])
                return subprocess.CompletedProcess(command, 0)

            with self.subTest(system=system):
                result = check_icmp("127.0.0.1", count=10, timeout_seconds=0.1,
                                    runner=runner, system_name=system)
                self.assertEqual(result.status, "reachable")


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

    def test_permission_error_is_not_reported_as_host_offline(self):
        def connector(*args, **kwargs):
            raise PermissionError(errno.EACCES, "permission denied")

        result = check_tcp("127.0.0.1", 443, connector=connector)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.detail, "TCP check failed locally")

    def test_windows_network_error_and_unknown_error_are_distinct(self):
        for winerror, status in ((10065, "unreachable"), (10013, "error")):
            error = OSError("synthetic socket failure")
            error.winerror = winerror
            with self.subTest(winerror=winerror):
                def connector(*args, **kwargs):
                    raise error

                self.assertEqual(check_tcp("127.0.0.1", 80, connector=connector).status,
                                 status)


class CliSemanticsTests(unittest.TestCase):
    def test_validate_options_rejects_port_and_worker_overreach(self):
        args = SimpleNamespace(tcp_port=0, count=2, timeout=1, workers=8)
        with self.assertRaises(ConfigurationError):
            validate_options(args)
        args = SimpleNamespace(tcp_port=443, count=2, timeout=1, workers=33)
        with self.assertRaises(ConfigurationError):
            validate_options(args)

    def test_timeout_must_be_finite_and_bounded(self):
        for timeout in (float("nan"), float("inf"), -float("inf"), 0, -1, 10.1):
            with self.subTest(timeout=timeout), self.assertRaises(ConfigurationError):
                validate_options(SimpleNamespace(tcp_port=None, count=2,
                                                 timeout=timeout, workers=8))

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
