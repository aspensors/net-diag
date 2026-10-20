import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.analyzer import build_verdict
from core.checker import NetworkChecker
from core.models import CheckReport, Outcome, ProbeOptions, TcpAttempt, TlsAttempt, VerdictKind
from cli.app import build_parser, load_domains, run_cli
from main import _configure_windows_output


def tcp(ip="1.1.1.1", port=443, ok=False, error="timeout"):
    return TcpAttempt(ip, port, Outcome.OK if ok else Outcome.FAILED, 1, None if ok else error)


def tls(ip="1.1.1.1", ok=False, sni="example.com"):
    return TlsAttempt(ip, sni, Outcome.OK if ok else Outcome.FAILED, 1)


class VerdictTests(unittest.TestCase):
    def test_empty_report_is_inconclusive(self):
        self.assertEqual(build_verdict(CheckReport("example.com")).kind, VerdictKind.INCONCLUSIVE)

    def test_port_80_only_cannot_imply_port_443_drop(self):
        report = CheckReport("example.com", tcp=[tcp(port=80)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.INCONCLUSIVE)

    def test_all_443_timeouts_support_tcp_failure(self):
        report = CheckReport("example.com", tcp=[tcp(), tcp("8.8.8.8", error="reset")])
        self.assertEqual(build_verdict(report).kind, VerdictKind.TCP_DROP)

    def test_unknown_socket_error_does_not_imply_drop(self):
        self.assertEqual(build_verdict(CheckReport("example.com", tcp=[tcp(error="socket")])).kind,
                         VerdictKind.INCONCLUSIVE)

    def test_http_response_outweighs_failed_tcp_sample(self):
        report = CheckReport("example.com", tcp=[tcp()], http_status=200)
        self.assertEqual(build_verdict(report).kind, VerdictKind.CLEAN)

    def test_unprobed_system_address_cannot_imply_dns_poisoning(self):
        report = CheckReport("example.com", system_ips=["1.1.1.1"], doh_ips={"test": ["8.8.8.8"]},
                             tls_with_sni=[tls("8.8.8.8", ok=True)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.CLEAN)

    def test_one_unprobed_system_address_keeps_dns_finding_unconfirmed(self):
        report = CheckReport("example.com", system_ips=["1.1.1.1", "9.9.9.9"],
                             doh_ips={"test": ["8.8.8.8"]},
                             tls_with_sni=[tls(), tls("8.8.8.8", ok=True)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.CLEAN)

    def test_dns_discrepancy_with_all_local_tls_failures(self):
        report = CheckReport("example.com", system_ips=["1.1.1.1"], doh_ips={"test": ["8.8.8.8"]},
                             tls_with_sni=[tls(), tls("8.8.8.8", ok=True)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.DNS_POISONING)

    def test_private_dns_address_with_working_tls_is_not_poisoning(self):
        report = CheckReport("example.com", system_ips=["192.168.1.1"], doh_ips={"test": ["8.8.8.8"]},
                             tls_with_sni=[tls("192.168.1.1", ok=True), tls("8.8.8.8", ok=True)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.CLEAN)

    def test_different_dns_answers_alone_are_not_poisoning(self):
        report = CheckReport("example.com", system_ips=["1.1.1.1"], doh_ips={"test": ["8.8.8.8"]})
        self.assertEqual(build_verdict(report).kind, VerdictKind.INCONCLUSIVE)

    def test_sni_control_must_use_same_address(self):
        report = CheckReport("example.com", tcp=[tcp(ok=True)], tls_with_sni=[tls()],
                             tls_without_sni=[tls("8.8.8.8", ok=True, sni=None)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.INCONCLUSIVE)

    def test_paired_sni_failure_is_reported(self):
        report = CheckReport("example.com", tcp=[tcp(ok=True)], tls_with_sni=[tls()],
                             tls_without_sni=[tls(ok=True, sni=None)])
        self.assertEqual(build_verdict(report).kind, VerdictKind.DPI_SNI)

    def test_successful_http_outweighs_sni_failure(self):
        report = CheckReport("example.com", tcp=[tcp(ok=True)], tls_with_sni=[tls()],
                             tls_without_sni=[tls(ok=True, sni=None)], http_status=200)
        self.assertEqual(build_verdict(report).kind, VerdictKind.CLEAN)

    def test_http_interception_marker_keeps_review_finding(self):
        report = CheckReport("example.com", http_status=302, http_suspected_hijack=True)
        self.assertEqual(build_verdict(report).kind, VerdictKind.HTTP_HIJACK)

    def test_tls_success_does_not_claim_all_stages_passed(self):
        verdict = build_verdict(CheckReport("example.com", tls_with_sni=[tls(ok=True)]))
        self.assertEqual(verdict.kind, VerdictKind.CLEAN)
        self.assertEqual(verdict.confidence, "medium")
        self.assertIn("не подтверждает", verdict.summary)


class CheckerTests(unittest.TestCase):
    def test_no_dns_results_skip_transport_without_network(self):
        checker = NetworkChecker()
        with patch.object(checker, "_resolve_system", return_value=[]), \
             patch.object(checker, "_resolve_doh", side_effect=ValueError("fixture")), \
             patch("socket.create_connection", side_effect=AssertionError("Network forbidden")):
            report = checker.check("example.com")
        self.assertEqual(report.verdict.kind, VerdictKind.INCONCLUSIVE)
        self.assertEqual([s.outcome for s in report.stages if s.stage in {"TCP", "TLS/SNI", "HTTP"}],
                         [Outcome.SKIPPED] * 3)
        json.dumps(report.as_dict())

    def test_candidates_deduplicated_and_bounded(self):
        checker = NetworkChecker(ProbeOptions(max_ips=2))
        with patch.object(checker, "_resolve_system", return_value=["1.1.1.1", "8.8.8.8"]), \
             patch.object(checker, "_resolve_doh", return_value=["1.1.1.1", "9.9.9.9"]), \
             patch.object(checker, "_check_tcp") as transport, \
             patch.object(checker, "_check_tls"), patch.object(checker, "_check_http"):
            checker.check("example.com")
        self.assertEqual(transport.call_args.args[0], ["1.1.1.1", "8.8.8.8"])

    def test_domain_url_and_idn_normalisation(self):
        self.assertEqual(NetworkChecker._normalise_domain(" HTTPS://Example.COM/path "), "example.com")
        self.assertEqual(NetworkChecker._normalise_domain("пример.рф"), "xn--e1afmkfd.xn--p1ai")


class CliTests(unittest.TestCase):
    def test_windows_redirected_help_uses_utf8(self):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252")
        with patch("sys.platform", "win32"), patch("sys.stdout", stream):
            _configure_windows_output()
            build_parser().print_help()
            stream.flush()
        self.assertIn("Диагностика", buffer.getvalue().decode("utf-8"))

    def test_domain_file_comments_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "domains.txt"
            path.write_text("# comment\nexample.com\n\nexample.org\n", encoding="utf-8")
            self.assertEqual(load_domains(["example.com"], path), ["example.com", "example.org"])

    def test_missing_domain_file_is_actionable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                load_domains([], Path(tmp) / "missing.txt")

    def test_nonfinite_or_nonpositive_timeouts_rejected_before_probes(self):
        for timeout in ("nan", "inf", "0", "-1"):
            with self.subTest(timeout=timeout), patch("cli.app.NetworkChecker") as checker, \
                 contextlib.redirect_stdout(io.StringIO()):
                args = build_parser().parse_args(["example.com", "--timeout", timeout])
                self.assertEqual(run_cli(args), 2)
                checker.assert_not_called()

    def test_partial_domain_failure_has_nonzero_exit_and_keeps_json(self):
        with tempfile.TemporaryDirectory() as tmp, patch("cli.app.NetworkChecker") as factory, \
             contextlib.redirect_stdout(io.StringIO()):
            factory.return_value.check.side_effect = [CheckReport("example.com"), ValueError("bad domain")]
            output = Path(tmp) / "report.json"
            args = build_parser().parse_args(["example.com", "bad/domain", "--json", str(output)])
            self.assertEqual(run_cli(args), 1)
            self.assertEqual(json.loads(output.read_text())[0]["domain"], "example.com")

    def test_successful_cli_export(self):
        with tempfile.TemporaryDirectory() as tmp, patch("cli.app.NetworkChecker") as factory, \
             contextlib.redirect_stdout(io.StringIO()):
            factory.return_value.check.return_value = CheckReport("example.com")
            output = Path(tmp) / "report.json"
            self.assertEqual(run_cli(build_parser().parse_args(["example.com", "--json", str(output)])), 0)
            self.assertEqual(len(json.loads(output.read_text())), 1)


if __name__ == "__main__":
    unittest.main()
