"""Real spawned workers with deliberately blocked probes; no external network."""

import contextlib
import io
import json
import multiprocessing
import queue
import tempfile
import threading
import time
from pathlib import Path
import unittest
from unittest.mock import patch

from cli.app import build_parser, run_cli
from core.models import CheckReport, Outcome, ProbeOptions, StageResult, VerdictKind
from core.runner import DiagnosticRunner, _worker as run_worker


def dns_worker(connection, domain, options):
    def blocked_dns(*args, **kwargs):
        snapshot = CheckReport(domain)
        snapshot.stages.append(StageResult("Fixture DNS entered", Outcome.WARNING, "resolver is blocked"))
        connection.send(("snapshot", snapshot))
        time.sleep(60)
        return []
    with patch("core.checker.socket.getaddrinfo", side_effect=blocked_dns):
        run_worker(connection, domain, options)


def partial_worker(connection, domain, options):
    report = CheckReport(domain, system_ips=["192.0.2.1"])
    report.stages.append(StageResult("DNS (system)", Outcome.OK, "fixture DNS completed"))
    connection.send(("snapshot", report))
    time.sleep(60)


def complete_worker(connection, domain, options):
    with patch("core.checker.NetworkChecker._resolve_system", return_value=[]), \
         patch("core.checker.NetworkChecker._resolve_doh", return_value=[]):
        run_worker(connection, domain, options)


def error_worker(connection, domain, options):
    connection.send(("error", ("RuntimeError", "fixture error")))
    connection.close()


def closed_worker(connection, domain, options):
    connection.close()


class DeadlineTests(unittest.TestCase):
    def tearDown(self):
        self.assertFalse([p for p in multiprocessing.active_children() if p.name == "net-diag-probe"],
                         "A probe worker was left running")
        self.assertFalse([t for t in threading.enumerate() if t.name == "net-diag-result-reader"],
                         "A pipe reader was left running")

    def test_blocked_system_dns_is_terminated_and_report_is_serialisable(self):
        started = time.monotonic()
        with patch("core.runner._worker", dns_worker):
            report = DiagnosticRunner(ProbeOptions(deadline_seconds=3)).check("example.com")
        self.assertLess(time.monotonic() - started, 6)
        self.assertTrue(report.timed_out)
        self.assertTrue(any(stage.stage == "Fixture DNS entered" for stage in report.stages))
        self.assertEqual(report.verdict.kind, VerdictKind.INCONCLUSIVE)
        self.assertEqual(json.loads(json.dumps(report.as_dict()))["timed_out"], True)

    def test_completed_stages_survive_a_later_stall(self):
        seen = []
        with patch("core.runner._worker", partial_worker):
            report = DiagnosticRunner(ProbeOptions(deadline_seconds=3)).check("example.com", seen.append)
        self.assertTrue(report.timed_out)
        self.assertEqual(report.system_ips, ["192.0.2.1"])
        self.assertEqual([stage.stage for stage in seen], ["DNS (system)", "Deadline", "Verdict"])

    def test_normal_completion_and_streamed_stages(self):
        seen = []
        with patch("core.runner._worker", complete_worker):
            report = DiagnosticRunner(ProbeOptions(deadline_seconds=8)).check("example.com", seen.append)
        self.assertFalse(report.timed_out)
        self.assertEqual(report.verdict.kind, VerdictKind.INCONCLUSIVE)
        self.assertEqual(len(seen), len(report.stages))
        self.assertTrue(any(stage.stage == "DNS (system)" for stage in seen))

    def test_worker_error_and_unexpected_exit_clean_up(self):
        for worker, message in ((error_worker, "fixture error"), (closed_worker, "без итогового")):
            with self.subTest(worker=worker.__name__), patch("core.runner._worker", worker):
                with self.assertRaisesRegex(RuntimeError, message):
                    DiagnosticRunner(ProbeOptions(deadline_seconds=8)).check("example.com")

    def test_progress_callback_failure_still_stops_worker(self):
        def fail(stage):
            raise RuntimeError("callback failed")
        with patch("core.runner._worker", partial_worker):
            with self.assertRaisesRegex(RuntimeError, "callback failed"):
                DiagnosticRunner(ProbeOptions(deadline_seconds=8)).check("example.com", fail)

    def test_deadline_works_when_called_from_gui_style_background_thread(self):
        result = queue.Queue()
        def invoke():
            try:
                result.put(DiagnosticRunner(ProbeOptions(deadline_seconds=8)).check("example.com"))
            except BaseException as exc:
                result.put(exc)
        with patch("core.runner._worker", complete_worker):
            thread = threading.Thread(target=invoke)
            thread.start()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        report = result.get_nowait()
        self.assertIsInstance(report, CheckReport)
        self.assertFalse(report.timed_out)

    def test_invalid_deadline_rejected_before_process_start(self):
        for value in (0, -1, float("nan"), float("inf")):
            with self.subTest(value=value), patch("core.runner.multiprocessing.get_context") as spawn:
                with self.assertRaises(ValueError):
                    DiagnosticRunner(ProbeOptions(deadline_seconds=value)).check("example.com")
                spawn.assert_not_called()

    def test_cli_saves_deadline_report_and_exits_one(self):
        with tempfile.TemporaryDirectory() as tmp, patch("cli.app.NetworkChecker") as factory, \
             contextlib.redirect_stdout(io.StringIO()):
            factory.return_value.check.return_value = CheckReport("example.com", timed_out=True)
            filename = Path(tmp) / "report.json"
            args = build_parser().parse_args(["example.com", "--deadline", "2", "--json", str(filename)])
            self.assertEqual(run_cli(args), 1)
            self.assertTrue(json.loads(filename.read_text())[0]["timed_out"])
            self.assertEqual(factory.call_args.args[0].deadline_seconds, 2)

    def test_cli_rejects_nonfinite_deadline_without_starting_worker(self):
        for value in ("nan", "inf", "0", "-1"):
            with self.subTest(value=value), patch("cli.app.NetworkChecker") as factory, \
                 contextlib.redirect_stdout(io.StringIO()):
                args = build_parser().parse_args(["example.com", "--deadline", value])
                self.assertEqual(run_cli(args), 2)
                factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
