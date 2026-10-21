"""Process isolation for network calls which cannot be cancelled safely in a thread."""

from __future__ import annotations

import math
import multiprocessing
import queue
import threading
import time

from .checker import NetworkChecker, ProgressCallback
from .models import CheckReport, Outcome, ProbeOptions, StageResult, Verdict, VerdictKind


def _worker(connection, domain: str, options: ProbeOptions) -> None:
    """Spawn-safe target: no GUI objects, callbacks or open sockets cross processes."""
    try:
        report = NetworkChecker(options).check(
            domain, on_snapshot=lambda snapshot: connection.send(("snapshot", snapshot)))
        connection.send(("complete", report))
    except Exception as exc:
        try:
            connection.send(("error", (type(exc).__name__, str(exc)[:240])))
        except (OSError, EOFError):
            pass
    finally:
        connection.close()


def _read_messages(connection, messages: queue.Queue) -> None:
    # Reading a partially transmitted pickle must not block the supervisor's
    # deadline. The reader exits when its dedicated worker closes the pipe.
    try:
        while True:
            message = connection.recv()
            messages.put(message)
            if message[0] in {"complete", "error"}:
                return
    except (EOFError, OSError, ValueError):
        messages.put(("closed", None))


class DiagnosticRunner:
    """One disposable worker and pipe per domain; partial results survive a timeout."""

    def __init__(self, options: ProbeOptions | None = None):
        self.options = options or ProbeOptions()

    def check(self, domain: str, on_progress: ProgressCallback | None = None) -> CheckReport:
        for value in (self.options.timeout_seconds, self.options.deadline_seconds):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("Таймаут и дедлайн должны быть конечными числами больше нуля.")
        domain = NetworkChecker._normalise_domain(domain)
        report = CheckReport(domain)
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=_worker, args=(send, domain, self.options),
                                  name="net-diag-probe", daemon=True)
        messages = queue.Queue()
        reader = threading.Thread(target=_read_messages, args=(receive, messages),
                                  name="net-diag-result-reader", daemon=True)
        started = time.monotonic()
        expires = started + self.options.deadline_seconds
        launched = False
        reading = False
        try:
            process.start()
            launched = True
            send.close()
            reader.start()
            reading = True
            while True:
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    return self._deadline_report(report, started, on_progress)
                try:
                    kind, payload = messages.get(timeout=remaining)
                except queue.Empty:
                    return self._deadline_report(report, started, on_progress)
                if kind == "snapshot":
                    report = payload
                    if on_progress and report.stages:
                        on_progress(report.stages[-1])
                elif kind == "complete":
                    return payload
                elif kind == "error":
                    exception, message = payload
                    if exception == "ValueError":
                        raise ValueError(message)
                    raise RuntimeError(f"Ошибка сетевого процесса ({exception}): {message}")
                else:
                    raise RuntimeError("Сетевой процесс завершился без итогового отчёта.")
        finally:
            send.close()
            if launched:
                # A timed-out worker may be inside getaddrinfo or an HTTP read.
                # Never wait for it without a bound, and never reuse its pipe.
                if process.is_alive():
                    process.terminate()
                process.join(timeout=0.5)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=0.5)
            if reading:
                reader.join(timeout=0.5)
            receive.close()
            if not launched or not process.is_alive():
                process.close()

    def _deadline_report(self, report, started, on_progress):
        report.timed_out = True
        report.verdict = Verdict(
            VerdictKind.INCONCLUSIVE, "low",
            "Общий лимит времени истёк. Сохранены только полученные данные; диагностика не завершена.",
            ["Проверьте доступность DNS/сети или увеличьте --deadline и повторите диагностику."],
        )
        stages = [
            StageResult("Deadline", Outcome.FAILED, report.verdict.summary,
                        {"deadline_seconds": self.options.deadline_seconds, "partial_report": True},
                        round((time.monotonic() - started) * 1000, 1)),
            StageResult("Verdict", Outcome.WARNING, report.verdict.kind.value + ": " + report.verdict.summary,
                        {"confidence": "low", "recommendations": report.verdict.recommendations}),
        ]
        for stage in stages:
            report.stages.append(stage)
            if on_progress:
                on_progress(stage)
        return report
