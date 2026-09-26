"""CLI runner, intentionally kept separate from core diagnostics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.checker import NetworkChecker
from core.models import CheckReport, Outcome, ProbeOptions, StageResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="net-diag", description="Диагностика DNS/TCP/TLS/HTTP-фильтрации")
    parser.add_argument("domains", nargs="*", help="Один или несколько доменов")
    parser.add_argument("--file", type=Path, help="Файл: по одному домену в строке (# — комментарий)")
    parser.add_argument("--timeout", type=float, default=7.0, help="Таймаут каждой сетевой пробы, секунд")
    parser.add_argument("--port-80", action="store_true", help="Дополнительно проверить TCP/80")
    parser.add_argument("--json", type=Path, metavar="PATH", help="Сохранить JSON-отчёт")
    parser.add_argument("--gui", action="store_true", help="Открыть графический интерфейс")
    return parser


def load_domains(values: list[str], filename: Path | None) -> list[str]:
    domains = list(values)
    if filename:
        try:
            domains.extend(line.strip() for line in filename.read_text(encoding="utf-8").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            raise ValueError(f"Не удалось прочитать {filename}: {exc}") from exc
    return list(dict.fromkeys(domains))


def run_cli(args: argparse.Namespace) -> int:
    console = Console()
    try:
        domains = load_domains(args.domains, args.file)
    except ValueError as exc:
        console.print(f"[red]Ошибка:[/] {exc}")
        return 2
    if not domains:
        console.print("[yellow]Укажите домен или --file. Для графического режима используйте --gui.[/]")
        return 2
    if args.timeout <= 0:
        console.print("[red]Таймаут должен быть больше нуля.[/]")
        return 2

    checker = NetworkChecker(ProbeOptions(timeout_seconds=args.timeout, test_port_80=args.port_80))
    reports: list[CheckReport] = []
    for domain in domains:
        console.rule(f"[bold cyan]{domain}")
        try:
            report = checker.check(domain, on_progress=lambda stage: _print_stage(console, stage))
            reports.append(report)
            _print_report(console, report)
        except ValueError as exc:
            console.print(f"[red]Некорректный домен:[/] {exc}")
        except Exception as exc:  # defensive boundary: a CLI must not print a traceback for a probe failure
            console.print(f"[red]Неожиданная ошибка диагностики {domain}:[/] {str(exc)[:240] or type(exc).__name__}")
    if args.json:
        try:
            args.json.write_text(json.dumps([item.as_dict() for item in reports], ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            console.print(f"[green]JSON-отчёт сохранён:[/] {args.json}")
        except OSError as exc:
            console.print(f"[red]Не удалось сохранить отчёт:[/] {exc}")
            return 1
    return 0 if reports else 2


def _print_stage(console: Console, stage: StageResult) -> None:
    styles = {Outcome.OK: "green", Outcome.WARNING: "yellow", Outcome.FAILED: "red", Outcome.SKIPPED: "dim"}
    duration = f" ({stage.elapsed_ms:.0f} ms)" if stage.elapsed_ms is not None else ""
    console.print(f"[{styles[stage.outcome]}]{stage.outcome.value.upper():7}[/] {stage.stage}: {stage.summary}{duration}")


def _print_report(console: Console, report: CheckReport) -> None:
    table = Table(title="Сводка", show_header=True)
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение")
    table.add_row("System DNS", ", ".join(report.system_ips) or "—")
    table.add_row("DoH", ", ".join(sorted({ip for ips in report.doh_ips.values() for ip in ips})) or "—")
    table.add_row("HTTP", str(report.http_status) if report.http_status else (report.http_error or "—"))
    if report.verdict:
        table.add_row("Вердикт", f"[bold]{report.verdict.kind.value}[/] ({report.verdict.confidence})")
    console.print(table)
    if report.verdict:
        for recommendation in report.verdict.recommendations:
            console.print(f"  [dim]•[/] {recommendation}")
