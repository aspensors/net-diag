"""Thread-safe CustomTkinter frontend for the diagnostic engine."""

from __future__ import annotations

import json
import queue
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.checker import NetworkChecker
from core.models import CheckReport, Outcome, ProbeOptions, StageResult


class NetDiagApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("net-diag — Network Diagnostic")
        self.geometry("940x650")
        self.minsize(800, 520)
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._reports: list[CheckReport] = []
        self._running = False
        self._build()
        self.after(100, self._drain_events)

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        header = ctk.CTkFrame(self, corner_radius=10)
        header.grid(row=0, column=0, padx=18, pady=(18, 10), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="net-diag", font=ctk.CTkFont(size=24, weight="bold")).grid(row=0, column=0, padx=16, pady=(14, 2), sticky="w")
        ctk.CTkLabel(header, text="DNS → TCP → TLS/SNI → HTTPS · безопасная диагностика сети", text_color="gray70").grid(row=1, column=0, padx=16, pady=(0, 14), sticky="w")

        controls = ctk.CTkFrame(self)
        controls.grid(row=1, column=0, padx=18, pady=8, sticky="ew")
        controls.grid_columnconfigure(0, weight=1)
        self.domain = ctk.CTkEntry(controls, placeholder_text="example.com или список доменов через пробел")
        self.domain.grid(row=0, column=0, padx=(12, 8), pady=12, sticky="ew")
        self.file_button = ctk.CTkButton(controls, text="Загрузить файл", width=120, command=self._choose_file)
        self.file_button.grid(row=0, column=1, padx=4, pady=12)
        self.run_button = ctk.CTkButton(controls, text="Запустить", width=110, command=self._start)
        self.run_button.grid(row=0, column=2, padx=(4, 12), pady=12)

        body = ctk.CTkFrame(self)
        body.grid(row=2, column=0, padx=18, pady=8, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(1, weight=1)
        self.verdict = ctk.CTkLabel(body, text="Готово к проверке", anchor="w", font=ctk.CTkFont(size=16, weight="bold"))
        self.verdict.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        self.log = ctk.CTkTextbox(body, wrap="word", font=("Cascadia Mono", 12))
        self.log.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="nsew")
        self.log.configure(state="disabled")

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=3, column=0, padx=18, pady=(2, 18), sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkLabel(footer, text="")
        self.progress.grid(row=0, column=0, sticky="w")
        self.export_button = ctk.CTkButton(footer, text="Экспорт JSON", command=self._export, state="disabled")
        self.export_button.grid(row=0, column=1, sticky="e")

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Список доменов", filetypes=[("Text files", "*.txt *.list"), ("All files", "*.*")])
        if not path:
            return
        try:
            values = [x.strip() for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
        except OSError as exc:
            messagebox.showerror("net-diag", f"Не удалось прочитать файл:\n{exc}")
            return
        self.domain.delete(0, "end")
        self.domain.insert(0, " ".join(values))

    def _start(self) -> None:
        domains = list(dict.fromkeys(self.domain.get().split()))
        if not domains:
            messagebox.showwarning("net-diag", "Введите хотя бы один домен или загрузите файл.")
            return
        if self._running:
            return
        self._reports.clear()
        self._set_log("")
        self._running = True
        self.run_button.configure(state="disabled")
        self.file_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.verdict.configure(text="Выполняется диагностика…", text_color="#5dade2")
        threading.Thread(target=self._worker, args=(domains,), daemon=True, name="net-diag-worker").start()

    def _worker(self, domains: list[str]) -> None:
        checker = NetworkChecker(ProbeOptions())
        for domain in domains:
            self._events.put(("line", f"\n══ {domain} ══\n"))
            try:
                report = checker.check(domain, on_progress=lambda stage, d=domain: self._events.put(("stage", (d, stage))))
                self._events.put(("report", report))
            except ValueError as exc:
                self._events.put(("line", f"ОШИБКА {domain}: {exc}\n"))
            except Exception as exc:  # keep worker failures visible but never crash Tk's UI loop
                self._events.put(("line", f"ОШИБКА диагностики {domain}: {str(exc)[:240] or type(exc).__name__}\n"))
        self._events.put(("done", None))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, value = self._events.get_nowait()
                if kind == "line":
                    self._append(str(value))
                elif kind == "stage":
                    domain, stage = value  # type: ignore[misc]
                    self._show_stage(domain, stage)
                elif kind == "report":
                    self._reports.append(value)  # type: ignore[arg-type]
                    report: CheckReport = value  # type: ignore[assignment]
                    if report.verdict:
                        colour = "#58d68d" if report.verdict.kind.value.startswith("OK") else "#f5b041"
                        self.verdict.configure(text=f"{report.domain}: {report.verdict.kind.value}", text_color=colour)
                elif kind == "done":
                    self._running = False
                    self.run_button.configure(state="normal")
                    self.file_button.configure(state="normal")
                    self.export_button.configure(state="normal" if self._reports else "disabled")
                    self.progress.configure(text="Проверка завершена")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _show_stage(self, domain: str, stage: StageResult) -> None:
        symbol = {Outcome.OK: "✓", Outcome.WARNING: "!", Outcome.FAILED: "×", Outcome.SKIPPED: "–"}[stage.outcome]
        timing = f" [{stage.elapsed_ms:.0f} ms]" if stage.elapsed_ms is not None else ""
        self._append(f"{symbol} {stage.stage}{timing}: {stage.summary}\n")
        self.progress.configure(text=f"{domain}: {stage.stage}")

    def _set_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", text)
        self.log.configure(state="disabled")

    def _append(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(title="Экспорт отчёта", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            Path(path).write_text(json.dumps([report.as_dict() for report in self._reports], ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.progress.configure(text=f"Отчёт сохранён: {path}")
        except OSError as exc:
            messagebox.showerror("net-diag", f"Не удалось сохранить отчёт:\n{exc}")


def run_gui() -> None:
    NetDiagApp().mainloop()
