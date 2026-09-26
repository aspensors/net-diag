"""Synchronous, UI-agnostic network probes with bounded timeouts and safe failures."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from urllib.parse import urlparse

import httpx

from .analyzer import build_verdict
from .models import CheckReport, Outcome, ProbeOptions, StageResult, TcpAttempt, TlsAttempt

ProgressCallback = Callable[[StageResult], None]


class NetworkChecker:
    """Runs a complete diagnostic sequence for one DNS hostname."""

    DOH_ENDPOINTS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
    }

    def __init__(self, options: ProbeOptions | None = None) -> None:
        self.options = options or ProbeOptions()

    def check(self, domain: str, on_progress: ProgressCallback | None = None) -> CheckReport:
        domain = self._normalise_domain(domain)
        report = CheckReport(domain=domain)

        def emit(result: StageResult) -> None:
            report.stages.append(result)
            if on_progress:
                on_progress(result)

        started = time.perf_counter()
        report.system_ips = self._resolve_system(domain)
        emit(StageResult("DNS (system)", Outcome.OK if report.system_ips else Outcome.FAILED,
                         ", ".join(report.system_ips) if report.system_ips else "Системный резолвер не вернул A/AAAA записи.",
                         {"addresses": report.system_ips}, self._elapsed(started)))

        started = time.perf_counter()
        doh_errors: dict[str, str] = {}
        for provider, endpoint in self.DOH_ENDPOINTS.items():
            try:
                report.doh_ips[provider] = self._resolve_doh(endpoint, domain)
            except (httpx.HTTPError, ValueError) as exc:
                report.doh_ips[provider] = []
                doh_errors[provider] = self._safe_error(exc)
        doh_values = sorted({ip for values in report.doh_ips.values() for ip in values})
        emit(StageResult("DNS (DoH)", Outcome.OK if doh_values else Outcome.WARNING,
                         ", ".join(doh_values) if doh_values else "DoH-ответ недоступен; сравнение DNS ограничено.",
                         {"providers": report.doh_ips, "errors": doh_errors}, self._elapsed(started)))

        self._compare_dns(report, emit)

        candidates = self._unique(report.system_ips + doh_values)[: self.options.max_ips]
        if not candidates:
            emit(StageResult("TCP", Outcome.SKIPPED, "Нет IP-адресов для TCP-пробы."))
            emit(StageResult("TLS/SNI", Outcome.SKIPPED, "Нет IP-адресов для TLS-пробы."))
            emit(StageResult("HTTP", Outcome.SKIPPED, "Нет IP-адресов для HTTP-пробы."))
        else:
            self._check_tcp(candidates, report, emit)
            self._check_tls(candidates, domain, report, emit)
            self._check_http(domain, report, emit)
        report.verdict = build_verdict(report)
        emit(StageResult("Verdict", Outcome.OK if report.verdict.kind.value.startswith("OK") else Outcome.WARNING,
                         report.verdict.kind.value + ": " + report.verdict.summary,
                         {"confidence": report.verdict.confidence, "recommendations": report.verdict.recommendations}))
        return report

    @staticmethod
    def _compare_dns(report: CheckReport, emit: ProgressCallback) -> None:
        """Report DNS disagreement as evidence, never as a conclusion by itself.

        Authoritative and CDN-backed names routinely return different anycast or
        geo-routed addresses to different recursive resolvers. A later verdict
        therefore requires a reachability/TLS discrepancy before calling this
        poisoning.
        """
        system = set(report.system_ips)
        doh = {ip for values in report.doh_ips.values() for ip in values}
        if not system or not doh:
            emit(StageResult("DNS comparison", Outcome.SKIPPED,
                             "Сравнение пропущено: один из источников DNS не дал адресов."))
            return
        overlap = sorted(system & doh)
        if overlap:
            emit(StageResult("DNS comparison", Outcome.OK,
                             "Ответы DNS частично совпадают.", {"overlap": overlap}))
            return
        emit(StageResult("DNS comparison", Outcome.WARNING,
                         "Ответы system DNS и DoH не пересекаются; для CDN/GeoDNS это может быть нормой.",
                         {"system_addresses": sorted(system), "doh_addresses": sorted(doh)}))

    def _check_tcp(self, addresses: list[str], report: CheckReport, emit: ProgressCallback) -> None:
        started = time.perf_counter()
        ports = [443] + ([80] if self.options.test_port_80 else [])
        for address in addresses:
            for port in ports:
                report.tcp.append(self._tcp_attempt(address, port))
        successes = sum(x.outcome is Outcome.OK for x in report.tcp)
        emit(StageResult("TCP", Outcome.OK if successes else Outcome.FAILED,
                         f"Успешных handshake: {successes}/{len(report.tcp)}.",
                         {"attempts": [vars_for(a) for a in report.tcp]}, self._elapsed(started)))

    def _check_tls(self, addresses: list[str], domain: str, report: CheckReport, emit: ProgressCallback) -> None:
        started = time.perf_counter()
        reachable = [x.address for x in report.tcp if x.port == 443 and x.outcome is Outcome.OK]
        for address in self._unique(reachable):
            report.tls_with_sni.append(self._tls_attempt(address, domain))
            report.tls_without_sni.append(self._tls_attempt(address, None))
        successful = sum(x.outcome is Outcome.OK for x in report.tls_with_sni)
        outcome = Outcome.OK if successful else (Outcome.FAILED if reachable else Outcome.SKIPPED)
        emit(StageResult("TLS/SNI", outcome,
                         f"TLS с SNI: {successful}/{len(report.tls_with_sni)} успешно; контроль без SNI: "
                         f"{sum(x.outcome is Outcome.OK for x in report.tls_without_sni)}/{len(report.tls_without_sni)}.",
                         {"with_sni": [vars_for(a) for a in report.tls_with_sni], "without_sni": [vars_for(a) for a in report.tls_without_sni]},
                         self._elapsed(started)))

    def _check_http(self, domain: str, report: CheckReport, emit: ProgressCallback) -> None:
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=self.options.timeout_seconds, follow_redirects=False, trust_env=False,
                              headers={"User-Agent": self.options.user_agent}) as client:
                response = client.head(f"https://{domain}/")
                if response.status_code == 405:
                    response = client.get(f"https://{domain}/", headers={"Range": "bytes=0-2048"})
            report.http_status = response.status_code
            report.http_url = str(response.url)
            report.http_headers = {key.lower(): value for key, value in response.headers.items()}
            report.http_suspected_hijack = self._looks_hijacked(response)
            status = Outcome.WARNING if report.http_suspected_hijack else Outcome.OK
            emit(StageResult("HTTP", status, f"HTTPS HTTP {response.status_code}.",
                             {"url": report.http_url, "headers": report.http_headers, "suspected_hijack": report.http_suspected_hijack},
                             self._elapsed(started)))
        except httpx.HTTPError as exc:
            report.http_error = self._safe_error(exc)
            emit(StageResult("HTTP", Outcome.FAILED, f"HTTPS-запрос не выполнен: {report.http_error}", elapsed_ms=self._elapsed(started)))

    def _resolve_system(self, domain: str) -> list[str]:
        try:
            entries = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        except OSError:
            return []
        return self._unique(item[4][0] for item in entries)

    def _resolve_doh(self, endpoint: str, domain: str) -> list[str]:
        records: list[str] = []
        with httpx.Client(timeout=self.options.timeout_seconds, trust_env=False) as client:
            for record_type in ("A", "AAAA"):
                response = client.get(endpoint, params={"name": domain, "type": record_type},
                                      headers={"Accept": "application/dns-json"})
                response.raise_for_status()
                payload = response.json()
                for answer in payload.get("Answer", []):
                    value = answer.get("data", "")
                    try:
                        ipaddress.ip_address(value)
                        records.append(value)
                    except ValueError:
                        continue
        return self._unique(records)

    def _tcp_attempt(self, address: str, port: int) -> TcpAttempt:
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=self.options.timeout_seconds):
                return TcpAttempt(address, port, Outcome.OK, self._elapsed(started))
        except OSError as exc:
            kind = self._socket_error_kind(exc)
            return TcpAttempt(address, port, Outcome.FAILED, self._elapsed(started), kind, self._safe_error(exc))

    def _tls_attempt(self, address: str, sni: str | None) -> TlsAttempt:
        started = time.perf_counter()
        # Verification is intentionally disabled here: this probe isolates TLS transport/SNI
        # behaviour. HTTPX performs normal certificate validation in the application probe.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection((address, 443), timeout=self.options.timeout_seconds) as raw:
                with context.wrap_socket(raw, server_hostname=sni) as secure:
                    cipher = secure.cipher()
                    return TlsAttempt(address, sni, Outcome.OK, self._elapsed(started), tls_version=secure.version(),
                                      cipher=cipher[0] if cipher else None)
        except (OSError, ssl.SSLError) as exc:
            kind = "reset" if isinstance(exc, ConnectionResetError) else ("tls" if isinstance(exc, ssl.SSLError) else self._socket_error_kind(exc))
            return TlsAttempt(address, sni, Outcome.FAILED, self._elapsed(started), kind, self._safe_error(exc))

    @staticmethod
    def _looks_hijacked(response: httpx.Response) -> bool:
        location = response.headers.get("location", "").lower()
        server = response.headers.get("server", "").lower()
        markers = ("blocked", "blockpage", "warning", "captive", "intercept", "operator")
        return (response.status_code in {301, 302, 303, 307, 308} and any(x in location for x in markers)) or any(x in server for x in markers)

    @staticmethod
    def _normalise_domain(value: str) -> str:
        value = value.strip()
        if "://" in value:
            value = urlparse(value).hostname or ""
        value = value.rstrip(".").lower()
        if not value or len(value) > 253 or "/" in value or " " in value:
            raise ValueError("Введите корректное доменное имя, без пути и пробелов.")
        return value.encode("idna").decode("ascii")

    @staticmethod
    def _unique(values: object) -> list[str]:
        return list(dict.fromkeys(str(value) for value in values))

    @staticmethod
    def _elapsed(started: float) -> float:
        return round((time.perf_counter() - started) * 1000, 1)

    @staticmethod
    def _socket_error_kind(exc: OSError) -> str:
        if isinstance(exc, TimeoutError) or getattr(exc, "errno", None) in {10060, 110}:
            return "timeout"
        if isinstance(exc, ConnectionResetError) or getattr(exc, "errno", None) in {10054, 104}:
            return "reset"
        if getattr(exc, "errno", None) in {10065, 113}:
            return "unreachable"
        return "socket"

    @staticmethod
    def _safe_error(exc: BaseException) -> str:
        message = str(exc).strip().replace("\n", " ")
        return message[:240] or exc.__class__.__name__


def vars_for(item: object) -> dict[str, object]:
    """slots dataclasses do not expose __dict__; serialise their public fields."""
    from dataclasses import asdict
    return asdict(item)
