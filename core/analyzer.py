"""Evidence-based classification. It makes no claims that cannot be inferred from probes."""

from __future__ import annotations

import ipaddress

from .models import CheckReport, Outcome, Verdict, VerdictKind


def build_verdict(report: CheckReport) -> Verdict:
    """Derive the most specific supported finding, preferring concrete application evidence."""
    system = set(report.system_ips)
    doh = {ip for ips in report.doh_ips.values() for ip in ips}
    dns_disjoint = bool(system and doh and system.isdisjoint(doh))
    system_tls_ok = any(item.outcome is Outcome.OK and item.address in system for item in report.tls_with_sni)
    doh_tls_ok = any(item.outcome is Outcome.OK and item.address in doh for item in report.tls_with_sni)
    system_has_only_non_global = bool(system) and all(not ipaddress.ip_address(ip).is_global for ip in system)

    # A different answer alone is expected for many CDN and GeoDNS deployments.
    # Classify it as poisoning only when the alternate DoH route completes TLS
    # while every locally resolved route fails, or when local DNS returns solely
    # non-global addresses while DoH provides public ones.
    if dns_disjoint and ((doh_tls_ok and not system_tls_ok) or (system_has_only_non_global and doh_tls_ok)):
        return Verdict(
            VerdictKind.DNS_POISONING,
            "medium",
            "Локальный DNS вернул адреса, для которых TLS к целевому имени не проходит, тогда как DoH-маршрут проходит.",
            [
                "Сверьте адреса с авторитетной DNS-зоной или сетью, которой доверяете.",
                "Рассмотрите включение DoH/DoT у доверенного резолвера согласно политике вашей сети.",
            ],
        )

    if report.http_suspected_hijack:
        return Verdict(
            VerdictKind.HTTP_HIJACK,
            "medium",
            "HTTP-ответ содержит признаки неожиданного редиректа или страницы-посредника.",
            [
                "Проверьте Location, Server и сертификат в экспортированном отчёте.",
                "Сравните результат из другой доверенной сети и обратитесь к администратору сети.",
            ],
        )

    tcp_ok = any(item.outcome is Outcome.OK for item in report.tcp if item.port == 443)
    tcp_blocked = report.tcp and not tcp_ok and all(
        item.error_kind in {"timeout", "unreachable", "reset"} for item in report.tcp if item.port == 443
    )
    if tcp_blocked:
        return Verdict(
            VerdictKind.TCP_DROP,
            "medium",
            "TCP-соединение к порту 443 не установлено: наблюдаются таймауты, сбросы или недостижимость.",
            [
                "Проверьте маршрут, локальный firewall и доступность адреса из другой сети.",
                "Передайте отчёт сетевому администратору; отдельно проверьте правила ACL/маршрутизации.",
            ],
        )

    sni_failed = bool(report.tls_with_sni) and not any(x.outcome is Outcome.OK for x in report.tls_with_sni)
    control_ok = any(x.outcome is Outcome.OK for x in report.tls_without_sni)
    if tcp_ok and sni_failed and control_ok:
        return Verdict(
            VerdictKind.DPI_SNI,
            "medium",
            "TCP работает, но TLS с целевым SNI не проходит, тогда как контрольный TLS к тому же IP проходит.",
            [
                "Исключите несовместимость TLS у сервера и проверьте с другой доверенной сети.",
                "Передайте результат владельцу сети/сервиса; используйте только разрешённые вашей политикой защищённые каналы.",
            ],
        )

    if report.http_status is not None or any(x.outcome is Outcome.OK for x in report.tls_with_sni):
        detail = (
            " System DNS и DoH дали разные адреса; для CDN/GeoDNS это может быть нормальным распределением."
            if dns_disjoint else ""
        )
        return Verdict(
            VerdictKind.CLEAN,
            "high",
            "Проверенные DNS, TCP, TLS/SNI и HTTP-пробы не показали явных признаков фильтрации." + detail,
            ["Сохраните отчёт как базовую точку для последующих сравнений."],
        )

    return Verdict(
        VerdictKind.INCONCLUSIVE,
        "low",
        "Недостаточно успешных проб для надёжной классификации причины отказа.",
        ["Повторите проверку позже или из другой сети и сравните экспортированные отчёты."],
    )
