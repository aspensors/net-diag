"""Evidence-based classification. It makes no claims that cannot be inferred from probes."""

from __future__ import annotations

from .models import CheckReport, Outcome, Verdict, VerdictKind


def build_verdict(report: CheckReport) -> Verdict:
    """Derive the most specific supported finding, preferring concrete application evidence."""
    system = set(report.system_ips)
    doh = {ip for ips in report.doh_ips.values() for ip in ips}
    dns_disjoint = bool(system and doh and system.isdisjoint(doh))
    system_tls_ok = any(item.outcome is Outcome.OK and item.address in system for item in report.tls_with_sni)
    doh_tls_ok = any(item.outcome is Outcome.OK and item.address in doh for item in report.tls_with_sni)
    failed_system_tls = {item.address for item in report.tls_with_sni
                         if item.address in system and item.outcome is Outcome.FAILED}
    all_system_tls_failed = bool(system) and system.issubset(failed_system_tls) and not system_tls_ok

    # A different answer alone is expected for many CDN and GeoDNS deployments.
    # Require actual failed probes for every system address. max_ips can leave
    # some addresses untested; absence of a success is not evidence of failure.
    if dns_disjoint and doh_tls_ok and all_system_tls_failed:
        return Verdict(
            VerdictKind.DNS_POISONING,
            "medium",
            "На всех проверенных адресах system DNS TLS не проходит, тогда как DoH-маршрут проходит. "
            "Это расхождение маршрутов, а не доказанная подмена DNS.",
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

    tcp_443 = [item for item in report.tcp if item.port == 443]
    tcp_ok = any(item.outcome is Outcome.OK for item in tcp_443)
    tls_ok = any(item.outcome is Outcome.OK for item in report.tls_with_sni)
    application_reachable = report.http_status is not None or tls_ok
    tcp_blocked = bool(tcp_443) and not tcp_ok and all(
        item.outcome is Outcome.FAILED and item.error_kind in {"timeout", "unreachable", "reset"}
        for item in tcp_443
    )
    if tcp_blocked and not application_reachable:
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
    failed_sni_addresses = {x.address for x in report.tls_with_sni if x.outcome is Outcome.FAILED}
    control_addresses = {x.address for x in report.tls_without_sni if x.outcome is Outcome.OK}
    paired_control_ok = bool(failed_sni_addresses & control_addresses)
    if tcp_ok and sni_failed and paired_control_ok and not application_reachable:
        return Verdict(
            VerdictKind.DPI_SNI,
            "medium",
            "TCP работает; есть IP, на котором TLS с целевым SNI не проходит, а контроль без SNI проходит. "
            "Это наблюдение совместимо с несколькими причинами и не доказывает наличие DPI.",
            [
                "Исключите несовместимость TLS у сервера и проверьте с другой доверенной сети.",
                "Передайте результат владельцу сети/сервиса; используйте только разрешённые вашей политикой защищённые каналы.",
            ],
        )

    if application_reachable:
        detail = (
            " System DNS и DoH дали разные адреса; для CDN/GeoDNS это может быть нормальным распределением."
            if dns_disjoint else ""
        )
        return Verdict(
            VerdictKind.CLEAN,
            "medium",
            "Есть успешная TLS/SNI-проба или HTTPS-ответ без обнаруженных маркеров страницы-посредника. "
            "Это не подтверждает успешность всех этапов или отсутствие фильтрации." + detail,
            ["Сохраните отчёт как базовую точку для последующих сравнений."],
        )

    return Verdict(
        VerdictKind.INCONCLUSIVE,
        "low",
        "Недостаточно успешных проб для надёжной классификации причины отказа.",
        ["Повторите проверку позже или из другой сети и сравните экспортированные отчёты."],
    )
