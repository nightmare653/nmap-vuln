"""Scan validation.

This answers "can I trust this scan?" — separately from "is the target
vulnerable?". A scan that never ran version detection, got cut off halfway, or
came back all-filtered will produce a thin vulnerability report for reasons
that have nothing to do with the target's actual security posture, and that
distinction has to be visible in the report.
"""

from __future__ import annotations

from collections import defaultdict

from .model import Analysis, Host, ScanRun, ValidationIssue

# Ports where a missing product string is expected rather than suspicious.
_QUIET_SERVICES = {"tcpwrapped", "unknown", ""}


def validate(analysis: Analysis) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for scan in analysis.scans:
        issues.extend(_validate_scan(scan))
        for host in scan.hosts:
            issues.extend(_validate_host(host, scan))
    issues.extend(_validate_cross_file(analysis))
    issues.sort(key=lambda i: i.sort_key)
    return issues


def _add(issues, severity, code, message, scope, target):
    issues.append(
        ValidationIssue(severity=severity, code=code, message=message, scope=scope, target=target)
    )


def _validate_scan(scan: ScanRun) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    name = scan.source

    for err in scan.parse_errors:
        _add(issues, "error", "PARSE_ERROR", err, "file", name)

    if not scan.completed:
        _add(
            issues,
            "error",
            "SCAN_INCOMPLETE",
            "Scan did not complete cleanly. Results are partial — hosts or ports "
            "after the cut-off point were never tested.",
            "scan",
            name,
        )

    if scan.fmt != "xml":
        _add(
            issues,
            "warn",
            "LOSSY_FORMAT",
            f"Parsed from {scan.fmt!r} output, which carries no CPEs and no fingerprint "
            "confidence. CVE matching falls back to keyword lookups. Re-run with -oX for "
            "reliable results.",
            "file",
            name,
        )

    args = scan.args or ""
    flags = scan.scan_types

    if args:
        if not ({"-sV", "-A"} & flags):
            _add(
                issues,
                "warn",
                "NO_VERSION_DETECTION",
                "No -sV/-A in the command line, so services were guessed from the port "
                "number alone. Version-based CVE matching is not possible — re-scan with -sV.",
                "scan",
                name,
            )
        if not ({"-sC", "--script", "-A"} & flags):
            _add(
                issues,
                "info",
                "NO_NSE",
                "No NSE scripts were run (-sC/--script). Script-derived findings such as "
                "vulners, ssl-* and http-* checks are absent.",
                "scan",
                name,
            )
        if "-p" not in args:
            _add(
                issues,
                "info",
                "DEFAULT_PORT_RANGE",
                "No -p given, so only nmap's top 1000 TCP ports were scanned. Services on "
                "other ports are untested, not proven absent.",
                "scan",
                name,
            )
        if "-sU" not in flags:
            _add(
                issues,
                "info",
                "NO_UDP",
                "TCP only — no UDP scan (-sU). UDP services (SNMP, DNS, NTP, IKE) are untested.",
                "scan",
                name,
            )
        if "-T5" in args:
            _add(
                issues,
                "warn",
                "AGGRESSIVE_TIMING",
                "-T5 was used. At this rate packets get dropped and open ports are "
                "routinely missed; a negative result here is weak evidence.",
                "scan",
                name,
            )
        if "--max-retries 0" in args or "--max-retries=0" in args:
            _add(
                issues,
                "warn",
                "NO_RETRIES",
                "--max-retries 0 disables retransmission. Ports may be reported closed "
                "purely because of packet loss.",
                "scan",
                name,
            )
        if "-Pn" in flags:
            _add(
                issues,
                "info",
                "PN_USED",
                "-Pn was used, so every host is assumed up. 'Host up' here is an "
                "assumption, not a measurement.",
                "scan",
                name,
            )
    else:
        _add(
            issues,
            "info",
            "NO_COMMAND_LINE",
            "Command line not recorded in this file, so scan coverage could not be assessed.",
            "file",
            name,
        )

    if not scan.hosts:
        _add(issues, "warn", "NO_HOSTS", "No hosts were parsed from this file.", "file", name)

    return issues


def _validate_host(host: Host, scan: ScanRun) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    target = host.label or "(unknown host)"

    if host.status == "down":
        _add(issues, "info", "HOST_DOWN", "Host reported down; nothing was tested.", "host", target)
        return issues

    open_ports = host.open_ports
    filtered = host.extraports.get("filtered", 0)

    if not open_ports:
        if filtered:
            _add(
                issues,
                "warn",
                "ALL_FILTERED",
                f"Host is up but every probed port came back filtered ({filtered} ports). "
                "A firewall or rate limiter is between the scanner and the target — this "
                "is not evidence that the host has no services.",
                "host",
                target,
            )
        else:
            _add(
                issues,
                "warn",
                "HOST_UP_NO_OPEN",
                "Host is up but no open ports were found in the scanned range.",
                "host",
                target,
            )
        return issues

    no_product, no_version, low_conf, wrapped = [], [], [], []

    for port in open_ports:
        svc = port.service
        if svc.name == "tcpwrapped":
            wrapped.append(port.key)
            continue
        if not svc.product:
            if svc.name not in _QUIET_SERVICES:
                no_product.append(f"{port.key} ({svc.name})")
            else:
                no_product.append(port.key)
            continue
        if not svc.version:
            no_version.append(f"{port.key} {svc.product}")
        if svc.conf and svc.conf < 7:
            low_conf.append(f"{port.key} {svc.product} (conf {svc.conf}/10)")

    if wrapped:
        _add(
            issues,
            "warn",
            "TCPWRAPPED",
            "Ports answered the TCP handshake then closed without a banner: "
            + ", ".join(wrapped)
            + ". This usually means a wrapper or filtering device, so the real service "
            "behind them is unidentified.",
            "host",
            target,
        )
    if no_product:
        _add(
            issues,
            "warn",
            "NO_PRODUCT",
            "Open ports with no product identified, so they cannot be CVE-matched: "
            + ", ".join(no_product[:12])
            + ("…" if len(no_product) > 12 else ""),
            "host",
            target,
        )
    if no_version:
        _add(
            issues,
            "warn",
            "NO_VERSION",
            "Product identified but no version, so only unversioned (low-confidence) "
            "matching is possible: " + ", ".join(no_version[:12])
            + ("…" if len(no_version) > 12 else ""),
            "host",
            target,
        )
    if low_conf:
        _add(
            issues,
            "warn",
            "LOW_CONFIDENCE_FINGERPRINT",
            "nmap itself was unsure of these fingerprints; treat any CVE matched from "
            "them as unconfirmed: " + ", ".join(low_conf[:12])
            + ("…" if len(low_conf) > 12 else ""),
            "host",
            target,
        )

    return issues


def _validate_cross_file(analysis: Analysis) -> list[ValidationIssue]:
    """Compare repeat scans of the same host and flag results that disagree."""
    issues: list[ValidationIssue] = []
    by_host: dict[str, list[tuple[str, Host]]] = defaultdict(list)

    for scan in analysis.scans:
        for host in scan.hosts:
            if host.address:
                by_host[host.address].append((scan.source, host))

    for address, entries in sorted(by_host.items()):
        if len(entries) < 2:
            continue

        states: dict[str, set[str]] = defaultdict(set)
        versions: dict[str, set[str]] = defaultdict(set)
        for _src, host in entries:
            for port in host.ports:
                states[port.key].add(port.state)
                if port.service.product:
                    versions[port.key].add(f"{port.service.product} {port.service.version}".strip())

        conflicting = sorted(k for k, v in states.items() if len({s.split("|")[0] for s in v}) > 1)
        drifting = sorted(k for k, v in versions.items() if len(v) > 1)

        _add(
            issues,
            "info",
            "DUPLICATE_HOST",
            f"Host appears in {len(entries)} scan files: "
            + ", ".join(sorted({e[0] for e in entries}))
            + ". Findings were merged and deduplicated.",
            "host",
            address,
        )

        if conflicting:
            _add(
                issues,
                "warn",
                "STATE_CONFLICT",
                "Port state disagrees between scans of the same host on "
                + ", ".join(conflicting[:12])
                + ("…" if len(conflicting) > 12 else "")
                + ". One of the scans was affected by filtering, rate limiting or a "
                "genuine change on the target — re-scan to settle it.",
                "host",
                address,
            )
        if drifting:
            _add(
                issues,
                "warn",
                "VERSION_CONFLICT",
                "Detected service version differs between scans on "
                + ", ".join(drifting[:12])
                + ("…" if len(drifting) > 12 else "")
                + ". Findings below may be matched against a stale version.",
                "host",
                address,
            )

    return issues


def confidence_penalty(scan: ScanRun) -> bool:
    """True when a scan's provenance means every finding from it is downgraded."""
    return scan.fmt != "xml" or not scan.completed
