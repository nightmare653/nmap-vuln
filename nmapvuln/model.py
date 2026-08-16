"""Data model shared by the parsers, validators, matchers and reporters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


def severity_from_score(score: Optional[float]) -> str:
    """CVSS v3 qualitative rating. Used when a CVE record carries no baseSeverity."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


@dataclass
class Script:
    """One NSE script result attached to a host or a port."""

    id: str
    output: str = ""

    def cves(self) -> list[str]:
        return sorted({m.upper() for m in CVE_RE.findall(self.output)})


@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    ostype: str = ""
    tunnel: str = ""
    method: str = ""  # "table" = guessed from port number, "probed" = -sV fingerprint
    conf: int = 0  # nmap's own 0-10 confidence in the fingerprint
    cpes: list[str] = field(default_factory=list)

    @property
    def probed(self) -> bool:
        return self.method == "probed"

    @property
    def banner(self) -> str:
        bits = [b for b in (self.product, self.version, self.extrainfo) if b]
        return " ".join(bits) or self.name or "unknown"


@dataclass
class Port:
    protocol: str = "tcp"
    portid: int = 0
    state: str = "unknown"
    reason: str = ""
    service: Service = field(default_factory=Service)
    scripts: list[Script] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.portid}/{self.protocol}"

    @property
    def is_open(self) -> bool:
        return self.state.startswith("open")


@dataclass
class Host:
    address: str = ""
    addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    os_matches: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)  # hostscript results
    extraports: dict[str, int] = field(default_factory=dict)  # state -> count
    source: str = ""  # file this host came from

    @property
    def label(self) -> str:
        if self.hostnames:
            return f"{self.address} ({self.hostnames[0]})"
        return self.address

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]


@dataclass
class ScanRun:
    """One `nmaprun` — i.e. one scan, from one file."""

    source: str = ""
    fmt: str = ""  # xml | gnmap | nmap
    nmap_version: str = ""
    args: str = ""
    start: str = ""
    end: str = ""
    elapsed: str = ""
    completed: bool = False  # did the scan reach a clean end?
    hosts: list[Host] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def scan_types(self) -> set[str]:
        """Rough flags recovered from the command line, e.g. {'-sV', '-sU'}."""
        found = set()
        for flag in ("-sV", "-sC", "-sU", "-sS", "-sT", "-A", "-Pn", "-p-", "--script", "-O"):
            if flag in (self.args or ""):
                found.add(flag)
        return found


@dataclass
class Finding:
    """A single vulnerability tied to one service on one host."""

    host: str = ""
    hostnames: str = ""
    port: str = ""
    service: str = ""
    product: str = ""
    cve: str = ""
    cvss: Optional[float] = None
    cvss_vector: str = ""
    severity: str = "UNKNOWN"
    published: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""  # nvd | vulners | nse
    confidence: str = "medium"  # high | medium | low
    matched_on: str = ""  # the CPE or keyword that produced the match
    exploit_known: bool = False
    scan_file: str = ""

    @property
    def sort_key(self) -> tuple:
        return (
            -SEVERITY_ORDER.get(self.severity, 0),
            -(self.cvss or 0.0),
            -CONFIDENCE_ORDER.get(self.confidence, 0),
            self.host,
            self.cve,
        )


@dataclass
class Weakness:
    """A non-CVE finding: weak crypto, a misconfiguration, or risky exposure.

    Kept separate from Finding because it is evidence-based rather than
    version-based — it comes from what the scan observed, not from matching a
    banner against a database, so it carries no CVE and no CVSS score.
    """

    host: str = ""
    hostnames: str = ""
    port: str = ""
    service: str = ""
    rule_id: str = ""
    title: str = ""
    severity: str = "MEDIUM"
    category: str = ""
    evidence: str = ""
    recommendation: str = ""
    source_script: str = ""
    scan_file: str = ""

    @property
    def sort_key(self) -> tuple:
        return (-SEVERITY_ORDER.get(self.severity, 0), self.host, self.port, self.rule_id)


@dataclass
class ValidationIssue:
    """Something questionable about the scan itself, not about the target."""

    severity: str = "info"  # error | warn | info
    code: str = ""
    message: str = ""
    scope: str = ""  # file | scan | host | port
    target: str = ""

    @property
    def sort_key(self) -> tuple:
        rank = {"error": 0, "warn": 1, "info": 2}
        return (rank.get(self.severity, 3), self.code, self.target)


@dataclass
class Analysis:
    """Everything the run produced, ready to be reported."""

    scans: list[ScanRun] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    weaknesses: list[Weakness] = field(default_factory=list)
    skipped_services: list[str] = field(default_factory=list)
    queried: int = 0
    offline: bool = False

    @property
    def hosts(self) -> list[Host]:
        return [h for s in self.scans for h in s.hosts]

    def counts_by_severity(self) -> dict[str, int]:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for f in self.findings:
            out[f.severity if f.severity in out else "UNKNOWN"] += 1
        return out

    def weakness_counts_by_severity(self) -> dict[str, int]:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for w in self.weaknesses:
            out[w.severity if w.severity in out else "UNKNOWN"] += 1
        return out

    def combined_counts(self) -> dict[str, int]:
        """CVE findings and non-CVE weaknesses together, for the summary cards."""
        cve, weak = self.counts_by_severity(), self.weakness_counts_by_severity()
        return {k: cve[k] + weak[k] for k in cve}
