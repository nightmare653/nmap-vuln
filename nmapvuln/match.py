"""Turn detected services into vulnerability findings.

Matching quality is the whole game here. The order of preference is:

  high   — nmap emitted a CPE with a version; NVD does the range matching.
  medium — no CPE, but the product maps to a known vendor:product and nmap
           probed a version, so we synthesise the CPE ourselves.
  low    — a product with no version, or a keyword search. These are
           "this software has had CVEs", not "this host is vulnerable", and
           they are excluded unless explicitly requested.

Findings already present in the scan (vulners/vulscan/vuln NSE output) are
extracted too, and are trusted at the level nmap reported them.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Optional

from .model import (
    CVE_RE,
    Analysis,
    Finding,
    Host,
    Port,
    ScanRun,
    severity_from_score,
)
from .sources import NVDClient, VulnersClient, finding_from_nvd

# nmap product strings do not match NVD vendor/product names. This covers the
# services that actually show up in an external scan; anything unmapped falls
# through to a keyword search.
PRODUCT_CPE = {
    "openssh": "openbsd:openssh",
    "apache httpd": "apache:http_server",
    "apache tomcat": "apache:tomcat",
    "apache tomcat/coyote jsp engine": "apache:tomcat",
    "nginx": "nginx:nginx",
    "microsoft iis httpd": "microsoft:internet_information_services",
    "lighttpd": "lighttpd:lighttpd",
    "jetty": "eclipse:jetty",
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql db": "postgresql:postgresql",
    "postgresql": "postgresql:postgresql",
    "microsoft sql server": "microsoft:sql_server",
    "mongodb": "mongodb:mongodb",
    "redis key-value store": "redis:redis",
    "redis": "redis:redis",
    "memcached": "memcached:memcached",
    "elasticsearch": "elastic:elasticsearch",
    "vsftpd": "beasts:vsftpd",
    "proftpd": "proftpd:proftpd",
    "pure-ftpd": "pureftpd:pure-ftpd",
    "filezilla ftpd": "filezilla-project:filezilla_server",
    "exim smtpd": "exim:exim",
    "postfix smtpd": "postfix:postfix",
    "sendmail": "sendmail:sendmail",
    "dovecot imapd": "dovecot:dovecot",
    "dovecot pop3d": "dovecot:dovecot",
    "samba smbd": "samba:samba",
    "isc bind": "isc:bind",
    "bind": "isc:bind",
    "dnsmasq": "thekelleys:dnsmasq",
    "openssl": "openssl:openssl",
    "php": "php:php",
    "php cgi": "php:php",
    "python": "python:python",
    "node.js": "nodejs:node.js",
    "node.js express framework": "openjsf:express",
    "dropbear sshd": "dropbear_ssh_project:dropbear_ssh",
    "openvpn": "openvpn:openvpn",
    "squid http proxy": "squid-cache:squid",
    "haproxy": "haproxy:haproxy",
    "varnish": "varnish-cache:varnish_cache",
    "jenkins": "jenkins:jenkins",
    "gitlab": "gitlab:gitlab",
    "grafana": "grafana:grafana",
    "wordpress": "wordpress:wordpress",
    "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
    "rabbitmq": "pivotal_software:rabbitmq",
    "docker": "docker:docker",
    "kubernetes": "kubernetes:kubernetes",
    "vmware esxi": "vmware:esxi",
    "vmware authentication daemon": "vmware:workstation",
    "microsoft windows rpc": "microsoft:windows",
    "microsoft terminal services": "microsoft:remote_desktop_services",
    "microsoft ftpd": "microsoft:internet_information_services",
    "microsoft exchange": "microsoft:exchange_server",
    "webmin": "webmin:webmin",
    "cups": "apple:cups",
    "ntpd": "ntp:ntp",
    "snmpd": "net-snmp:net-snmp",
    "net-snmp": "net-snmp:net-snmp",
    "tightvnc": "tightvnc:tightvnc",
    "realvnc": "realvnc:vnc",
    "gnu inetutils ftpd": "gnu:inetutils",
    "openresty": "openresty:openresty",
}

_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._\-]*$")
# Trailing distro packaging noise: "1.2.3-1ubuntu2.4", "2.4.6 (Ubuntu)"
_DISTRO_SUFFIX = re.compile(r"[-+~](?:ubuntu|deb|el|fc|centos|rhel|p?\d+ubuntu).*$", re.I)


@dataclass(frozen=True)
class ServiceQuery:
    """A unique thing to look up. Many host/port pairs collapse into one query."""

    cpe23: str = ""
    product: str = ""
    version: str = ""
    keyword: str = ""
    confidence: str = "medium"

    @property
    def label(self) -> str:
        return self.cpe23 or self.keyword or f"{self.product} {self.version}".strip()


def cpe22_to_23(cpe: str) -> str:
    """cpe:/a:apache:http_server:2.4.49 -> cpe:2.3:a:apache:http_server:2.4.49:*:*…"""
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        parts += ["*"] * (13 - len(parts))
        return ":".join(parts[:13])
    if not cpe.startswith("cpe:/"):
        return ""
    body = cpe[len("cpe:/") :]
    fields = body.split(":")
    fields += [""] * (7 - len(fields))
    part, vendor, product, version, update, edition, language = fields[:7]
    out = ["cpe", "2.3", part or "*", vendor or "*", product or "*", version or "*"]
    out += [update or "*", edition or "*", language or "*", "*", "*", "*", "*"]
    return ":".join(out)


def _clean_version(version: str) -> str:
    """'8.2p1 Ubuntu 4ubuntu0.5' -> '8.2p1'.

    Only the upstream version is usable for CPE matching; the distro packaging
    suffix that follows it is meaningless to NVD.
    """
    version = version.strip().split()[0] if version.strip() else ""
    version = _DISTRO_SUFFIX.sub("", version)
    version = version.rstrip(".-")
    return version if _VERSION_RE.match(version) else ""


def _cpe_has_version(cpe23: str) -> bool:
    parts = cpe23.split(":")
    return len(parts) > 5 and parts[5] not in ("*", "-", "")


def build_queries(port: Port) -> list[ServiceQuery]:
    """Decide what to look up for one open port. Empty means 'not matchable'."""
    svc = port.service
    if not svc:
        return []
    if svc.name == "tcpwrapped":
        return []

    version = _clean_version(svc.version)
    queries: list[ServiceQuery] = []
    seen: set[str] = set()

    # 1. CPEs nmap gave us, preferring application CPEs over OS ones.
    for raw in svc.cpes:
        cpe23 = cpe22_to_23(raw)
        if not cpe23 or cpe23 in seen:
            continue
        parts = cpe23.split(":")
        if parts[2] == "h":  # hardware CPEs are not useful for service CVEs
            continue
        if not _cpe_has_version(cpe23) and version:
            parts[5] = version
            cpe23 = ":".join(parts)
        seen.add(cpe23)
        queries.append(
            ServiceQuery(
                cpe23=cpe23,
                product=svc.product or parts[4],
                version=version or (parts[5] if parts[5] != "*" else ""),
                confidence="high" if _cpe_has_version(cpe23) else "low",
            )
        )

    if queries:
        return queries

    # 2. No CPE from nmap — synthesise one from a known product name.
    if svc.product:
        key = svc.product.strip().lower()
        vendor_product = PRODUCT_CPE.get(key)
        if vendor_product is None:
            # "Apache httpd 2.4.49" style strings sometimes carry the version.
            vendor_product = PRODUCT_CPE.get(re.sub(r"\s+[\d.]+$", "", key))
        if vendor_product and version:
            cpe23 = f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"
            return [
                ServiceQuery(
                    cpe23=cpe23, product=svc.product, version=version, confidence="medium"
                )
            ]
        if vendor_product:
            cpe23 = f"cpe:2.3:a:{vendor_product}:*:*:*:*:*:*:*:*"
            return [
                ServiceQuery(cpe23=cpe23, product=svc.product, version="", confidence="low")
            ]

        # 3. Unknown product: keyword search. Skip products that are really just a
        # version blob ("2-4 (RPC #100000)") — those produce pure noise.
        if not re.search(r"[A-Za-z]{3}", svc.product):
            return []
        keyword = f"{svc.product} {version}".strip()
        return [
            ServiceQuery(
                keyword=keyword,
                product=svc.product,
                version=version,
                confidence="medium" if version else "low",
            )
        ]

    return []


class Matcher:
    def __init__(
        self,
        nvd: Optional[NVDClient],
        vulners: Optional[VulnersClient],
        include_unversioned: bool = False,
        min_cvss: float = 0.0,
        verbose: bool = False,
    ):
        self.nvd = nvd
        self.vulners = vulners
        self.include_unversioned = include_unversioned
        self.min_cvss = min_cvss
        self.verbose = verbose
        self._cve_cache: dict[str, list[dict]] = {}

    # -- public ----------------------------------------------------------

    def run(self, analysis: Analysis) -> None:
        findings: list[Finding] = []
        targets: list[tuple[ScanRun, Host, Port, ServiceQuery]] = []

        for scan in analysis.scans:
            for host in scan.hosts:
                for port in host.open_ports:
                    findings.extend(self._nse_findings(scan, host, port))
                    for query in build_queries(port):
                        if query.confidence == "low" and not self.include_unversioned:
                            analysis.skipped_services.append(
                                f"{host.label} {port.key} {port.service.banner} "
                                f"(no version — use --include-unversioned)"
                            )
                            continue
                        targets.append((scan, host, port, query))

        unique = sorted({q.label for _s, _h, _p, q in targets})
        if unique and self.nvd:
            print(
                f"[*] {len(unique)} unique service signatures to look up "
                f"across {len(targets)} host/port pairs",
                file=sys.stderr,
            )

        for scan, host, port, query in targets:
            findings.extend(self._lookup(scan, host, port, query))

        analysis.queried = len(unique)
        analysis.findings = self._dedupe(findings)
        analysis.findings.sort(key=lambda f: f.sort_key)

    # -- internals -------------------------------------------------------

    def _lookup(self, scan: ScanRun, host: Host, port: Port, query: ServiceQuery) -> list[Finding]:
        out: list[Finding] = []
        degraded = scan.fmt != "xml"

        confidence = query.confidence
        if degraded and confidence == "high":
            confidence = "medium"

        for cve in self._nvd_records(query):
            (cve_id, score, vector, severity, published, description, refs) = finding_from_nvd(cve)
            if not cve_id:
                continue
            if self.min_cvss and (score or 0.0) < self.min_cvss:
                continue
            out.append(
                Finding(
                    host=host.address,
                    hostnames=", ".join(host.hostnames),
                    port=port.key,
                    service=port.service.name,
                    product=port.service.banner,
                    cve=cve_id,
                    cvss=score,
                    cvss_vector=vector,
                    severity=severity,
                    published=published,
                    description=description,
                    references=refs,
                    source="nvd",
                    confidence=confidence,
                    matched_on=query.label,
                    scan_file=scan.source,
                )
            )

        for item in self._vulners_records(query):
            cve_ids = sorted({m.upper() for m in CVE_RE.findall(item.get("id", ""))}) or sorted(
                {m.upper() for m in CVE_RE.findall(" ".join(item.get("cvelist", []) or []))}
            )
            score = ((item.get("cvss") or {}).get("score")) or None
            exploit = str(item.get("type", "")).lower() in ("exploitdb", "packetstorm", "zdt")
            for cve_id in cve_ids or [item.get("id", "")]:
                if not cve_id:
                    continue
                if self.min_cvss and (score or 0.0) < self.min_cvss:
                    continue
                out.append(
                    Finding(
                        host=host.address,
                        hostnames=", ".join(host.hostnames),
                        port=port.key,
                        service=port.service.name,
                        product=port.service.banner,
                        cve=cve_id,
                        cvss=score,
                        cvss_vector="",
                        severity=severity_from_score(score),
                        published=(item.get("published") or "")[:10],
                        description=(item.get("title") or "").strip(),
                        references=[f"https://vulners.com/{item.get('type')}/{item.get('id')}"]
                        if item.get("id")
                        else [],
                        source="vulners",
                        confidence=confidence,
                        matched_on=query.label,
                        exploit_known=exploit,
                        scan_file=scan.source,
                    )
                )
        return out

    def _nvd_records(self, query: ServiceQuery) -> list[dict]:
        if self.nvd is None:
            return []
        key = query.label
        if key in self._cve_cache:
            return self._cve_cache[key]
        if query.cpe23:
            records = self.nvd.by_cpe(query.cpe23)
        elif query.keyword:
            records = self.nvd.by_keyword(query.keyword)
        else:
            records = []
        self._cve_cache[key] = records
        return records

    def _vulners_records(self, query: ServiceQuery) -> list[dict]:
        if self.vulners is None or not self.vulners.enabled:
            return []
        if not query.product or not query.version:
            return []
        return self.vulners.by_software(query.product, query.version)

    def _nse_findings(self, scan: ScanRun, host: Host, port: Port) -> list[Finding]:
        """Pull CVEs that the scan itself already reported."""
        out: list[Finding] = []
        for script in port.scripts:
            vulnerable = "VULNERABLE" in script.output.upper()
            for cve_id in script.cves():
                score = _score_near(script.output, cve_id)
                # Honour --min-cvss where the script gave us a score. Scoreless
                # entries are kept: the scan itself raised them, and silently
                # dropping something nmap flagged would be the worse failure.
                if self.min_cvss and score is not None and score < self.min_cvss:
                    continue
                out.append(
                    Finding(
                        host=host.address,
                        hostnames=", ".join(host.hostnames),
                        port=port.key,
                        service=port.service.name,
                        product=port.service.banner,
                        cve=cve_id,
                        cvss=score,
                        severity=severity_from_score(score),
                        description=f"Reported by NSE script {script.id}"
                        + (" — script marked the host VULNERABLE" if vulnerable else ""),
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        source="nse",
                        confidence="high" if vulnerable else "medium",
                        matched_on=script.id,
                        exploit_known="EXPLOIT" in script.output.upper(),
                        scan_file=scan.source,
                    )
                )
        return out

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """One row per host+port+CVE, merging what each source knows best.

        The sources are complementary rather than competing: NVD supplies the
        authoritative score, vector and description, while NSE and Vulners
        supply exploit availability and the fact that the scan itself flagged
        it. Picking a single winner throws away half of that, so the records
        are merged field by field and every contributing source is credited.
        """
        merged: dict[tuple, Finding] = {}
        conf_rank = {"high": 3, "medium": 2, "low": 1}

        for f in findings:
            key = (f.host, f.port, f.cve)
            current = merged.get(key)
            if current is None:
                merged[key] = f
                continue

            if current.cvss is None and f.cvss is not None:
                current.cvss = f.cvss
                current.severity = f.severity
            if not current.cvss_vector:
                current.cvss_vector = f.cvss_vector
            if not current.published:
                current.published = f.published
            # NVD writes real prose; the NSE record is a one-line stub.
            if f.source == "nvd" and len(f.description) > len(current.description):
                current.description = f.description
            elif not current.description:
                current.description = f.description

            for ref in f.references:
                if ref not in current.references:
                    current.references.append(ref)
            current.references = current.references[:8]

            current.exploit_known = current.exploit_known or f.exploit_known
            if conf_rank.get(f.confidence, 0) > conf_rank.get(current.confidence, 0):
                current.confidence = f.confidence
            if f.source not in current.source.split("+"):
                current.source = "+".join(sorted(set(current.source.split("+") + [f.source])))
            if current.matched_on != f.matched_on and f.matched_on not in current.matched_on:
                current.matched_on = f"{current.matched_on}, {f.matched_on}"

            if current.severity == "UNKNOWN" and current.cvss is not None:
                current.severity = severity_from_score(current.cvss)

        return list(merged.values())


def _score_near(text: str, cve_id: str) -> Optional[float]:
    """vulners NSE prints 'CVE-2021-1234  7.5  https://…' — grab that score."""
    for line in text.splitlines():
        if cve_id.upper() in line.upper():
            m = re.search(re.escape(cve_id) + r"\s+([0-9]{1,2}\.[0-9])", line, re.I)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    return None
    return None
