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
    "openssh": "a:openbsd:openssh",
    "apache httpd": "a:apache:http_server",
    "apache tomcat": "a:apache:tomcat",
    "apache tomcat/coyote jsp engine": "a:apache:tomcat",
    "nginx": "a:nginx:nginx",
    "microsoft iis httpd": "a:microsoft:internet_information_services",
    "lighttpd": "a:lighttpd:lighttpd",
    "jetty": "a:eclipse:jetty",
    "mysql": "a:oracle:mysql",
    "mariadb": "a:mariadb:mariadb",
    "postgresql db": "a:postgresql:postgresql",
    "postgresql": "a:postgresql:postgresql",
    "microsoft sql server": "a:microsoft:sql_server",
    "mongodb": "a:mongodb:mongodb",
    "redis key-value store": "a:redis:redis",
    "redis": "a:redis:redis",
    "memcached": "a:memcached:memcached",
    "elasticsearch": "a:elastic:elasticsearch",
    "vsftpd": "a:beasts:vsftpd",
    "proftpd": "a:proftpd:proftpd",
    "pure-ftpd": "a:pureftpd:pure-ftpd",
    "filezilla ftpd": "a:filezilla-project:filezilla_server",
    "exim smtpd": "a:exim:exim",
    "postfix smtpd": "a:postfix:postfix",
    "sendmail": "a:sendmail:sendmail",
    "dovecot imapd": "a:dovecot:dovecot",
    "dovecot pop3d": "a:dovecot:dovecot",
    "samba smbd": "a:samba:samba",
    "isc bind": "a:isc:bind",
    "bind": "a:isc:bind",
    "dnsmasq": "a:thekelleys:dnsmasq",
    "openssl": "a:openssl:openssl",
    "php": "a:php:php",
    "php cgi": "a:php:php",
    "python": "a:python:python",
    "node.js": "a:nodejs:node.js",
    "node.js express framework": "a:openjsf:express",
    "dropbear sshd": "a:dropbear_ssh_project:dropbear_ssh",
    "openvpn": "a:openvpn:openvpn",
    "squid http proxy": "a:squid-cache:squid",
    "haproxy": "a:haproxy:haproxy",
    "varnish": "a:varnish-cache:varnish_cache",
    "jenkins": "a:jenkins:jenkins",
    "gitlab": "a:gitlab:gitlab",
    "grafana": "a:grafana:grafana",
    "wordpress": "a:wordpress:wordpress",
    "drupal": "a:drupal:drupal",
    "joomla": "a:joomla:joomla",
    "rabbitmq": "a:pivotal_software:rabbitmq",
    "docker": "a:docker:docker",
    "kubernetes": "a:kubernetes:kubernetes",
    "vmware esxi": "o:vmware:esxi",
    "vmware authentication daemon": "a:vmware:workstation",
    "microsoft windows rpc": "o:microsoft:windows",
    "microsoft terminal services": "a:microsoft:remote_desktop_services",
    "microsoft ftpd": "a:microsoft:internet_information_services",
    "microsoft exchange": "a:microsoft:exchange_server",
    "webmin": "a:webmin:webmin",
    "cups": "a:apple:cups",
    "ntpd": "a:ntp:ntp",
    "snmpd": "a:net-snmp:net-snmp",
    "net-snmp": "a:net-snmp:net-snmp",
    "tightvnc": "a:tightvnc:tightvnc",
    "realvnc": "a:realvnc:vnc",
    "gnu inetutils ftpd": "a:gnu:inetutils",
    "openresty": "a:openresty:openresty",
}

# Distribution packaging markers, in the version string or in nmap's extrainfo.
# A Debian "OpenSSH 7.4" carries fixes for most of what NVD lists against
# upstream 7.4 without changing the advertised version, so a version match
# against one of these is a lead at best and usually a false positive. This is
# the single largest source of bogus CVE rows against Linux targets.
# The separator may be followed by a Debian revision number, as in
# "1.1.1f-1ubuntu2.16", so a digit run is allowed before the distribution name.
_BACKPORT_RE = re.compile(
    r"(?:^|[-+~. ])\d*(?:ubuntu|debian|deb\d|raspbian|centos|rhel|el\d+|fc\d+"
    r"|almalinux|rocky|amzn|suse|sles|dfsg)",
    re.I,
)

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


def looks_backported(service) -> bool:
    """True when the banner names a distribution build rather than an upstream one."""
    haystack = " ".join(
        bit for bit in (service.version, service.extrainfo, service.ostype) if bit
    )
    return bool(_BACKPORT_RE.search(haystack))


def cve_matches_product(cve: dict, cpe23: str) -> bool:
    """Check locally that a returned CVE really applies to the product asked about.

    NVD does the version-range matching server side, but a keyword or loose
    CPE query can still return records for a different product entirely. This
    re-reads the CVE's own applicability configuration and keeps it only when
    the vendor and product line up.
    """
    parts = cpe23.split(":")
    if len(parts) < 5:
        return True
    want = f"{parts[3]}:{parts[4]}".lower()
    if "*" in want:
        return True

    configurations = cve.get("configurations") or []
    saw_any = False
    for config in configurations:
        for node in config.get("nodes") or []:
            for entry in node.get("cpeMatch") or []:
                criteria = (entry.get("criteria") or "").lower().split(":")
                if len(criteria) > 4:
                    saw_any = True
                    if f"{criteria[3]}:{criteria[4]}" == want:
                        return True
    # A record with no applicability data at all (awaiting analysis) cannot be
    # checked either way; keep it rather than inventing a verdict.
    return not saw_any


def _cpe_has_version(cpe23: str) -> bool:
    parts = cpe23.split(":")
    return len(parts) > 5 and parts[5] not in ("*", "-", "")


def build_queries(port: Port, allow_keyword: bool = False) -> list[ServiceQuery]:
    """Decide what to look up for one open port. Empty means 'not matchable'.

    Keyword search is off unless asked for. An NVD keyword query returns
    everything whose text mentions the words, so an unmapped product name
    produces dozens of unrelated CVEs per port — the noisiest thing this
    tool can do, and it was previously on by default.
    """
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
            cpe23 = f"cpe:2.3:{vendor_product}:{version}:*:*:*:*:*:*:*"
            return [
                ServiceQuery(
                    cpe23=cpe23, product=svc.product, version=version, confidence="medium"
                )
            ]
        if vendor_product:
            cpe23 = f"cpe:2.3:{vendor_product}:*:*:*:*:*:*:*:*"
            return [
                ServiceQuery(cpe23=cpe23, product=svc.product, version="", confidence="low")
            ]

        # 3. Unknown product: keyword search, only on request. Skip products
        # that are really just a version blob ("2-4 (RPC #100000)") outright.
        if not allow_keyword:
            return []
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
        include_backported: bool = False,
        keyword_search: bool = False,
        verify_cpe: bool = True,
    ):
        self.nvd = nvd
        self.vulners = vulners
        self.include_unversioned = include_unversioned
        self.min_cvss = min_cvss
        self.verbose = verbose
        self.include_backported = include_backported
        self.keyword_search = keyword_search
        self.verify_cpe = verify_cpe
        self._cve_cache: dict[str, list[dict]] = {}
        self._suppressed: dict[str, int] = {}

    def _suppress(self, reason: str, count: int = 1) -> None:
        self._suppressed[reason] = self._suppressed.get(reason, 0) + count

    # -- public ----------------------------------------------------------

    def run(self, analysis: Analysis) -> None:
        findings: list[Finding] = []
        targets: list[tuple[ScanRun, Host, Port, ServiceQuery]] = []

        for scan in analysis.scans:
            for host in scan.hosts:
                for port in host.open_ports:
                    findings.extend(self._nse_findings(scan, host, port))
                    queries = build_queries(port, allow_keyword=self.keyword_search)
                    if not queries and port.service.product:
                        analysis.skipped_services.append(
                            f"{host.label} {port.key} {port.service.banner} "
                            f"(no CPE mapping - not looked up)"
                        )
                    for query in queries:
                        if query.confidence == "low" and not self.include_unversioned:
                            analysis.skipped_services.append(
                                f"{host.label} {port.key} {port.service.banner} "
                                f"(no version - use --include-unversioned)"
                            )
                            continue
                        # A distribution build advertises the upstream version it
                        # forked from, so matching it against upstream CVE ranges
                        # reports fixes the vendor already shipped. Skipped before
                        # the lookup so no rate-limited request is spent on it.
                        if not self.include_backported and looks_backported(port.service):
                            self._suppress(
                                "services whose banner names a distribution build, where "
                                "upstream CVE ranges do not apply (--include-backported)"
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
        for reason, count in self._suppressed.items():
            analysis.suppress(reason, count)

    # -- internals -------------------------------------------------------

    def _lookup(self, scan: ScanRun, host: Host, port: Port, query: ServiceQuery) -> list[Finding]:
        out: list[Finding] = []
        degraded = scan.fmt != "xml"

        confidence = query.confidence
        if degraded and confidence == "high":
            confidence = "medium"

        backported = looks_backported(port.service)

        for cve in self._nvd_records(query):
            (cve_id, score, vector, severity, published, description, refs) = finding_from_nvd(cve)
            if not cve_id:
                continue
            if self.verify_cpe and query.cpe23 and not cve_matches_product(cve, query.cpe23):
                self._suppress(
                    "CVE rows whose matched product is absent from the CVE's own "
                    "applicability data (--no-verify-cpe)"
                )
                continue
            if self.min_cvss and (score or 0.0) < self.min_cvss:
                self._suppress("CVE rows scoring below --min-cvss")
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
                    backport_suspected=backported,
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
                    self._suppress("CVE rows scoring below --min-cvss")
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
                        backport_suspected=backported,
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
