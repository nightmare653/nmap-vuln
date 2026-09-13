"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys

from .cache import DEFAULT_TTL, Cache
from .match import Matcher
from .model import Analysis, SEVERITY_ORDER
from .parsers import discover, parse_file
from .report import write_csv, write_html, write_validation_csv, write_weakness_csv
from .rules import detect
from .sources import EpssClient, KevCatalog, NVDClient, VulnersClient
from .validate import validate

VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nmapvuln",
        description="Validate nmap scan output and correlate detected services with known CVEs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  nmapvuln scans/ -o report/\n"
            "  nmapvuln scan.xml --nvd-key $NVD_KEY --min-cvss 7.0\n"
            "  nmapvuln scans/ --offline           # no network, NSE findings only\n"
            "  nmapvuln scans/ --include-unversioned --fail-on high\n"
        ),
    )
    p.add_argument("paths", nargs="+", help="nmap output files or directories (.xml, .nmap, .gnmap)")
    p.add_argument("-o", "--out", default="nmapvuln-report", help="output directory")
    p.add_argument("--name", default="report", help="base name for the output files")
    p.add_argument("--title", default="Nmap Scan Validation & CVE Report", help="report title")

    p.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""),
                   help="NVD API key (or set NVD_API_KEY). Raises the rate limit to 50/30s.")
    p.add_argument("--vulners-key", default=os.environ.get("VULNERS_API_KEY", ""),
                   help="Vulners API key (or set VULNERS_API_KEY). Optional.")
    p.add_argument("--offline", action="store_true",
                   help="no network calls; report only CVEs already present in NSE output")

    p.add_argument("--include-unversioned", action="store_true",
                   help="also match services with no detected version (noisy, low confidence)")
    p.add_argument("--include-backported", action="store_true",
                   help="include CVEs matched against distribution-packaged banners "
                        "(Ubuntu/Debian/RHEL builds carry backported fixes, so these are "
                        "mostly false positives and are withheld by default)")
    p.add_argument("--include-tentative", action="store_true",
                   help="include weaknesses that could not be confirmed from the scan data")
    p.add_argument("--keyword-search", action="store_true",
                   help="fall back to NVD keyword search for products with no CPE mapping "
                        "(returns anything whose text mentions the words; very noisy)")
    p.add_argument("--no-verify-cpe", action="store_true",
                   help="skip the local re-check that a returned CVE lists the matched "
                        "product in its own applicability data")
    p.add_argument("--kev-only", action="store_true",
                   help="report only CVEs in CISA's Known Exploited Vulnerabilities catalog")
    p.add_argument("--no-enrich", action="store_true",
                   help="skip the CISA KEV and EPSS lookups")
    p.add_argument("--no-rules", action="store_true",
                   help="skip non-CVE weakness detection (weak crypto, misconfiguration)")
    p.add_argument("--no-exposure", action="store_true",
                   help="skip weaknesses raised purely from a service being reachable")
    p.add_argument("--min-cvss", type=float, default=0.0, help="drop findings below this CVSS score")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                   default="none", help="exit non-zero if a finding at or above this severity exists")

    p.add_argument("--cache", default=os.path.join(
        os.path.expanduser("~"), ".cache", "nmapvuln", "cve-cache.sqlite"), help="cache database path")
    p.add_argument("--cache-ttl", type=int, default=DEFAULT_TTL, help="cache lifetime in seconds")
    p.add_argument("--no-cache", action="store_true", help="bypass the cache entirely")

    p.add_argument("--no-recurse", action="store_true", help="do not descend into subdirectories")
    p.add_argument("-v", "--verbose", action="store_true", help="log every API query")
    p.add_argument("--version", action="version", version=f"nmapvuln {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --kev-only decides what to keep from the CISA catalog, so without the
    # catalog it would silently discard every finding. Refuse instead.
    if args.kev_only and args.offline:
        parser.error("--kev-only needs the CISA KEV catalog, which --offline cannot fetch")

    files = discover(args.paths, recursive=not args.no_recurse)
    if not files:
        print("[!] No nmap output files found (.xml, .nmap, .gnmap).", file=sys.stderr)
        return 1

    print(f"[*] Parsing {len(files)} file(s)", file=sys.stderr)
    analysis = Analysis(offline=args.offline)
    for path in files:
        for scan in parse_file(path):
            analysis.scans.append(scan)
            if args.verbose:
                state = "ok" if scan.completed else "incomplete"
                print(f"    {os.path.basename(path)}: {len(scan.hosts)} host(s), {state}",
                      file=sys.stderr)

    print("[*] Validating scans", file=sys.stderr)
    analysis.issues = validate(analysis)

    if not args.no_rules:
        print("[*] Checking for non-CVE weaknesses", file=sys.stderr)
        everything = detect(analysis.scans, include_exposure=not args.no_exposure)
        if args.include_tentative:
            analysis.weaknesses = everything
        else:
            analysis.weaknesses = [w for w in everything if w.confidence != "tentative"]
        withheld = len(everything) - len(analysis.weaknesses)
        if withheld:
            analysis.suppress(
                "weaknesses the scan data could not confirm (--include-tentative)",
                withheld,
            )

    cache = Cache(args.cache, ttl=args.cache_ttl, enabled=not args.no_cache)
    nvd = vulners = None
    if not args.offline:
        nvd = NVDClient(cache, api_key=args.nvd_key, verbose=args.verbose)
        vulners = VulnersClient(cache, api_key=args.vulners_key, verbose=args.verbose)
        if not args.nvd_key:
            print("[!] No NVD API key - limited to 5 requests / 30s. Free key: "
                  "https://nvd.nist.gov/developers/request-an-api-key", file=sys.stderr)
    else:
        print("[*] Offline mode: using NSE script output only", file=sys.stderr)

    matcher = Matcher(
        nvd,
        vulners,
        include_unversioned=args.include_unversioned,
        min_cvss=args.min_cvss,
        verbose=args.verbose,
        include_backported=args.include_backported,
        keyword_search=args.keyword_search,
        verify_cpe=not args.no_verify_cpe,
    )
    matcher.run(analysis)

    kev = epss = None
    # --kev-only depends on the catalog, so it overrides --no-enrich.
    if analysis.findings and not args.offline and (not args.no_enrich or args.kev_only):
        print("[*] Corroborating against CISA KEV and EPSS", file=sys.stderr)
        kev = KevCatalog(cache, verbose=args.verbose)
        epss = EpssClient(cache, verbose=args.verbose)
        catalog = kev.load()
        scores = epss.scores([f.cve for f in analysis.findings])
        for finding in analysis.findings:
            cve_id = finding.cve.upper()
            if cve_id in catalog:
                finding.kev = True
                finding.kev_due = catalog[cve_id]
                finding.exploit_known = True
            if cve_id in scores:
                finding.epss = scores[cve_id]
        analysis.findings.sort(key=lambda f: f.sort_key)

    if args.kev_only:
        keeping = [f for f in analysis.findings if f.kev]
        withheld = len(analysis.findings) - len(keeping)
        if withheld:
            analysis.suppress("CVE rows not listed in CISA KEV (--kev-only)", withheld)
        analysis.findings = keeping

    for client in (nvd, vulners, kev, epss):
        if client is not None:
            for err in client.errors:
                print(f"[!] {err}", file=sys.stderr)
    cache.close()

    base = os.path.join(args.out, args.name)
    html_path = write_html(analysis, base + ".html", title=args.title)
    csv_path = write_csv(analysis, base + "-findings.csv")
    weak_path = write_weakness_csv(analysis, base + "-weaknesses.csv")
    val_path = write_validation_csv(analysis, base + "-validation.csv")

    counts = analysis.counts_by_severity()
    weak = analysis.weakness_counts_by_severity()
    errors = sum(1 for i in analysis.issues if i.severity == "error")
    warns = sum(1 for i in analysis.issues if i.severity == "warn")

    print("", file=sys.stderr)
    print(f"[+] {len(analysis.findings)} CVE finding(s): "
          f"{counts['CRITICAL']} critical, {counts['HIGH']} high, "
          f"{counts['MEDIUM']} medium, {counts['LOW']} low", file=sys.stderr)
    print(f"[+] {len(analysis.weaknesses)} non-CVE weakness(es): "
          f"{weak['CRITICAL']} critical, {weak['HIGH']} high, "
          f"{weak['MEDIUM']} medium, {weak['LOW']} low", file=sys.stderr)
    print(f"[+] scan validation: {errors} error(s), {warns} warning(s)", file=sys.stderr)
    for reason, count in sorted(analysis.suppressed.items(), key=lambda kv: -kv[1]):
        print(f"[~] withheld {count} {reason}", file=sys.stderr)
    kev_count = sum(1 for f in analysis.findings if f.kev)
    if kev_count:
        print(f"[!] {kev_count} finding(s) are in CISA's Known Exploited "
              f"Vulnerabilities catalog - treat these first", file=sys.stderr)
    if analysis.skipped_services:
        print(f"[!] {len(set(analysis.skipped_services))} service(s) unassessed "
              f"(no version) - re-run with --include-unversioned to include them", file=sys.stderr)
    print(f"[+] {html_path}", file=sys.stderr)
    print(f"[+] {csv_path}", file=sys.stderr)
    print(f"[+] {weak_path}", file=sys.stderr)
    print(f"[+] {val_path}", file=sys.stderr)

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        severities = [f.severity for f in analysis.findings]
        severities += [w.severity for w in analysis.weaknesses]
        if any(SEVERITY_ORDER.get(s, 0) >= threshold for s in severities):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
