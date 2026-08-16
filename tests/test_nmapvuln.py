"""Regression tests. Run with: python -m pytest tests/ -q  (or python tests/test_nmapvuln.py)"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapvuln.match import Matcher, _clean_version, build_queries, cpe22_to_23  # noqa: E402
from nmapvuln.model import Analysis, Finding, Port, Service  # noqa: E402
from nmapvuln.parsers import (  # noqa: E402
    _split_version_blob,
    parse_file,
    parse_gnmap,
    parse_nmap,
    parse_xml,
)
from nmapvuln.rules import detect  # noqa: E402
from nmapvuln.validate import validate  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")


def _write(tmp: str, name: str, content: str) -> str:
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


class TestVersionSplitting(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_split_version_blob("OpenSSH 7.4 (protocol 2.0)"),
                         ("OpenSSH", "7.4", "protocol 2.0"))

    def test_distro_suffix_stays_in_version(self):
        product, version, _extra = _split_version_blob(
            "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)")
        self.assertEqual(product, "OpenSSH")
        self.assertEqual(version, "8.2p1 Ubuntu 4ubuntu0.5")

    def test_multiword_product(self):
        self.assertEqual(_split_version_blob("PostgreSQL DB 11.7")[:2], ("PostgreSQL DB", "11.7"))

    def test_product_containing_digits(self):
        # 'Node.js' must not be mistaken for a version token.
        self.assertEqual(_split_version_blob("Node.js Express framework")[0],
                         "Node.js Express framework")

    def test_no_version(self):
        self.assertEqual(_split_version_blob("MySQL"), ("MySQL", "", ""))


class TestVersionCleaning(unittest.TestCase):
    def test_strips_packaging(self):
        self.assertEqual(_clean_version("8.2p1 Ubuntu 4ubuntu0.5"), "8.2p1")
        self.assertEqual(_clean_version("2.4.6-1ubuntu2.4"), "2.4.6")

    def test_rejects_non_versions(self):
        self.assertEqual(_clean_version(""), "")
        self.assertEqual(_clean_version("unknown"), "")


class TestCpeConversion(unittest.TestCase):
    def test_22_to_23(self):
        self.assertEqual(cpe22_to_23("cpe:/a:apache:http_server:2.4.49"),
                         "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

    def test_no_version(self):
        self.assertEqual(cpe22_to_23("cpe:/a:openbsd:openssh"),
                         "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")

    def test_already_23_is_padded(self):
        self.assertEqual(cpe22_to_23("cpe:2.3:a:nginx:nginx:1.18.0").count(":"), 12)

    def test_garbage(self):
        self.assertEqual(cpe22_to_23("not a cpe"), "")


class TestQueryBuilding(unittest.TestCase):
    def _port(self, **kw) -> Port:
        return Port(portid=80, state="open", service=Service(**kw))

    def test_cpe_with_version_is_high_confidence(self):
        port = self._port(name="http", product="Apache httpd", version="2.4.49",
                          method="probed", cpes=["cpe:/a:apache:http_server:2.4.49"])
        queries = build_queries(port)
        self.assertEqual(queries[0].confidence, "high")
        self.assertIn("apache:http_server:2.4.49", queries[0].cpe23)

    def test_cpe_without_version_borrows_probed_version(self):
        port = self._port(name="http", product="nginx", version="1.18.0",
                          method="probed", cpes=["cpe:/a:nginx:nginx"])
        queries = build_queries(port)
        self.assertEqual(queries[0].confidence, "high")
        self.assertIn(":1.18.0:", queries[0].cpe23)

    def test_known_product_without_cpe_is_medium(self):
        port = self._port(name="ftp", product="vsftpd", version="2.3.4", method="probed")
        queries = build_queries(port)
        self.assertEqual(queries[0].confidence, "medium")
        self.assertIn("beasts:vsftpd:2.3.4", queries[0].cpe23)

    def test_unversioned_is_low(self):
        port = self._port(name="mysql", product="MySQL", method="probed")
        self.assertEqual(build_queries(port)[0].confidence, "low")

    def test_tcpwrapped_is_not_matchable(self):
        self.assertEqual(build_queries(self._port(name="tcpwrapped", method="probed")), [])

    def test_no_service_info_is_not_matchable(self):
        self.assertEqual(build_queries(self._port(name="cslistener", method="table")), [])

    def test_version_blob_product_is_rejected(self):
        # rpcbind's gnmap version field is '2-4 (RPC #100000)' — pure noise as a keyword.
        self.assertEqual(build_queries(self._port(name="rpcbind", product="2-4")), [])

    def test_hardware_cpe_ignored(self):
        port = self._port(name="http", product="Router", version="1.0",
                          method="probed", cpes=["cpe:/h:cisco:router"])
        self.assertTrue(all(not q.cpe23.startswith("cpe:2.3:h") for q in build_queries(port)))


class TestXmlParser(unittest.TestCase):
    def setUp(self):
        self.run = parse_xml(os.path.join(SAMPLES, "sample.xml"))[0]

    def test_metadata(self):
        self.assertEqual(self.run.nmap_version, "7.94")
        self.assertTrue(self.run.completed)
        self.assertIn("-sV", self.run.scan_types)

    def test_hosts_and_ports(self):
        self.assertEqual(len(self.run.hosts), 2)
        host = self.run.hosts[0]
        self.assertEqual(host.address, "10.10.10.5")
        self.assertEqual(host.hostnames, ["web01.lab.local"])
        self.assertEqual(len(host.open_ports), 5)

    def test_cpe_and_scripts(self):
        http = [p for p in self.run.hosts[0].ports if p.portid == 80][0]
        self.assertEqual(http.service.cpes, ["cpe:/a:apache:http_server:2.4.49"])
        self.assertTrue(any(s.id == "vulners" for s in http.scripts))
        cves = http.scripts[0].cves()
        self.assertIn("CVE-2021-41773", cves)

    def test_extraports(self):
        self.assertEqual(self.run.hosts[1].extraports.get("filtered"), 65535)


class TestTruncationRecovery(unittest.TestCase):
    def test_recovers_complete_hosts(self):
        with open(os.path.join(SAMPLES, "sample.xml"), encoding="utf-8") as fh:
            full = fh.read()
        cut = full[: full.find("</host>") + len("</host>") + 100]
        with tempfile.TemporaryDirectory() as tmp:
            run = parse_xml(_write(tmp, "cut.xml", cut))[0]
        self.assertEqual(len(run.hosts), 1)
        self.assertFalse(run.completed)
        self.assertTrue(any("truncated" in e for e in run.parse_errors))

    def test_unsalvageable_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = parse_xml(_write(tmp, "junk.xml", "<<<not xml at all"))[0]
        self.assertEqual(run.hosts, [])
        self.assertTrue(run.parse_errors)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = parse_xml(_write(tmp, "empty.xml", ""))[0]
        self.assertIn("empty", run.parse_errors[0])


class TestGnmapParser(unittest.TestCase):
    def setUp(self):
        self.run = parse_gnmap(os.path.join(SAMPLES, "sample.gnmap"))

    def test_hosts_merged_across_status_and_ports_lines(self):
        self.assertEqual(len(self.run.hosts), 2)
        host = [h for h in self.run.hosts if h.address == "10.10.10.5"][0]
        self.assertEqual(host.hostnames, ["web01.lab.local"])
        self.assertEqual(len(host.ports), 3)

    def test_service_versions(self):
        host = [h for h in self.run.hosts if h.address == "10.10.10.5"][0]
        ssh = [p for p in host.ports if p.portid == 22][0]
        self.assertEqual((ssh.service.product, ssh.service.version), ("OpenSSH", "7.4"))

    def test_filtered_port_state(self):
        host = [h for h in self.run.hosts if h.address == "10.10.10.5"][0]
        https = [p for p in host.ports if p.portid == 443][0]
        self.assertEqual(https.state, "filtered")
        self.assertFalse(https.is_open)

    def test_completion_detected(self):
        self.assertTrue(self.run.completed)


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.run = parse_nmap(os.path.join(SAMPLES, "sample.nmap"))

    def test_hosts(self):
        self.assertEqual(len(self.run.hosts), 2)
        self.assertEqual(self.run.hosts[0].address, "10.10.10.11")
        self.assertEqual(self.run.hosts[0].hostnames, ["db01.lab.local"])

    def test_ports_and_versions(self):
        pg = [p for p in self.run.hosts[0].ports if p.portid == 5432][0]
        self.assertEqual(pg.service.product, "PostgreSQL DB")
        self.assertEqual(pg.service.version, "11.7")

    def test_script_output_captured(self):
        pg = [p for p in self.run.hosts[0].ports if p.portid == 5432][0]
        self.assertTrue(any(s.id.startswith("ssl") for s in pg.scripts))

    def test_extraports(self):
        self.assertEqual(self.run.hosts[1].extraports.get("filtered"), 1000)


class TestFormatDispatch(unittest.TestCase):
    def test_extension_routing(self):
        self.assertEqual(parse_file(os.path.join(SAMPLES, "sample.xml"))[0].fmt, "xml")
        self.assertEqual(parse_file(os.path.join(SAMPLES, "sample.gnmap"))[0].fmt, "gnmap")
        self.assertEqual(parse_file(os.path.join(SAMPLES, "sample.nmap"))[0].fmt, "nmap")

    def test_content_sniffing_for_unknown_extension(self):
        with open(os.path.join(SAMPLES, "sample.xml"), encoding="utf-8") as fh:
            content = fh.read()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(parse_file(_write(tmp, "scan.out", content))[0].fmt, "xml")


class TestValidation(unittest.TestCase):
    def _codes(self, *files) -> set[str]:
        analysis = Analysis()
        for name in files:
            analysis.scans.extend(parse_file(os.path.join(SAMPLES, name)))
        return {i.code for i in validate(analysis)}

    def test_flags_lossy_format(self):
        self.assertIn("LOSSY_FORMAT", self._codes("sample.gnmap"))

    def test_flags_aggressive_timing(self):
        self.assertIn("AGGRESSIVE_TIMING", self._codes("sample.gnmap"))

    def test_flags_all_filtered_host(self):
        self.assertIn("ALL_FILTERED", self._codes("sample.xml"))

    def test_flags_tcpwrapped_and_missing_version(self):
        codes = self._codes("sample.xml")
        self.assertIn("TCPWRAPPED", codes)
        self.assertIn("NO_VERSION", codes)

    def test_detects_duplicate_host_across_files(self):
        self.assertIn("DUPLICATE_HOST", self._codes("sample.xml", "sample.gnmap"))

    def test_xml_scan_is_not_flagged_lossy(self):
        analysis = Analysis()
        analysis.scans.extend(parse_file(os.path.join(SAMPLES, "sample.xml")))
        codes = {i.code for i in validate(analysis)}
        self.assertNotIn("LOSSY_FORMAT", codes)
        self.assertNotIn("NO_VERSION_DETECTION", codes)


class TestDedupe(unittest.TestCase):
    def test_merges_sources_and_keeps_best_metadata(self):
        nse = Finding(host="h", port="80/tcp", cve="CVE-2021-41773", cvss=7.5, severity="HIGH",
                      description="Reported by NSE script vulners", source="nse",
                      confidence="high", exploit_known=True, references=["https://a"])
        nvd = Finding(host="h", port="80/tcp", cve="CVE-2021-41773", cvss=7.5, severity="HIGH",
                      cvss_vector="CVSS:3.1/AV:N", description="A flaw was found in path "
                      "normalization in Apache HTTP Server 2.4.49.", source="nvd",
                      confidence="medium", references=["https://b"])
        merged = Matcher._dedupe([nse, nvd])
        self.assertEqual(len(merged), 1)
        f = merged[0]
        self.assertEqual(f.source, "nse+nvd")
        self.assertEqual(f.confidence, "high")          # best of the two
        self.assertTrue(f.exploit_known)                # OR'd across sources
        self.assertIn("path normalization", f.description)  # NVD's prose wins
        self.assertEqual(f.cvss_vector, "CVSS:3.1/AV:N")
        self.assertEqual(sorted(f.references), ["https://a", "https://b"])

    def test_distinct_hosts_are_not_merged(self):
        a = Finding(host="h1", port="80/tcp", cve="CVE-1", source="nvd")
        b = Finding(host="h2", port="80/tcp", cve="CVE-1", source="nvd")
        self.assertEqual(len(Matcher._dedupe([a, b])), 2)

    def test_severity_recomputed_from_merged_score(self):
        a = Finding(host="h", port="80/tcp", cve="CVE-1", severity="UNKNOWN", source="nse")
        b = Finding(host="h", port="80/tcp", cve="CVE-1", cvss=9.8, severity="CRITICAL",
                    source="nvd")
        self.assertEqual(Matcher._dedupe([a, b])[0].severity, "CRITICAL")


class TestRules(unittest.TestCase):
    """Non-CVE weakness detection over the scripted sample."""

    @classmethod
    def setUpClass(cls):
        scans = parse_file(os.path.join(SAMPLES, "sample-scripts.xml"))
        cls.weaknesses = detect(scans)
        cls.by_id = {}
        for w in cls.weaknesses:
            cls.by_id.setdefault(w.rule_id, []).append(w)

    def test_weak_dh_group_detected(self):
        # The question that prompted this feature: a 1024-bit DH modulus.
        hits = self.by_id["TLS_DH_WEAK_GROUP"]
        self.assertEqual(hits[0].port, "443/tcp")
        self.assertIn("1024", hits[0].evidence)

    def test_strong_dh_group_does_not_fire(self):
        from nmapvuln.model import Host, Port, ScanRun, Script

        host = Host(address="1.1.1.1", status="up")
        port = Port(portid=443, state="open")
        port.scripts.append(Script(id="ssl-dh-params", output="Modulus Length: 4096"))
        host.ports.append(port)
        scan = ScanRun(source="x", fmt="xml", hosts=[host])
        ids = {w.rule_id for w in detect([scan], include_exposure=False)}
        self.assertNotIn("TLS_DH_WEAK_GROUP", ids)

    def test_ssh_weak_algorithms(self):
        for rule_id in ("SSH_WEAK_KEX", "SSH_WEAK_CIPHER", "SSH_WEAK_MAC",
                        "SSH_WEAK_HOSTKEY_TYPE", "SSH_WEAK_HOSTKEY_SIZE"):
            self.assertIn(rule_id, self.by_id, f"{rule_id} did not fire")

    def test_tls_cipher_and_cert_problems(self):
        for rule_id in ("TLS_SSLV3", "TLS_RC4", "TLS_3DES", "TLS_EXPORT_CIPHER",
                        "TLS_DEPRECATED_VERSION", "TLS_WEAK_CIPHER_GRADE",
                        "TLS_CERT_EXPIRED", "TLS_CERT_WEAK_KEY", "TLS_CERT_WEAK_SIGNATURE"):
            self.assertIn(rule_id, self.by_id, f"{rule_id} did not fire")

    def test_host_scripts_are_examined(self):
        # smb-* run as hostscript, outside any port — these were previously missed.
        for rule_id in ("SMB_V1_ENABLED", "SMB_SIGNING_DISABLED", "SMB_GUEST_ACCESS"):
            self.assertIn(rule_id, self.by_id, f"{rule_id} did not fire")
        self.assertEqual(self.by_id["SMB_V1_ENABLED"][0].port, "host")

    def test_service_and_auth_weaknesses(self):
        for rule_id in ("FTP_ANONYMOUS", "FTP_ANONYMOUS_WRITABLE", "DNS_OPEN_RECURSION",
                        "REDIS_NO_AUTH", "MYSQL_EMPTY_PASSWORD", "HTTP_DANGEROUS_METHODS"):
            self.assertIn(rule_id, self.by_id, f"{rule_id} did not fire")

    def test_exposure_rules(self):
        self.assertIn("CLEARTEXT_TELNET", self.by_id)
        self.assertIn("DATA_SERVICE_EXPOSED", self.by_id)

    def test_tls_wrapped_service_is_not_flagged_cleartext(self):
        # 443 is ftp-less, but confirm the tunnel check works in general.
        from nmapvuln.model import Host, Port, ScanRun, Service

        host = Host(address="1.1.1.1", status="up")
        host.ports.append(
            Port(portid=990, state="open", service=Service(name="ftp", tunnel="ssl")))
        scan = ScanRun(source="x", fmt="xml", hosts=[host])
        ids = {w.rule_id for w in detect([scan])}
        self.assertNotIn("CLEARTEXT_FTP", ids)

    def test_exposure_can_be_disabled(self):
        scans = parse_file(os.path.join(SAMPLES, "sample-scripts.xml"))
        ids = {w.rule_id for w in detect(scans, include_exposure=False)}
        self.assertNotIn("CLEARTEXT_TELNET", ids)
        self.assertIn("TLS_DH_WEAK_GROUP", ids)  # script rules still run

    def test_generic_catchall_does_not_duplicate_specific_rules(self):
        # ssl-heartbleed declares State: VULNERABLE and has a dedicated rule;
        # it must be reported once, not also as NSE_VULNERABLE_STATE.
        heartbleed_port = self.by_id["TLS_HEARTBLEED"][0].port
        generic = [w for w in self.by_id.get("NSE_VULNERABLE_STATE", [])
                   if w.port == heartbleed_port]
        self.assertEqual(generic, [])

    def test_every_weakness_carries_evidence_and_advice(self):
        for w in self.weaknesses:
            self.assertTrue(w.evidence, f"{w.rule_id} has no evidence")
            self.assertTrue(w.recommendation, f"{w.rule_id} has no recommendation")
            self.assertIn(w.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_deduplicated_per_host_port_rule(self):
        keys = [(w.host, w.port, w.rule_id) for w in self.weaknesses]
        self.assertEqual(len(keys), len(set(keys)))

    def test_down_hosts_are_skipped(self):
        from nmapvuln.model import Host, ScanRun

        scan = ScanRun(source="x", fmt="xml", hosts=[Host(address="1.1.1.1", status="down")])
        self.assertEqual(detect([scan]), [])


class TestOfflineRun(unittest.TestCase):
    """The full pipeline with no network: NSE-derived findings only."""

    def test_end_to_end(self):
        analysis = Analysis(offline=True)
        for name in ("sample.xml", "sample.gnmap", "sample.nmap"):
            analysis.scans.extend(parse_file(os.path.join(SAMPLES, name)))
        analysis.issues = validate(analysis)
        Matcher(None, None).run(analysis)

        cves = {f.cve for f in analysis.findings}
        self.assertEqual(cves, {"CVE-2021-41773", "CVE-2021-42013"})
        self.assertEqual(analysis.counts_by_severity()["CRITICAL"], 1)
        self.assertTrue(analysis.skipped_services)  # MySQL had no version

    def test_min_cvss_filters_nse_findings(self):
        analysis = Analysis(offline=True)
        analysis.scans.extend(parse_file(os.path.join(SAMPLES, "sample.xml")))
        Matcher(None, None, min_cvss=9.0).run(analysis)
        self.assertEqual({f.cve for f in analysis.findings}, {"CVE-2021-42013"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
