"""Regression tests. Run with: python -m pytest tests/ -q  (or python tests/test_nmapvuln.py)"""

from __future__ import annotations

import datetime
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


# ===========================================================================
# Accuracy regression tests.
#
# Every case below is a false positive or false negative this tool actually
# produced. They are written against the smallest piece of script output that
# reproduces the mistake, so a future rewrite of a rule cannot quietly
# reintroduce it.
# ===========================================================================

from nmapvuln import scriptdata  # noqa: E402
from nmapvuln.match import cve_matches_product, looks_backported  # noqa: E402
from nmapvuln.model import Host, Port, ScanRun, Script, Service  # noqa: E402

SCAN_EPOCH = 1704067200  # 2024-01-01, so fixtures do not rot as time passes


def _scan(scripts, service=None, portid=443, host_scripts=()):
    """One up host with one open port carrying the given scripts."""
    host = Host(address="10.0.0.1", status="up")
    port = Port(
        portid=portid,
        state="open",
        service=service or Service(name="https", method="probed"),
    )
    for script_id, output in scripts:
        port.scripts.append(Script(id=script_id, output=output))
    for script_id, output in host_scripts:
        host.scripts.append(Script(id=script_id, output=output))
    host.ports.append(port)
    return ScanRun(source="t.xml", fmt="xml", hosts=[host], start_epoch=SCAN_EPOCH)


def _ids(scripts, **kw):
    scan = _scan(scripts, **kw)
    return {w.rule_id for w in detect([scan], include_exposure=False)}


HEALTHY_CERT = """
  Subject: commonName=good.example.com
  Issuer: commonName=R3/organizationName=Let's Encrypt
  Public Key type: rsa
  Public Key bits: 2048
  Signature Algorithm: sha256WithRSAEncryption
  Not valid before: 2023-06-01T00:00:00
  Not valid after:  2033-06-01T00:00:00
"""

EXPIRED_CERT = """
  Subject: commonName=old.example.com
  Issuer: commonName=old.example.com
  Public Key type: rsa
  Public Key bits: 1024
  Signature Algorithm: sha1WithRSAEncryption
  Not valid before: 2014-01-01T00:00:00
  Not valid after:  2016-01-01T00:00:00
"""

EC_CERT = """
  Subject: commonName=ec.example.com
  Issuer: commonName=R3/organizationName=Let's Encrypt
  Public Key type: ec
  Public Key bits: 256
  Signature Algorithm: ecdsa-with-SHA256
  Not valid before: 2023-06-01T00:00:00
  Not valid after:  2033-06-01T00:00:00
"""


class TestCertificateAccuracy(unittest.TestCase):
    """nmap prints 'Not valid after' for every certificate, healthy included."""

    def test_healthy_certificate_is_not_reported_expired(self):
        self.assertEqual(_ids([("ssl-cert", HEALTHY_CERT)]), set())

    def test_expired_certificate_is_reported(self):
        ids = _ids([("ssl-cert", EXPIRED_CERT)])
        self.assertIn("TLS_CERT_EXPIRED", ids)
        self.assertIn("TLS_CERT_SELF_SIGNED", ids)
        self.assertIn("TLS_CERT_WEAK_KEY", ids)
        self.assertIn("TLS_CERT_WEAK_SIGNATURE", ids)

    def test_expiry_is_judged_against_the_scan_clock(self):
        # The certificate expires in 2033: valid at scan time, so not a finding
        # even when the report is generated later.
        cert = scriptdata.parse_certificate(HEALTHY_CERT)
        self.assertFalse(cert.expired_at(datetime.datetime(2024, 1, 1)))
        self.assertTrue(cert.expired_at(datetime.datetime(2035, 1, 1)))

    def test_elliptic_curve_key_is_not_undersized_at_256_bits(self):
        # A 256-bit EC key is stronger than a 2048-bit RSA key. Measuring it
        # against an RSA threshold flags every modern certificate.
        self.assertNotIn("TLS_CERT_WEAK_KEY", _ids([("ssl-cert", EC_CERT)]))

    def test_sha256_is_not_read_as_a_weak_hash(self):
        self.assertNotIn("TLS_CERT_WEAK_SIGNATURE", _ids([("ssl-cert", HEALTHY_CERT)]))

    def test_ecdsa_with_sha1_is_caught(self):
        cert = scriptdata.parse_certificate(
            "Subject: commonName=x\nSignature Algorithm: ecdsa-with-SHA1\n"
        )
        self.assertEqual(cert.weak_signature, "sha1")

    def test_sample_nmap_certificate_raises_nothing(self):
        scans = parse_file(os.path.join(SAMPLES, "sample.nmap"))
        ids = {w.rule_id for w in detect(scans, include_exposure=False)}
        self.assertNotIn("TLS_CERT_EXPIRED", ids)
        self.assertNotIn("TLS_CERT_WEAK_KEY", ids)


RSA_THEN_ED25519 = """
  2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)
  256 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (ED25519)
"""

ED25519_THEN_RSA = """
  256 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (ED25519)
  256 ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89 (ECDSA)
  2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)
"""

STRONG_THEN_WEAK_RSA = """
  2048 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (RSA)
  1024 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00 (RSA)
"""


class TestHostKeyAccuracy(unittest.TestCase):
    def test_modern_keys_are_not_undersized(self):
        self.assertNotIn("SSH_WEAK_HOSTKEY_SIZE", _ids([("ssh-hostkey", RSA_THEN_ED25519)]))

    def test_modern_keys_are_not_undersized_whatever_the_order(self):
        # The old rule read only the first match, so a 256-bit Ed25519 key
        # listed first was reported as an undersized host key.
        self.assertNotIn("SSH_WEAK_HOSTKEY_SIZE", _ids([("ssh-hostkey", ED25519_THEN_RSA)]))

    def test_weak_rsa_key_after_a_strong_one_is_still_found(self):
        # The mirror image: reading only the first match missed this entirely.
        ids = _ids([("ssh-hostkey", STRONG_THEN_WEAK_RSA)])
        self.assertIn("SSH_WEAK_HOSTKEY_SIZE", ids)

    def test_dsa_key_is_reported_by_algorithm_not_size(self):
        output = "  1024 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 (DSA)\n"
        self.assertIn("SSH_WEAK_HOSTKEY_TYPE", _ids([("ssh-hostkey", output)]))

    def test_parser_reads_bits_and_algorithm(self):
        keys = scriptdata.parse_host_keys(ED25519_THEN_RSA)
        self.assertEqual([(k.bits, k.algorithm) for k in keys],
                         [(256, "ED25519"), (256, "ECDSA"), (2048, "RSA")])


STRONG_SSH_ALGOS = """
  kex_algorithms: (2)
      curve25519-sha256
      diffie-hellman-group-exchange-sha256
  server_host_key_algorithms: (2)
      rsa-sha2-512
      ssh-ed25519
  encryption_algorithms: (2)
      chacha20-poly1305@openssh.com
      aes256-gcm@openssh.com
  mac_algorithms: (2)
      hmac-sha2-256-etm@openssh.com
      umac-64-etm@openssh.com
  compression_algorithms: (2)
      none
      zlib@openssh.com
"""

WEAK_MAC_ALGOS = """
  encryption_algorithms: (1)
      aes256-gcm@openssh.com
  mac_algorithms: (2)
      hmac-sha2-256
      umac-64@openssh.com
"""


class TestSshAlgorithmScoping(unittest.TestCase):
    def test_healthy_host_raises_nothing(self):
        self.assertEqual(_ids([("ssh2-enum-algos", STRONG_SSH_ALGOS)]), set())

    def test_none_in_the_compression_list_is_not_a_weak_cipher(self):
        # 'none' is a legitimate compression algorithm. A pattern scanning the
        # whole blob read it as a null cipher.
        self.assertNotIn("SSH_WEAK_CIPHER", _ids([("ssh2-enum-algos", STRONG_SSH_ALGOS)]))

    def test_etm_variant_of_umac64_is_not_weak(self):
        self.assertNotIn("SSH_WEAK_MAC", _ids([("ssh2-enum-algos", STRONG_SSH_ALGOS)]))

    def test_bare_umac64_is_weak(self):
        self.assertIn("SSH_WEAK_MAC", _ids([("ssh2-enum-algos", WEAK_MAC_ALGOS)]))

    def test_lists_are_parsed_separately(self):
        lists = scriptdata.parse_ssh_algorithms(STRONG_SSH_ALGOS)
        self.assertEqual(lists["compression_algorithms"], ["none", "zlib@openssh.com"])
        self.assertNotIn("none", lists["encryption_algorithms"])


STRONG_TLS = """
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
    compressors:
      NULL
    cipher preference: server
  TLSv1.3:
    ciphers:
      TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
    cipher preference: server
  least strength: A
"""

WEAK_TLS = """
  SSLv3:
    ciphers:
      TLS_RSA_WITH_RC4_128_SHA (rsa 2048) - C
      TLS_RSA_WITH_NULL_SHA (rsa 2048) - F
    compressors:
      NULL
  least strength: F
"""


class TestTlsCipherAccuracy(unittest.TestCase):
    def test_healthy_tls_raises_nothing(self):
        self.assertEqual(_ids([("ssl-enum-ciphers", STRONG_TLS)]), set())

    def test_null_compressor_is_not_a_null_cipher(self):
        # Every ssl-enum-ciphers block lists 'NULL' as an offered compressor.
        # Matching the token anywhere in the output reported a NULL cipher
        # suite — a CRITICAL — against every healthy TLS service.
        self.assertNotIn("TLS_NULL_CIPHER", _ids([("ssl-enum-ciphers", STRONG_TLS)]))

    def test_real_null_cipher_suite_is_reported(self):
        self.assertIn("TLS_NULL_CIPHER", _ids([("ssl-enum-ciphers", WEAK_TLS)]))

    def test_grade_a_does_not_fire_the_grade_rule(self):
        self.assertNotIn("TLS_WEAK_CIPHER_GRADE", _ids([("ssl-enum-ciphers", STRONG_TLS)]))

    def test_ciphers_are_attributed_to_their_protocol(self):
        survey = scriptdata.parse_tls_ciphers(WEAK_TLS)
        self.assertEqual(survey.protocols, ["SSLv3"])
        self.assertEqual(len(survey.ciphers["SSLv3"]), 2)
        self.assertEqual(survey.least_strength, "F")


class TestDhModulusAccuracy(unittest.TestCase):
    def test_weak_modulus_after_a_strong_one_is_found(self):
        output = "  Modulus Length: 2048\n  Modulus Length: 1024\n"
        self.assertIn("TLS_DH_WEAK_GROUP", _ids([("ssl-dh-params", output)]))

    def test_all_strong_moduli_raise_nothing(self):
        output = "  Modulus Length: 2048\n  Modulus Length: 4096\n"
        self.assertNotIn("TLS_DH_WEAK_GROUP", _ids([("ssl-dh-params", output)]))

    def test_every_modulus_is_parsed(self):
        self.assertEqual(
            scriptdata.parse_dh_moduli("Modulus Length: 2048\nModulus Length: 1024\n"),
            [2048, 1024],
        )


MONGO_REFUSED = """
  ERROR: not authorized on admin to execute command { listDatabases: 1.0 }
"""

MONGO_OPEN = """
  databases
    0
      name = admin
      sizeOnDisk = 83886080
  totalSize = 83886080
  ok = 1
"""


class TestDatastoreAccuracy(unittest.TestCase):
    def test_authorisation_error_is_not_read_as_open_access(self):
        # MongoDB's refusal quotes the command it rejected, which contains the
        # word 'listDatabases' — enough for the old pattern to fire.
        self.assertNotIn("MONGODB_NO_AUTH", _ids([("mongodb-databases", MONGO_REFUSED)]))

    def test_genuinely_open_instance_is_reported(self):
        self.assertIn("MONGODB_NO_AUTH", _ids([("mongodb-databases", MONGO_OPEN)]))

    def test_redis_requiring_auth_is_not_reported(self):
        output = "  ERROR: NOAUTH Authentication required.\n"
        self.assertNotIn("REDIS_NO_AUTH", _ids([("redis-info", output)]))


NLA_ENFORCED = """
  Security layer
    CredSSP (NLA): SUCCESS
    CredSSP with Early User Auth: FAILED
    Native RDP: FAILED
  RDP Encryption level: High
"""

NLA_OPTIONAL = """
  Security layer
    CredSSP (NLA): SUCCESS
    CredSSP with Early User Auth: SUCCESS
    Native RDP: SUCCESS
    SSL: SUCCESS
"""


class TestRdpAccuracy(unittest.TestCase):
    def test_early_user_auth_failure_is_not_nla_being_off(self):
        # Very common on healthy servers, and the old pattern read it as NLA
        # not being enforced.
        self.assertNotIn("RDP_NLA_DISABLED", _ids([("rdp-enum-encryption", NLA_ENFORCED)]))
        self.assertTrue(scriptdata.rdp_nla_enforced(NLA_ENFORCED))

    def test_accepted_legacy_layer_is_reported(self):
        self.assertIn("RDP_NLA_DISABLED", _ids([("rdp-enum-encryption", NLA_OPTIONAL)]))

    def test_unreadable_output_returns_none(self):
        self.assertIsNone(scriptdata.rdp_nla_enforced("  RDP Encryption level: High\n"))


class TestExposureConfidence(unittest.TestCase):
    def _weaknesses(self, service, **kw):
        host = Host(address="10.0.0.1", status="up")
        host.ports.append(Port(portid=3306, state="open", service=service))
        scan = ScanRun(source="t.xml", fmt="xml", hosts=[host], start_epoch=SCAN_EPOCH)
        return detect([scan], **kw)

    def test_port_table_guess_is_tentative(self):
        # Without -sV, 'mysql on 3306' is a guess about what is listening.
        found = self._weaknesses(Service(name="mysql", method="table"))
        self.assertEqual([w.confidence for w in found], ["tentative"])

    def test_probed_service_is_confirmed(self):
        found = self._weaknesses(
            Service(name="mysql", product="MySQL", version="5.7.40", method="probed")
        )
        self.assertEqual([w.confidence for w in found], ["confirmed"])

    def test_tentative_rows_are_withheld_at_the_firm_floor(self):
        found = self._weaknesses(Service(name="mysql", method="table"), min_confidence="firm")
        self.assertEqual(found, [])


OPENSSH_CVE = {
    "id": "CVE-2020-15778",
    "descriptions": [{"lang": "en", "value": "scp in OpenSSH allows command injection."}],
    "metrics": {
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 7.8, "vectorString": "CVSS:3.1/AV:N",
                          "baseSeverity": "HIGH"}}
        ]
    },
    "published": "2020-07-24T22:15:00",
    "references": [{"url": "https://example.invalid/a"}],
    "configurations": [
        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*"}]}]}
    ],
}

NGINX_CVE = dict(OPENSSH_CVE, id="CVE-2019-20372", configurations=[
    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:1.16.0:*:*:*:*:*:*:*"}]}]}
])


class _StubNvd:
    """Stands in for NVDClient so the matcher can be tested without network."""

    def __init__(self, records):
        self.records = records
        self.errors: list = []

    def by_cpe(self, cpe23):
        return list(self.records)

    def by_keyword(self, keyword):
        return list(self.records)


def _ssh_analysis(version, extrainfo=""):
    host = Host(address="10.0.0.1", status="up", hostnames=["h"])
    host.ports.append(
        Port(
            portid=22,
            state="open",
            service=Service(
                name="ssh",
                product="OpenSSH",
                version=version,
                extrainfo=extrainfo,
                method="probed",
                cpes=["cpe:/a:openbsd:openssh:8.2p1"],
            ),
        )
    )
    analysis = Analysis()
    analysis.scans.append(
        ScanRun(source="t.xml", fmt="xml", args="nmap -sV", hosts=[host], start_epoch=SCAN_EPOCH)
    )
    return analysis


class TestBackportSuppression(unittest.TestCase):
    """Distribution builds carry backported fixes without changing the version."""

    def test_distribution_banner_is_detected(self):
        self.assertTrue(
            looks_backported(
                Service(version="8.2p1 Ubuntu 4ubuntu0.5", extrainfo="Ubuntu Linux; protocol 2.0")
            )
        )
        self.assertTrue(looks_backported(Service(version="1.1.1f-1ubuntu2.16")))
        self.assertFalse(looks_backported(Service(version="8.2p1", extrainfo="protocol 2.0")))

    def test_backported_findings_are_withheld_by_default(self):
        analysis = _ssh_analysis("8.2p1 Ubuntu 4ubuntu0.5", "Ubuntu Linux; protocol 2.0")
        Matcher(_StubNvd([OPENSSH_CVE]), None).run(analysis)
        self.assertEqual(analysis.findings, [])
        self.assertTrue(analysis.suppressed)

    def test_backported_findings_can_be_asked_for(self):
        analysis = _ssh_analysis("8.2p1 Ubuntu 4ubuntu0.5", "Ubuntu Linux; protocol 2.0")
        Matcher(_StubNvd([OPENSSH_CVE]), None, include_backported=True).run(analysis)
        self.assertEqual([f.cve for f in analysis.findings], ["CVE-2020-15778"])
        self.assertTrue(analysis.findings[0].backport_suspected)

    def test_upstream_banner_is_not_suppressed(self):
        analysis = _ssh_analysis("8.2p1", "protocol 2.0")
        Matcher(_StubNvd([OPENSSH_CVE]), None).run(analysis)
        self.assertEqual([f.cve for f in analysis.findings], ["CVE-2020-15778"])


class TestProductVerification(unittest.TestCase):
    def test_cve_for_another_product_is_dropped(self):
        analysis = _ssh_analysis("8.2p1", "protocol 2.0")
        Matcher(_StubNvd([NGINX_CVE]), None).run(analysis)
        self.assertEqual(analysis.findings, [])
        self.assertTrue(analysis.suppressed)

    def test_verification_can_be_turned_off(self):
        analysis = _ssh_analysis("8.2p1", "protocol 2.0")
        Matcher(_StubNvd([NGINX_CVE]), None, verify_cpe=False).run(analysis)
        self.assertEqual(len(analysis.findings), 1)

    def test_record_without_applicability_data_is_kept(self):
        self.assertTrue(cve_matches_product({"id": "CVE-1"}, "cpe:2.3:a:openbsd:openssh:8.2:*"))


class TestKeywordSearchIsOptIn(unittest.TestCase):
    def test_unmapped_product_is_not_keyword_searched_by_default(self):
        port = Port(portid=9999, state="open",
                    service=Service(name="unknown", product="Frobnicator Server",
                                    version="1.0", method="probed"))
        self.assertEqual(build_queries(port), [])

    def test_keyword_search_can_be_requested(self):
        port = Port(portid=9999, state="open",
                    service=Service(name="unknown", product="Frobnicator Server",
                                    version="1.0", method="probed"))
        queries = build_queries(port, allow_keyword=True)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].keyword, "Frobnicator Server 1.0")

    def test_unmapped_product_is_recorded_as_unassessed(self):
        host = Host(address="10.0.0.1", status="up", hostnames=["h"])
        host.ports.append(
            Port(portid=9999, state="open",
                 service=Service(name="unknown", product="Frobnicator Server",
                                 version="1.0", method="probed"))
        )
        analysis = Analysis()
        analysis.scans.append(ScanRun(source="t.xml", fmt="xml", hosts=[host]))
        Matcher(_StubNvd([]), None).run(analysis)
        self.assertTrue(any("no CPE mapping" in s for s in analysis.skipped_services))


class TestCpePartField(unittest.TestCase):
    """Operating systems need part 'o'; a cpe:2.3:a:microsoft:windows matches nothing."""

    def test_operating_systems_use_the_os_part(self):
        from nmapvuln.match import PRODUCT_CPE

        self.assertTrue(PRODUCT_CPE["microsoft windows rpc"].startswith("o:"))
        self.assertTrue(PRODUCT_CPE["vmware esxi"].startswith("o:"))

    def test_applications_use_the_application_part(self):
        from nmapvuln.match import PRODUCT_CPE

        self.assertEqual(PRODUCT_CPE["openssh"], "a:openbsd:openssh")

    def test_synthesised_cpe_carries_the_part(self):
        port = Port(portid=443, state="open",
                    service=Service(name="http", product="VMware ESXi", version="6.7",
                                    method="probed"))
        self.assertTrue(build_queries(port)[0].cpe23.startswith("cpe:2.3:o:vmware:esxi:6.7"))

class TestHealthyHostIsQuiet(unittest.TestCase):
    """The whole-file guard: a well-configured host must produce no defects.

    sample-healthy.xml is modern TLS with a CA-issued EC certificate, current
    SSH algorithms, Ed25519 and 3072-bit RSA host keys, SMB signing required,
    RDP with NLA enforced, and datastores that refuse the probe. The committed
    version of this tool reported nine weaknesses against it, including a
    CRITICAL. Anything this test sees beyond plain reachability is a regression.
    """

    @classmethod
    def setUpClass(cls):
        cls.scans = parse_file(os.path.join(SAMPLES, "sample-healthy.xml"))
        cls.all = detect(cls.scans)
        cls.shown = [w for w in cls.all if w.confidence != "tentative"]

    def test_no_defects_are_reported(self):
        defects = [w for w in self.shown if w.category != "exposure"]
        self.assertEqual(
            [(w.rule_id, w.port, w.evidence) for w in defects],
            [],
            "healthy host produced a finding that is not merely reachability",
        )

    def test_reachability_is_still_noted(self):
        # Mongo and Redis really are reachable from where the scan ran. That is
        # worth recording, which is why it is kept — graded low, not medium.
        rules = {w.rule_id for w in self.shown}
        self.assertEqual(rules, {"DATA_SERVICE_EXPOSED"})
        self.assertTrue(all(w.severity == "LOW" for w in self.shown))

    def test_exposure_can_be_dropped_entirely(self):
        self.assertEqual(detect(self.scans, include_exposure=False), [])

    def test_port_table_guess_is_withheld(self):
        # 8081 was guessed as mysql from the port number alone.
        withheld = [w for w in self.all if w.confidence == "tentative"]
        self.assertEqual([w.port for w in withheld], ["8081/tcp"])


class TestFlagCombinations(unittest.TestCase):
    def test_kev_only_offline_is_refused(self):
        # Without the catalog the filter would discard every finding, so the
        # combination is rejected rather than silently emptying the report.
        from nmapvuln.cli import main

        with self.assertRaises(SystemExit) as caught:
            main(["samples", "--offline", "--kev-only"])
        self.assertNotEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
