"""Non-CVE weakness detection.

A large share of what is actually reportable in an nmap scan has no CVE
attached to it: a 1024-bit DH group, SMB signing left off, anonymous FTP,
an expired certificate, RC4 still enabled, a database listening on a public
interface. None of that shows up in a CPE-to-CVE correlation, so it is matched
here instead — against NSE script output, and against the service inventory
itself for things that are a weakness purely by being exposed.

Detection happens two ways, and the difference is what keeps the output clean:

* **Analysers** parse a script's output into values and reason over them
  (see :mod:`nmapvuln.scriptdata`). Every script carrying real structure goes
  through one, because a text pattern over ``ssl-cert`` cannot tell "expires
  in 2031" from "expired in 2016", and a pattern over ``ssh2-enum-algos``
  cannot tell a MAC name from a cipher name.
* **Pattern rules** cover scripts whose whole output is already a verdict
  ("Anonymous FTP login allowed"). These now scan every match in the output
  rather than only the first, so a weak value listed after a strong one is not
  missed.

Each weakness carries a confidence. Anything ``tentative`` is withheld from the
report unless asked for, because a finding the reader has to disprove costs
more than it is worth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from . import scriptdata
from .model import WEAKNESS_CONFIDENCE, Host, Port, ScanRun, Script, Weakness

# ---------------------------------------------------------------------------
# Catalogue: the fixed text and grading for each weakness, independent of how
# it was detected.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Spec:
    title: str
    severity: str
    category: str
    recommendation: str


SPECS: dict[str, Spec] = {
    # -- TLS transport ------------------------------------------------------
    "TLS_SSLV2": Spec(
        "SSLv2 enabled (DROWN)", "HIGH", "tls",
        "Disable SSLv2 entirely. It is broken beyond repair and its presence "
        "undermines TLS on other services sharing the same key.",
    ),
    "TLS_SSLV3": Spec(
        "SSLv3 enabled (POODLE)", "MEDIUM", "tls",
        "Disable SSLv3. Modern clients do not need it, and CBC padding in SSLv3 "
        "is exploitable via POODLE.",
    ),
    "TLS_DEPRECATED_VERSION": Spec(
        "Deprecated TLS version enabled (TLS 1.0 / 1.1)", "LOW", "tls",
        "Disable TLS 1.0 and 1.1. Both are deprecated by RFC 8996 and fail PCI "
        "DSS; enable TLS 1.2 and 1.3 only.",
    ),
    "TLS_NULL_CIPHER": Spec(
        "NULL cipher suite offered (no encryption)", "CRITICAL", "tls",
        "Disable NULL cipher suites immediately — traffic is authenticated but "
        "sent in cleartext.",
    ),
    "TLS_EXPORT_CIPHER": Spec(
        "Export-grade cipher suite offered (FREAK)", "HIGH", "tls",
        "Disable all EXPORT cipher suites; their key sizes are breakable in "
        "minutes on commodity hardware.",
    ),
    "TLS_RC4": Spec(
        "RC4 cipher suite offered", "MEDIUM", "tls",
        "Disable RC4 (RFC 7465). Its keystream biases allow plaintext recovery "
        "against repeated secrets such as session cookies.",
    ),
    "TLS_3DES": Spec(
        "3DES / DES cipher suite offered (Sweet32)", "MEDIUM", "tls",
        "Disable 64-bit block ciphers. Sweet32 recovers plaintext from "
        "long-lived connections carrying a repeated secret.",
    ),
    "TLS_DH_ANONYMOUS": Spec(
        "Anonymous Diffie-Hellman key exchange offered", "HIGH", "tls",
        "Disable anonymous cipher suites — they provide encryption with no "
        "authentication, so the session can be trivially machine-in-the-middled.",
    ),
    "TLS_WEAK_CIPHER_GRADE": Spec(
        "Weak overall cipher strength reported by nmap", "MEDIUM", "tls",
        "Review the enabled cipher suite list; nmap graded the weakest offered "
        "suite below B.",
    ),
    "TLS_DH_WEAK_GROUP": Spec(
        "Weak Diffie-Hellman group (insufficient modulus strength)", "MEDIUM", "tls",
        "Use a 2048-bit or larger DH group, or switch to ECDHE key exchange. "
        "Regenerate the group rather than reusing a common one.",
    ),
    "TLS_DH_EXPORT_GRADE": Spec(
        "Export-grade Diffie-Hellman group (Logjam)", "HIGH", "tls",
        "Disable all export cipher suites. Export-grade DH is trivially broken "
        "and enables downgrade attacks against otherwise-strong sessions.",
    ),
    # -- TLS certificate ----------------------------------------------------
    "TLS_CERT_EXPIRED": Spec(
        "TLS certificate has expired", "MEDIUM", "tls",
        "Renew the certificate and automate renewal. Expired certificates train "
        "users to click through warnings.",
    ),
    "TLS_CERT_NOT_YET_VALID": Spec(
        "TLS certificate is not yet valid", "LOW", "tls",
        "Check the certificate's validity window and the host's clock.",
    ),
    "TLS_CERT_SELF_SIGNED": Spec(
        "Self-signed TLS certificate", "LOW", "tls",
        "Use a certificate from a trusted CA on anything user-facing; "
        "self-signed certificates cannot be validated by clients.",
    ),
    "TLS_CERT_WEAK_KEY": Spec(
        "Certificate public key is undersized", "MEDIUM", "tls",
        "Re-issue with a 2048-bit or larger RSA key, or a 256-bit ECDSA key.",
    ),
    "TLS_CERT_WEAK_SIGNATURE": Spec(
        "Certificate signed with a weak hash (MD5 / SHA-1)", "MEDIUM", "tls",
        "Re-issue the certificate with SHA-256 or stronger. SHA-1 collisions are "
        "practical and browsers reject such certificates.",
    ),
    # -- SSH ----------------------------------------------------------------
    "SSH_WEAK_KEX": Spec(
        "Weak SSH key exchange algorithm offered", "MEDIUM", "ssh",
        "Restrict KexAlgorithms to curve25519-sha256 and "
        "diffie-hellman-group-exchange-sha256 or better. Group1 is a fixed "
        "1024-bit group and is considered breakable by well-resourced attackers.",
    ),
    "SSH_WEAK_MAC": Spec(
        "Weak SSH MAC algorithm offered", "LOW", "ssh",
        "Restrict MACs to encrypt-then-MAC variants such as "
        "hmac-sha2-256-etm@openssh.com.",
    ),
    "SSH_WEAK_CIPHER": Spec(
        "Weak SSH cipher offered (CBC mode / arcfour / 3DES)", "MEDIUM", "ssh",
        "Restrict Ciphers to AEAD suites such as chacha20-poly1305@openssh.com "
        "and aes256-gcm@openssh.com. CBC modes are vulnerable to plaintext "
        "recovery in SSH.",
    ),
    "SSH_WEAK_HOSTKEY_TYPE": Spec(
        "DSA (ssh-dss) host key in use", "MEDIUM", "ssh",
        "Remove DSA host keys. They are fixed at 1024 bits and disabled by "
        "default in modern OpenSSH; use Ed25519 or RSA-2048+.",
    ),
    "SSH_WEAK_HOSTKEY_SIZE": Spec(
        "Undersized SSH host key", "MEDIUM", "ssh",
        "Regenerate the host key at 2048 bits or larger, or switch to Ed25519.",
    ),
    # -- RDP ----------------------------------------------------------------
    "RDP_NLA_DISABLED": Spec(
        "RDP Network Level Authentication not enforced", "MEDIUM", "auth",
        "Require NLA. Without it, RDP is exposed to pre-authentication attacks "
        "and credential capture.",
    ),
    # -- Unauthenticated datastores ----------------------------------------
    "MONGODB_NO_AUTH": Spec(
        "MongoDB accessible without authentication", "CRITICAL", "auth",
        "Enable authentication and bind MongoDB to localhost or a private "
        "interface. Unauthenticated instances are mass-scanned and ransomed.",
    ),
    "REDIS_NO_AUTH": Spec(
        "Redis accessible without authentication", "CRITICAL", "auth",
        "Set requirepass, enable protected-mode and bind to a private interface. "
        "Unauthenticated Redis leads to code execution via config rewrite.",
    ),
    "ELASTICSEARCH_EXPOSED": Spec(
        "Elasticsearch accessible without authentication", "CRITICAL", "auth",
        "Enable authentication and restrict network access; open Elasticsearch "
        "clusters expose the entire indexed dataset.",
    ),
    "LDAP_ANONYMOUS_BIND": Spec(
        "LDAP anonymous bind permitted", "MEDIUM", "auth",
        "Disable anonymous bind. It exposes the directory structure and often "
        "the full user list.",
    ),
}


# ---------------------------------------------------------------------------
# Analysers for scripts with structured output
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    rule_id: str
    evidence: str
    confidence: str = "firm"
    severity: str = ""  # overrides the catalogue grading when set


def _tls_cipher_flaws(name: str) -> list[str]:
    """Which weaknesses one cipher suite name implies."""
    upper = name.upper()
    out = []
    if "WITH_NULL" in upper or "_NULL_" in upper or upper.endswith("_NULL"):
        out.append("TLS_NULL_CIPHER")
    if "EXPORT" in upper:
        out.append("TLS_EXPORT_CIPHER")
    if "RC4" in upper:
        out.append("TLS_RC4")
    if "3DES" in upper or "_DES_CBC" in upper or "_DES_" in upper:
        out.append("TLS_3DES")
    if "_ANON_" in upper or "DH_ANON" in upper:
        out.append("TLS_DH_ANONYMOUS")
    return out


def analyse_tls_ciphers(script: Script, _scan: ScanRun) -> list[Detection]:
    survey = scriptdata.parse_tls_ciphers(script.output)
    if survey is None:
        return []

    out: list[Detection] = []
    for protocol in survey.protocols:
        upper = protocol.upper()
        if upper == "SSLV2":
            out.append(Detection("TLS_SSLV2", f"{protocol} accepted", "confirmed"))
        elif upper == "SSLV3":
            out.append(Detection("TLS_SSLV3", f"{protocol} accepted", "confirmed"))
        elif upper in ("TLSV1.0", "TLSV1.1"):
            out.append(Detection("TLS_DEPRECATED_VERSION", f"{protocol} accepted", "confirmed"))

    # One row per flaw, naming the suites that caused it, rather than one row
    # per suite: a server offering six RC4 suites has one RC4 problem.
    grouped: dict[str, list[str]] = {}
    for protocol, cipher in survey.all_ciphers():
        for rule_id in _tls_cipher_flaws(cipher):
            grouped.setdefault(rule_id, []).append(f"{protocol} {cipher}")
    for rule_id, hits in grouped.items():
        unique = sorted(set(hits))
        evidence = "; ".join(unique[:4])
        if len(unique) > 4:
            evidence += f" (+{len(unique) - 4} more)"
        out.append(Detection(rule_id, evidence, "confirmed"))

    # nmap grades the weakest suite A..F. Anything past B is worth a look.
    if survey.least_strength in ("C", "D", "E", "F"):
        out.append(
            Detection(
                "TLS_WEAK_CIPHER_GRADE", f"least strength: {survey.least_strength}", "confirmed"
            )
        )
    return out


def analyse_dh_params(script: Script, _scan: ScanRun) -> list[Detection]:
    moduli = scriptdata.parse_dh_moduli(script.output)
    out: list[Detection] = []
    weak = [m for m in moduli if m < 2048]
    if weak:
        out.append(
            Detection(
                "TLS_DH_WEAK_GROUP",
                "Modulus Length: " + ", ".join(str(m) for m in sorted(set(weak))),
                "confirmed",
                severity="HIGH" if min(weak) < 1024 else "MEDIUM",
            )
        )
    text = scriptdata.normalise(script.output)
    if re.search(r"EXPORT[- ]GRADE DH GROUP", text, re.I):
        out.append(Detection("TLS_DH_EXPORT_GRADE", "export-grade DH group offered", "confirmed"))
    if re.search(r"ANONYMOUS DH GROUP", text, re.I):
        out.append(Detection("TLS_DH_ANONYMOUS", "anonymous DH group offered", "confirmed"))
    return out


def analyse_certificate(script: Script, scan: ScanRun) -> list[Detection]:
    cert = scriptdata.parse_certificate(script.output)
    if cert is None:
        return []

    when = scan.reference_time
    out: list[Detection] = []

    # The date is compared, not the presence of the phrase. Every certificate
    # nmap prints carries a "Not valid after" line, healthy ones included.
    if cert.expired_at(when):
        days = (when - cert.not_after).days
        out.append(
            Detection(
                "TLS_CERT_EXPIRED",
                f"Not valid after: {cert.not_after:%Y-%m-%d} "
                f"({days} day(s) before the scan ran)",
                "confirmed",
            )
        )
    if cert.not_yet_valid_at(when):
        out.append(
            Detection(
                "TLS_CERT_NOT_YET_VALID",
                f"Not valid before: {cert.not_before:%Y-%m-%d}",
                "confirmed",
            )
        )
    if cert.self_signed:
        out.append(Detection("TLS_CERT_SELF_SIGNED", f"Subject == Issuer: {cert.subject}"[:300]))
    if cert.weak_key:
        out.append(
            Detection(
                "TLS_CERT_WEAK_KEY",
                f"Public Key type: {cert.key_type or 'unknown'}, bits: {cert.key_bits}",
                "confirmed",
            )
        )
    if cert.weak_signature:
        out.append(
            Detection(
                "TLS_CERT_WEAK_SIGNATURE",
                f"Signature Algorithm: {cert.signature_algorithm}",
                "confirmed",
            )
        )
    return out


# Algorithm names that are weak, checked only inside the list they belong to.
# Deliberately conservative: 'hmac-sha1' and 'ssh-rsa' are deprecated but still
# the default on a great many healthy hosts, and flagging them buries the rest.
WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-group1-sha1",
        "rsa1024-sha1",
    }
)
WEAK_MAC = frozenset({"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64", "hmac-ripemd160"})
WEAK_HOSTKEY_ALGO = frozenset({"ssh-dss"})


def _weak_ssh_cipher(name: str) -> bool:
    lowered = name.lower().split("@")[0]
    if lowered.endswith("-cbc"):
        return True
    return lowered.startswith("arcfour") or lowered in ("none", "des")


def analyse_ssh_algorithms(script: Script, _scan: ScanRun) -> list[Detection]:
    lists = scriptdata.parse_ssh_algorithms(script.output)
    if not lists:
        return []

    out: list[Detection] = []

    def hits(key: str, predicate: Callable[[str], bool]) -> list[str]:
        return [a for a in lists.get(key, []) if predicate(a)]

    kex = hits("kex_algorithms", lambda a: a.lower() in WEAK_KEX)
    if kex:
        out.append(Detection("SSH_WEAK_KEX", "kex_algorithms: " + ", ".join(kex), "confirmed"))

    # umac-64-etm@openssh.com is fine; only the bare truncated variants are
    # weak, so this compares whole algorithm names rather than substrings.
    macs = hits("mac_algorithms", lambda a: a.lower().split("@")[0] in WEAK_MAC)
    if macs:
        out.append(Detection("SSH_WEAK_MAC", "mac_algorithms: " + ", ".join(macs), "confirmed"))

    ciphers = hits("encryption_algorithms", _weak_ssh_cipher)
    if ciphers:
        out.append(
            Detection(
                "SSH_WEAK_CIPHER", "encryption_algorithms: " + ", ".join(ciphers), "confirmed"
            )
        )

    keys = hits("server_host_key_algorithms", lambda a: a.lower() in WEAK_HOSTKEY_ALGO)
    if keys:
        out.append(
            Detection(
                "SSH_WEAK_HOSTKEY_TYPE",
                "server_host_key_algorithms: " + ", ".join(keys),
                "confirmed",
            )
        )
    return out


def analyse_host_keys(script: Script, _scan: ScanRun) -> list[Detection]:
    keys = scriptdata.parse_host_keys(script.output)
    if not keys:
        return []

    out: list[Detection] = []
    # Sized against the key's own algorithm: a 256-bit Ed25519 key is strong,
    # and a flat 2048-bit floor reports every modern host as weak.
    undersized = [k for k in keys if k.undersized]
    if undersized:
        out.append(
            Detection(
                "SSH_WEAK_HOSTKEY_SIZE",
                ", ".join(f"{k.bits}-bit {k.algorithm}" for k in undersized),
                "confirmed",
            )
        )
    dsa = [k for k in keys if k.family in ("dss", "dsa")]
    if dsa:
        out.append(
            Detection(
                "SSH_WEAK_HOSTKEY_TYPE",
                ", ".join(f"{k.bits}-bit {k.algorithm}" for k in dsa),
                "confirmed",
            )
        )
    return out


def analyse_rdp(script: Script, _scan: ScanRun) -> list[Detection]:
    # "CredSSP with Early User Auth: FAILED" is normal on a server that does
    # require NLA, so only an accepted non-CredSSP layer counts.
    if scriptdata.rdp_nla_enforced(script.output) is not False:
        return []
    return [
        Detection(
            "RDP_NLA_DISABLED",
            "a non-CredSSP security layer was accepted (Native RDP or SSL)",
            "confirmed",
        )
    ]


def _datastore_analyser(rule_id: str, marker: str) -> Callable[[Script, ScanRun], list[Detection]]:
    """Fire only when the probe returned data *and* was not refused.

    The naive form of this check reads "the script produced output naming the
    product, therefore no authentication is required". That is wrong whenever
    the output is an authorisation error that happens to name the product:
    MongoDB's refusal quotes the command it rejected, ``listDatabases``.
    """

    def analyse(script: Script, _scan: ScanRun) -> list[Detection]:
        text = scriptdata.normalise(script.output)
        if not text.strip() or scriptdata.script_reports_auth_error(text):
            return []
        match = re.search(marker, text, re.I | re.M)
        if not match:
            return []
        return [Detection(rule_id, f"{script.id}: {match.group(0).strip()}"[:300], "firm")]

    return analyse


ANALYSERS: dict[str, Callable[[Script, ScanRun], list[Detection]]] = {
    "ssl-enum-ciphers": analyse_tls_ciphers,
    "ssl-dh-params": analyse_dh_params,
    "ssl-cert": analyse_certificate,
    "ssh2-enum-algos": analyse_ssh_algorithms,
    "ssh-hostkey": analyse_host_keys,
    "rdp-enum-encryption": analyse_rdp,
    "mongodb-databases": _datastore_analyser(
        "MONGODB_NO_AUTH", r"^\s*(?:totalSize|databases)\b.*$"
    ),
    "mongodb-info": _datastore_analyser("MONGODB_NO_AUTH", r"^.*\bMongoDB Build info\b.*$"),
    "redis-info": _datastore_analyser("REDIS_NO_AUTH", r"^\s*redis_version\s*[:=].*$"),
    "http-elasticsearch-head": _datastore_analyser(
        "ELASTICSEARCH_EXPOSED", r"^.*\b(?:cluster_name|number_of_nodes)\b.*$"
    ),
    "ldap-rootdse": _datastore_analyser("LDAP_ANONYMOUS_BIND", r"^\s*namingContexts\s*:.*$"),
}


# ---------------------------------------------------------------------------
# Pattern rules: scripts whose output is already a verdict
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    recommendation: str
    scripts: tuple[str, ...] = ()  # NSE script ids; empty = any script
    pattern: str = ""
    confidence: str = "confirmed"
    flags: int = re.I | re.M


TLS_RULES = [
    Rule(
        id="TLS_HEARTBLEED",
        title="OpenSSL Heartbleed memory disclosure",
        severity="CRITICAL",
        category="tls",
        scripts=("ssl-heartbleed",),
        pattern=r"State:\s*(VULNERABLE)",
        recommendation="Patch OpenSSL immediately, then rotate every key, certificate and "
        "credential that was in memory on the affected host.",
    ),
    Rule(
        id="TLS_CCS_INJECTION",
        title="OpenSSL CCS injection",
        severity="HIGH",
        category="tls",
        scripts=("ssl-ccs-injection",),
        pattern=r"State:\s*(VULNERABLE)",
        recommendation="Patch OpenSSL. An attacker in path can force a weak key and "
        "decrypt or modify the session.",
    ),
]

SSH_RULES = [
    Rule(
        id="SSH_V1_SUPPORTED",
        title="SSH protocol version 1 supported",
        severity="HIGH",
        category="ssh",
        # Dropped ssh2-enum-algos from this rule: that script never reports the
        # protocol version, so matching its output was matching nothing useful.
        scripts=("sshv1",),
        pattern=r"(Server supports SSHv1|SSH-1\.\d)",
        recommendation="Disable SSHv1. It has fundamental integrity flaws and no modern "
        "client requires it.",
    ),
]

SMB_RULES = [
    Rule(
        id="SMB_SIGNING_DISABLED",
        title="SMB message signing not required",
        severity="MEDIUM",
        category="smb",
        scripts=("smb-security-mode", "smb2-security-mode"),
        # nmap prints 'message_signing: disabled (dangerous, but default)' for SMB1
        # and 'Message signing enabled but not required' for SMB2.
        pattern=r"(message[_ ]signing:?\s*(?:disabled|enabled but not required)[^\n]*)",
        recommendation="Require SMB signing on servers and clients. Without it, NTLM "
        "relay attacks let an attacker authenticate as a captured user.",
    ),
    Rule(
        id="SMB_V1_ENABLED",
        title="SMBv1 enabled",
        severity="HIGH",
        category="smb",
        # smb-os-discovery dropped: it names the dialect in passing on hosts
        # that do not actually offer SMBv1.
        scripts=("smb-protocols",),
        pattern=r"^\s*(NT LM 0\.12[^\n]*|SMBv1[^\n]*)",
        recommendation="Disable SMBv1 entirely. It is unpatchable by design, and is the "
        "transport for EternalBlue-class attacks.",
    ),
    Rule(
        id="SMB_GUEST_ACCESS",
        title="SMB guest or anonymous access permitted",
        severity="HIGH",
        category="smb",
        scripts=("smb-enum-shares", "smb-enum-users", "smb-security-mode"),
        pattern=r"(Anonymous access:\s*READ[^\n]*"
        # "account_used: <blank>" is dropped: nmap prints it whenever it read
        # the security mode over a null session, which most Windows hosts
        # allow for that query alone. The finding is anonymous *enumeration*,
        # not the null session, so only guest access and readable shares count.
        r"|account_used:\s*guest[^\n]*"
        r"|Account that was used for enumeration:\s*guest[^\n]*)",
        recommendation="Disable the guest account and require authentication for all "
        "shares; anonymous enumeration hands an attacker the user and share list.",
    ),
]

SERVICE_RULES = [
    Rule(
        id="FTP_ANONYMOUS",
        title="Anonymous FTP login allowed",
        severity="MEDIUM",
        category="auth",
        scripts=("ftp-anon",),
        pattern=r"(Anonymous FTP login allowed[^\n]*)",
        recommendation="Disable anonymous FTP, or confirm the exposed directory contains "
        "nothing sensitive and is not writable.",
    ),
    Rule(
        id="FTP_ANONYMOUS_WRITABLE",
        title="Anonymous FTP directory is writable",
        severity="HIGH",
        category="auth",
        scripts=("ftp-anon",),
        # A world-writable mode bit on a listed entry, or nmap saying so. The
        # previous form matched the word 'writable' anywhere within 400
        # characters of the login banner, which caught unrelated filenames.
        pattern=r"(^\s*[d-]rwxrwxrwx[^\n]*|writable by anonymous[^\n]*)",
        recommendation="An anonymously writable FTP root frequently leads to code "
        "execution when it is served by a web server. Remove write access.",
    ),
    Rule(
        id="DNS_OPEN_RECURSION",
        title="Open recursive DNS resolver",
        severity="MEDIUM",
        category="exposure",
        scripts=("dns-recursion",),
        pattern=r"(Recursion appears to be enabled[^\n]*)",
        recommendation="Restrict recursion to trusted networks. Open resolvers are "
        "abused as amplifiers in DDoS reflection attacks.",
    ),
    Rule(
        id="SNMP_DEFAULT_COMMUNITY",
        title="SNMP readable with a default community string",
        severity="HIGH",
        category="auth",
        # Only the brute-force result proves the community string worked.
        # Reading the word 'public' out of arbitrary snmp-info output flags
        # every device whose system description happens to contain it.
        scripts=("snmp-brute",),
        pattern=r"^\s*(public|private)\s*-\s*Valid credentials",
        recommendation="Change the community string and restrict SNMP by source address, "
        "or move to SNMPv3 with authentication and encryption.",
    ),
    Rule(
        id="NFS_EXPORTS",
        title="NFS exports readable",
        severity="MEDIUM",
        category="exposure",
        scripts=("nfs-showmount",),
        pattern=r"^\s*(/\S+\s+\S+)",  # an export path followed by its client spec
        recommendation="Restrict NFS exports to specific hosts and enable root squashing; "
        "world-readable exports frequently expose backups and home directories.",
    ),
    Rule(
        id="HTTP_DANGEROUS_METHODS",
        title="Dangerous HTTP methods enabled (PUT / DELETE)",
        severity="HIGH",
        category="http",
        scripts=("http-methods",),
        pattern=r"Potentially risky methods:\s*([^\n]*\b(?:PUT|DELETE)\b[^\n]*)",
        recommendation="Disable PUT and DELETE unless the application requires them. "
        "PUT on a web root is a direct path to code execution.",
    ),
    Rule(
        id="HTTP_TRACE_ENABLED",
        title="HTTP TRACE method enabled",
        severity="LOW",
        category="http",
        scripts=("http-methods", "http-trace"),
        pattern=r"(TRACE is enabled[^\n]*|Potentially risky methods:[^\n]*\bTRACE\b[^\n]*)",
        recommendation="Disable TRACE. It enables cross-site tracing to read headers that "
        "scripts are not meant to see.",
    ),
    Rule(
        id="HTTP_OPEN_PROXY",
        title="Open HTTP proxy",
        severity="HIGH",
        category="exposure",
        scripts=("http-open-proxy",),
        pattern=r"(Potentially OPEN proxy[^\n]*)",
        recommendation="Close the open proxy — it lets attackers reach internal systems "
        "and launder traffic through this host.",
    ),
    Rule(
        id="HTTP_GIT_EXPOSED",
        title="Exposed .git repository",
        severity="HIGH",
        category="info-disclosure",
        scripts=("http-git",),
        pattern=r"(Git repository found[^\n]*)",
        recommendation="Block access to .git. The full source history — often including "
        "committed credentials — can be reconstructed from it.",
    ),
    Rule(
        id="HTTP_BACKUP_FILES",
        title="Configuration or backup files exposed",
        severity="HIGH",
        category="info-disclosure",
        scripts=("http-config-backup", "http-backup-finder"),
        # '.zip' and '.tar.gz' dropped: legitimate downloads carry those
        # extensions, and the script lists every URL it tried.
        pattern=r"^\s*(\S+\.(?:bak|old|save|swp|sql|conf))\b",
        recommendation="Remove backup and configuration files from the web root; they "
        "routinely contain database credentials.",
    ),
    Rule(
        id="HTTP_DIR_LISTING",
        title="Directory listing enabled",
        severity="LOW",
        category="info-disclosure",
        scripts=("http-enum",),
        pattern=r"([^\n]*\bdirectory listing\b[^\n]*)",
        recommendation="Disable automatic directory indexing.",
    ),
    Rule(
        id="VNC_NO_AUTH",
        title="VNC accessible without authentication",
        severity="CRITICAL",
        category="auth",
        scripts=("vnc-info", "realvnc-auth-bypass"),
        # nmap lists security types one per line; 'None (1)' is the no-auth
        # type. The old pattern also matched the literal phrase 'no
        # authentication' wherever it appeared, including in advice text.
        pattern=r"^\s*(None\s*\(1\))",
        recommendation="Enable VNC authentication and place the service behind a VPN. "
        "Unauthenticated VNC is full interactive access to the desktop.",
    ),
    Rule(
        id="MYSQL_EMPTY_PASSWORD",
        title="MySQL account with an empty password",
        severity="CRITICAL",
        category="auth",
        scripts=("mysql-empty-password",),
        pattern=r"([^\n]*account has empty password[^\n]*)",
        recommendation="Set passwords on all accounts and remove anonymous users.",
    ),
]

# Weaknesses that follow from a service being reachable at all, independent of
# any script having run.
EXPOSURE_RULES: dict[str, tuple[str, str, str, str]] = {
    # service name -> (id, title, severity, recommendation)
    "telnet": (
        "CLEARTEXT_TELNET",
        "Telnet exposed (credentials sent in cleartext)",
        "HIGH",
        "Replace Telnet with SSH. Credentials and session content are transmitted "
        "unencrypted and are trivially captured on path.",
    ),
    "ftp": (
        "CLEARTEXT_FTP",
        "FTP exposed (credentials sent in cleartext)",
        "LOW",
        "Use FTPS or SFTP. Plain FTP transmits credentials in cleartext.",
    ),
    "rlogin": (
        "CLEARTEXT_RLOGIN",
        "rlogin exposed (cleartext, trust-based authentication)",
        "HIGH",
        "Disable rlogin; it authenticates on host trust and sends data in cleartext.",
    ),
    "rsh": (
        "CLEARTEXT_RSH",
        "rsh exposed (cleartext, trust-based authentication)",
        "HIGH",
        "Disable rsh and use SSH instead.",
    ),
    "finger": (
        "FINGER_EXPOSED",
        "finger service exposed (user enumeration)",
        "MEDIUM",
        "Disable the finger service; it enumerates local user accounts.",
    ),
    "pop3": (
        "CLEARTEXT_POP3",
        "POP3 exposed without implicit TLS",
        "LOW",
        "Require POP3S or enforce STARTTLS before authentication.",
    ),
    "imap": (
        "CLEARTEXT_IMAP",
        "IMAP exposed without implicit TLS",
        "LOW",
        "Require IMAPS or enforce STARTTLS before authentication.",
    ),
    "vnc": (
        "VNC_EXPOSED",
        "VNC exposed to the network",
        "MEDIUM",
        "Place VNC behind a VPN; it is a frequent target for brute force and its "
        "legacy authentication is weak.",
    ),
}

# Databases and internal services that should rarely be reachable externally.
EXPOSED_DATA_SERVICES = {
    "mysql": "MySQL",
    "ms-sql-s": "Microsoft SQL Server",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "memcached": "memcached",
    "elasticsearch": "Elasticsearch",
    "cassandra": "Cassandra",
    "couchdb": "CouchDB",
    "rabbitmq": "RabbitMQ",
    "docker": "Docker API",
    "kubernetes": "Kubernetes API",
    "zookeeper": "ZooKeeper",
}

ALL_RULES: list[Rule] = TLS_RULES + SSH_RULES + SMB_RULES + SERVICE_RULES

# Generic catch-all: any NSE vuln script that declares a VULNERABLE state but
# cites no CVE would otherwise be invisible to the CVE correlator.
_VULN_STATE = re.compile(r"State:\s*(VULNERABLE[^\n]*)", re.I)
_VULN_TITLE = re.compile(r"^\s*\|?\s*([A-Z][^\n|]{12,90})\s*$", re.M)


def _evidence(output: str, match: re.Match, span: int = 2) -> str:
    """Return the matching line plus a little surrounding context."""
    lines = output.splitlines()
    offset, running = 0, []
    for idx, line in enumerate(lines):
        running.append((idx, offset, offset + len(line)))
        offset += len(line) + 1

    hit = match.start()
    target = 0
    for idx, start, end in running:
        if start <= hit <= end:
            target = idx
            break

    lo = max(0, target - span // 2)
    chunk = lines[lo : target + span]
    cleaned = [re.sub(r"^\s*\|?_?\s*", "", ln).rstrip() for ln in chunk]
    return " / ".join(c for c in cleaned if c)[:300]


def _weakness(
    rule_id: str,
    host: Host,
    port: Optional[Port],
    scan: ScanRun,
    script_id: str,
    evidence: str,
    confidence: str,
    severity: str = "",
    spec: Optional[Spec] = None,
) -> Weakness:
    spec = spec or SPECS[rule_id]
    return Weakness(
        host=host.address,
        hostnames=", ".join(host.hostnames),
        port=port.key if port else "host",
        service=port.service.name if port else "",
        rule_id=rule_id,
        title=spec.title,
        severity=severity or spec.severity,
        category=spec.category,
        evidence=evidence,
        recommendation=spec.recommendation,
        source_script=script_id,
        scan_file=scan.source,
        confidence=confidence,
    )


def _apply_rules(
    scripts: list[Script], host: Host, port: Optional[Port], scan: ScanRun
) -> list[Weakness]:
    out: list[Weakness] = []
    for script in scripts:
        if not script.output:
            continue
        matched_specific = False

        analyser = ANALYSERS.get(script.id)
        if analyser is not None:
            for detection in analyser(script, scan):
                matched_specific = True
                out.append(
                    _weakness(
                        detection.rule_id,
                        host,
                        port,
                        scan,
                        script.id,
                        detection.evidence,
                        detection.confidence,
                        detection.severity,
                    )
                )

        for rule in ALL_RULES:
            if rule.scripts and script.id not in rule.scripts:
                continue
            # Every match, not just the first. A value below the threshold
            # listed after one above it is exactly what a single re.search
            # misses, and it misses it silently.
            for match in re.finditer(rule.pattern, script.output, rule.flags):
                matched_specific = True
                out.append(
                    _weakness(
                        rule.id,
                        host,
                        port,
                        scan,
                        script.id,
                        _evidence(script.output, match),
                        rule.confidence,
                        rule.severity,
                        spec=Spec(rule.title, rule.severity, rule.category, rule.recommendation),
                    )
                )
                break  # one row per rule per script; the evidence names the hit

        # Catch-all for vuln scripts that report a state but cite no CVE. Skipped
        # when a specific rule already fired on this script, so that a known check
        # such as ssl-heartbleed is not reported twice under two names.
        state = _VULN_STATE.search(script.output)
        if (
            state
            and not matched_specific
            and not re.search(r"CVE-\d{4}-\d{4,7}", script.output, re.I)
        ):
            titles = _VULN_TITLE.findall(script.output)
            title = titles[0].strip() if titles else script.id
            out.append(
                _weakness(
                    "NSE_VULNERABLE_STATE",
                    host,
                    port,
                    scan,
                    script.id,
                    _evidence(script.output, state, span=3),
                    "firm",
                    spec=Spec(
                        f"{title} (reported by {script.id})",
                        "HIGH",
                        "nse",
                        "Review the script output on the host and confirm the finding "
                        "manually; nmap declared this check VULNERABLE.",
                    ),
                )
            )
    return out


def _exposure_weaknesses(host: Host, port: Port, scan: ScanRun) -> list[Weakness]:
    out: list[Weakness] = []
    name = (port.service.name or "").lower()

    # Without -sV, nmap names the service from the port number alone. "MySQL on
    # 3306" is then a guess about what is listening, not an observation, so the
    # row is marked tentative and stays out of the report by default.
    confidence = "confirmed" if port.service.probed else "tentative"

    # Cleartext protocols are a weakness by virtue of being reachable — unless
    # the port is running them inside TLS, which nmap records as a tunnel.
    if name in EXPOSURE_RULES and port.service.tunnel != "ssl":
        rule_id, title, severity, recommendation = EXPOSURE_RULES[name]
        out.append(
            _weakness(
                rule_id,
                host,
                port,
                scan,
                "(service inventory)",
                f"{port.key} open, service identified as {port.service.banner}",
                confidence,
                spec=Spec(title, severity, "exposure", recommendation),
            )
        )

    if name in EXPOSED_DATA_SERVICES:
        out.append(
            _weakness(
                "DATA_SERVICE_EXPOSED",
                host,
                port,
                scan,
                "(service inventory)",
                f"{port.key} open, service identified as {port.service.banner}",
                confidence,
                spec=Spec(
                    f"{EXPOSED_DATA_SERVICES[name]} reachable on the scanned interface",
                    # Reachability is worth recording but is not on its own a
                    # defect: plenty of datastores are meant to be reachable
                    # from where the scan ran. Graded low so that it does not
                    # crowd out the findings that are defects.
                    "LOW",
                    "exposure",
                    "Confirm whether this datastore is meant to be reachable from where "
                    "the scan ran. Bind it to a private interface or firewall it; verify "
                    "authentication is enforced.",
                ),
            )
        )

    return out


def detect(
    scans: list[ScanRun],
    include_exposure: bool = True,
    min_confidence: Optional[str] = None,
) -> list[Weakness]:
    """Run every rule over every scan and return deduplicated weaknesses.

    ``min_confidence`` drops anything graded below it. The caller decides,
    because "show me everything" is a legitimate request even though it makes
    a poor default.
    """
    found: list[Weakness] = []

    for scan in scans:
        for host in scan.hosts:
            if host.status == "down":
                continue
            # Host scripts (smb-security-mode, smb-os-discovery and friends) live
            # outside any port and were previously never examined.
            found.extend(_apply_rules(host.scripts, host, None, scan))
            for port in host.open_ports:
                found.extend(_apply_rules(port.scripts, host, port, scan))
                if include_exposure:
                    found.extend(_exposure_weaknesses(host, port, scan))

    floor = WEAKNESS_CONFIDENCE.get(min_confidence or "", 0)

    deduped: dict[tuple, Weakness] = {}
    for w in found:
        if WEAKNESS_CONFIDENCE.get(w.confidence, 0) < floor:
            continue
        key = (w.host, w.port, w.rule_id)
        existing = deduped.get(key)
        # Keep the better-evidenced duplicate: ssh-hostkey and ssh2-enum-algos
        # both report a DSA host key, and the confirmed row is the useful one.
        if existing is None or WEAKNESS_CONFIDENCE.get(w.confidence, 0) > WEAKNESS_CONFIDENCE.get(
            existing.confidence, 0
        ):
            deduped[key] = w
    return sorted(deduped.values(), key=lambda w: w.sort_key)
