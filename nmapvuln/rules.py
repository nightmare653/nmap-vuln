"""Non-CVE weakness detection.

A large share of what is actually reportable in an nmap scan has no CVE
attached to it: a 1024-bit DH group, SMB signing left off, anonymous FTP,
an expired certificate, RC4 still enabled, a database listening on a public
interface. None of that shows up in a CPE-to-CVE correlation, so it is matched
here instead — against NSE script output, and against the service inventory
itself for things that are a weakness purely by being exposed.

Rules are declarative. A rule fires on a regex over the output of one or more
NSE scripts, optionally gated by a numeric check (so "DH modulus < 2048" can be
expressed properly rather than as a pile of literal alternatives).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .model import Host, Port, ScanRun, Script, Weakness


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    recommendation: str
    scripts: tuple[str, ...] = ()  # NSE script ids; empty = any script
    pattern: str = ""
    # Optional numeric gate: called with the first regex group, returns True to fire.
    check: Optional[Callable[[str], bool]] = None
    flags: int = re.I | re.M


def _below(threshold: int) -> Callable[[str], bool]:
    def fn(value: str) -> bool:
        try:
            return int(value) < threshold
        except (TypeError, ValueError):
            return False

    return fn


def _grade_worse_than(worst_ok: str) -> Callable[[str], bool]:
    """ssl-enum-ciphers grades A..F; fire when the least strength is below worst_ok."""

    def fn(value: str) -> bool:
        return bool(value) and value.upper() > worst_ok.upper()

    return fn


# ---------------------------------------------------------------------------
# TLS / SSL
# ---------------------------------------------------------------------------

TLS_RULES = [
    Rule(
        id="TLS_DH_WEAK_GROUP",
        title="Weak Diffie-Hellman group (insufficient modulus strength)",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-dh-params",),
        pattern=r"Modulus Length:\s*(\d+)",
        check=_below(2048),
        recommendation="Use a 2048-bit or larger DH group, or switch to ECDHE key "
        "exchange. Regenerate the group rather than reusing a common one.",
    ),
    Rule(
        id="TLS_DH_EXPORT_GRADE",
        title="Export-grade Diffie-Hellman group (Logjam)",
        severity="HIGH",
        category="tls",
        scripts=("ssl-dh-params",),
        pattern=r"(EXPORT-GRADE DH GROUP)",
        recommendation="Disable all export cipher suites. Export-grade DH is trivially "
        "broken and enables downgrade attacks against otherwise-strong sessions.",
    ),
    Rule(
        id="TLS_DH_ANONYMOUS",
        title="Anonymous Diffie-Hellman key exchange offered",
        severity="HIGH",
        category="tls",
        scripts=("ssl-dh-params", "ssl-enum-ciphers"),
        pattern=r"(ANONYMOUS DH GROUP|_anon_|DH_anon)",
        recommendation="Disable anonymous cipher suites — they provide encryption with "
        "no authentication, so the session can be trivially machine-in-the-middled.",
    ),
    Rule(
        id="TLS_SSLV2",
        title="SSLv2 enabled (DROWN)",
        severity="HIGH",
        category="tls",
        scripts=("ssl-enum-ciphers", "sslv2", "sslv2-drown"),
        pattern=r"^\s*\|?\s*(SSLv2)\b",
        recommendation="Disable SSLv2 entirely. It is broken beyond repair and its "
        "presence undermines TLS on other services sharing the same key.",
    ),
    Rule(
        id="TLS_SSLV3",
        title="SSLv3 enabled (POODLE)",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-enum-ciphers", "ssl-poodle"),
        pattern=r"^\s*\|?\s*(SSLv3)\b",
        recommendation="Disable SSLv3. Modern clients do not need it, and CBC padding "
        "in SSLv3 is exploitable via POODLE.",
    ),
    Rule(
        id="TLS_DEPRECATED_VERSION",
        title="Deprecated TLS version enabled (TLS 1.0 / 1.1)",
        severity="LOW",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"^\s*\|?\s*(TLSv1\.[01])\b",
        recommendation="Disable TLS 1.0 and 1.1. Both are deprecated (RFC 8996) and fail "
        "PCI DSS; enable TLS 1.2 and 1.3 only.",
    ),
    Rule(
        id="TLS_NULL_CIPHER",
        title="NULL cipher suite offered (no encryption)",
        severity="CRITICAL",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"(TLS_[A-Z0-9_]*WITH_NULL[A-Z0-9_]*)",
        recommendation="Disable NULL cipher suites immediately — traffic is authenticated "
        "but sent in cleartext.",
    ),
    Rule(
        id="TLS_EXPORT_CIPHER",
        title="Export-grade cipher suite offered (FREAK)",
        severity="HIGH",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"(TLS_[A-Z0-9_]*EXPORT[A-Z0-9_]*)",
        recommendation="Disable all EXPORT cipher suites; their key sizes are breakable "
        "in minutes on commodity hardware.",
    ),
    Rule(
        id="TLS_RC4",
        title="RC4 cipher suite offered",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"(TLS_[A-Z0-9_]*RC4[A-Z0-9_]*)",
        recommendation="Disable RC4 (RFC 7465). Its keystream biases allow plaintext "
        "recovery against repeated secrets such as session cookies.",
    ),
    Rule(
        id="TLS_3DES",
        title="3DES / DES cipher suite offered (Sweet32)",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"(TLS_[A-Z0-9_]*(?:3DES|DES_CBC)[A-Z0-9_]*)",
        recommendation="Disable 64-bit block ciphers. Sweet32 recovers plaintext from "
        "long-lived connections carrying a repeated secret.",
    ),
    Rule(
        id="TLS_WEAK_CIPHER_GRADE",
        title="Weak overall cipher strength reported by nmap",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-enum-ciphers",),
        pattern=r"least strength:\s*([A-F])",
        check=_grade_worse_than("B"),
        recommendation="Review the enabled cipher suite list; nmap graded the weakest "
        "offered suite below B.",
    ),
    Rule(
        id="TLS_CERT_EXPIRED",
        title="TLS certificate is expired or not yet valid",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-cert",),
        pattern=r"(Certificate (?:has expired|is not yet valid)|NOT VALID AFTER)",
        recommendation="Renew the certificate and automate renewal. Expired certificates "
        "train users to click through warnings.",
    ),
    Rule(
        id="TLS_CERT_SELF_SIGNED",
        title="Self-signed TLS certificate",
        severity="LOW",
        category="tls",
        scripts=("ssl-cert",),
        pattern=r"(Issuer:[^\n]*(self[- ]signed)|Subject:\s*(\S[^\n]*)\n[^\n]*Issuer:\s*\3)",
        recommendation="Use a certificate from a trusted CA on anything user-facing; "
        "self-signed certificates cannot be validated by clients.",
    ),
    Rule(
        id="TLS_CERT_WEAK_SIGNATURE",
        title="Certificate signed with a weak hash (MD5 / SHA-1)",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-cert",),
        pattern=r"Signature Algorithm:\s*((?:md5|sha1)[A-Za-z0-9]*)",
        recommendation="Re-issue the certificate with SHA-256 or stronger. SHA-1 "
        "collisions are practical and browsers reject such certificates.",
    ),
    Rule(
        id="TLS_CERT_WEAK_KEY",
        title="Certificate public key is undersized",
        severity="MEDIUM",
        category="tls",
        scripts=("ssl-cert",),
        pattern=r"Public Key bits:\s*(\d+)",
        check=_below(2048),
        recommendation="Re-issue with a 2048-bit or larger RSA key, or a 256-bit ECDSA key.",
    ),
    Rule(
        id="TLS_HEARTBLEED",
        title="OpenSSL Heartbleed memory disclosure",
        severity="CRITICAL",
        category="tls",
        scripts=("ssl-heartbleed",),
        pattern=r"(State:\s*VULNERABLE)",
        recommendation="Patch OpenSSL immediately, then rotate every key, certificate and "
        "credential that was in memory on the affected host.",
    ),
    Rule(
        id="TLS_CCS_INJECTION",
        title="OpenSSL CCS injection",
        severity="HIGH",
        category="tls",
        scripts=("ssl-ccs-injection",),
        pattern=r"(State:\s*VULNERABLE)",
        recommendation="Patch OpenSSL. An attacker in path can force a weak key and "
        "decrypt or modify the session.",
    ),
]

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

SSH_RULES = [
    Rule(
        id="SSH_WEAK_KEX",
        title="Weak SSH key exchange algorithm offered",
        severity="MEDIUM",
        category="ssh",
        scripts=("ssh2-enum-algos",),
        pattern=r"(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|"
        r"gss-group1-sha1|rsa1024-sha1)",
        recommendation="Restrict KexAlgorithms to curve25519-sha256 and "
        "diffie-hellman-group-exchange-sha256 or better. Group1 is a fixed 1024-bit "
        "group and is considered breakable by well-resourced attackers.",
    ),
    Rule(
        id="SSH_WEAK_MAC",
        title="Weak SSH MAC algorithm offered",
        severity="LOW",
        category="ssh",
        scripts=("ssh2-enum-algos",),
        pattern=r"(hmac-md5\S*|hmac-sha1-96\S*|umac-64(?!-etm)\S*|hmac-ripemd160\S*)",
        recommendation="Restrict MACs to encrypt-then-MAC variants such as "
        "hmac-sha2-256-etm@openssh.com.",
    ),
    Rule(
        id="SSH_WEAK_CIPHER",
        title="Weak SSH cipher offered (CBC mode / arcfour / 3DES)",
        severity="MEDIUM",
        category="ssh",
        scripts=("ssh2-enum-algos",),
        pattern=r"(3des-cbc|arcfour\S*|blowfish-cbc|cast128-cbc|aes\d+-cbc|des-cbc)",
        recommendation="Restrict Ciphers to AEAD suites such as "
        "chacha20-poly1305@openssh.com and aes256-gcm@openssh.com. CBC modes are "
        "vulnerable to plaintext recovery in SSH.",
    ),
    Rule(
        id="SSH_WEAK_HOSTKEY_TYPE",
        title="DSA (ssh-dss) host key in use",
        severity="MEDIUM",
        category="ssh",
        scripts=("ssh-hostkey", "ssh2-enum-algos"),
        pattern=r"(ssh-dss)",
        recommendation="Remove DSA host keys. They are fixed at 1024 bits and disabled "
        "by default in modern OpenSSH; use Ed25519 or RSA-2048+.",
    ),
    Rule(
        id="SSH_WEAK_HOSTKEY_SIZE",
        title="Undersized SSH host key",
        severity="MEDIUM",
        category="ssh",
        scripts=("ssh-hostkey",),
        pattern=r"^\s*\|?\s*(\d{3,4})\s+(?:[0-9a-f]{2}:){5}",
        check=_below(2048),
        recommendation="Regenerate the host key at 2048 bits or larger, or switch to Ed25519.",
    ),
    Rule(
        id="SSH_V1_SUPPORTED",
        title="SSH protocol version 1 supported",
        severity="HIGH",
        category="ssh",
        scripts=("sshv1", "ssh2-enum-algos"),
        pattern=r"(SSH-1\.|protocol version 1 )",
        recommendation="Disable SSHv1. It has fundamental integrity flaws and no modern "
        "client requires it.",
    ),
]

# ---------------------------------------------------------------------------
# SMB / Windows
# ---------------------------------------------------------------------------

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
        scripts=("smb-protocols", "smb-os-discovery"),
        pattern=r"(SMBv1|NT LM 0\.12)",
        recommendation="Disable SMBv1 entirely. It is unpatchable by design, and is the "
        "transport for EternalBlue-class attacks.",
    ),
    Rule(
        id="SMB_GUEST_ACCESS",
        title="SMB guest or anonymous access permitted",
        severity="HIGH",
        category="smb",
        scripts=("smb-enum-shares", "smb-enum-users", "smb-security-mode"),
        pattern=r"(Anonymous access:\s*READ[^\n]*|account_used:\s*(?:guest|<blank>)"
        r"|Account that was used for enumeration:\s*guest)",
        recommendation="Disable the guest account and require authentication for all "
        "shares; anonymous enumeration hands an attacker the user and share list.",
    ),
]

# ---------------------------------------------------------------------------
# Services and applications
# ---------------------------------------------------------------------------

SERVICE_RULES = [
    Rule(
        id="FTP_ANONYMOUS",
        title="Anonymous FTP login allowed",
        severity="MEDIUM",
        category="auth",
        scripts=("ftp-anon",),
        pattern=r"(Anonymous FTP login allowed)",
        recommendation="Disable anonymous FTP, or confirm the exposed directory contains "
        "nothing sensitive and is not writable.",
    ),
    Rule(
        id="FTP_ANONYMOUS_WRITABLE",
        title="Anonymous FTP directory is writable",
        severity="HIGH",
        category="auth",
        scripts=("ftp-anon",),
        pattern=r"(drwxrwxrwx|Anonymous FTP login allowed[\s\S]{0,400}?\bwritable\b)",
        recommendation="An anonymously writable FTP root frequently leads to code "
        "execution when it is served by a web server. Remove write access.",
    ),
    Rule(
        id="DNS_OPEN_RECURSION",
        title="Open recursive DNS resolver",
        severity="MEDIUM",
        category="exposure",
        scripts=("dns-recursion",),
        pattern=r"(Recursion appears to be enabled)",
        recommendation="Restrict recursion to trusted networks. Open resolvers are "
        "abused as amplifiers in DDoS reflection attacks.",
    ),
    Rule(
        id="SNMP_DEFAULT_COMMUNITY",
        title="SNMP readable with a default community string",
        severity="HIGH",
        category="auth",
        scripts=("snmp-info", "snmp-brute", "snmp-sysdescr"),
        pattern=r"(community(?:\s+string)?[:=]?\s*(?:public|private))",
        recommendation="Change the community string and restrict SNMP by source address, "
        "or move to SNMPv3 with authentication and encryption.",
    ),
    Rule(
        id="NFS_EXPORTS",
        title="NFS exports readable",
        severity="MEDIUM",
        category="exposure",
        scripts=("nfs-showmount", "nfs-ls"),
        pattern=r"^\s*\|?\s*(/\S+)",
        recommendation="Restrict NFS exports to specific hosts and enable root squashing; "
        "world-readable exports frequently expose backups and home directories.",
    ),
    Rule(
        id="HTTP_DANGEROUS_METHODS",
        title="Dangerous HTTP methods enabled (PUT / DELETE)",
        severity="HIGH",
        category="http",
        scripts=("http-methods",),
        pattern=r"Potentially risky methods:\s*([^\n]*(?:PUT|DELETE)[^\n]*)",
        recommendation="Disable PUT and DELETE unless the application requires them. "
        "PUT on a web root is a direct path to code execution.",
    ),
    Rule(
        id="HTTP_TRACE_ENABLED",
        title="HTTP TRACE method enabled",
        severity="LOW",
        category="http",
        scripts=("http-methods", "http-trace"),
        pattern=r"(TRACE is enabled|Potentially risky methods:[^\n]*TRACE)",
        recommendation="Disable TRACE. It enables cross-site tracing to read headers that "
        "scripts are not meant to see.",
    ),
    Rule(
        id="HTTP_OPEN_PROXY",
        title="Open HTTP proxy",
        severity="HIGH",
        category="exposure",
        scripts=("http-open-proxy",),
        pattern=r"(Potentially OPEN proxy)",
        recommendation="Close the open proxy — it lets attackers reach internal systems "
        "and launder traffic through this host.",
    ),
    Rule(
        id="HTTP_GIT_EXPOSED",
        title="Exposed .git repository",
        severity="HIGH",
        category="info-disclosure",
        scripts=("http-git",),
        pattern=r"(Git repository found)",
        recommendation="Block access to .git. The full source history — often including "
        "committed credentials — can be reconstructed from it.",
    ),
    Rule(
        id="HTTP_BACKUP_FILES",
        title="Configuration or backup files exposed",
        severity="HIGH",
        category="info-disclosure",
        scripts=("http-config-backup", "http-backup-finder"),
        pattern=r"^\s*\|?\s*(\S+\.(?:bak|old|save|swp|zip|tar\.gz|sql|conf))",
        recommendation="Remove backup and configuration files from the web root; they "
        "routinely contain database credentials.",
    ),
    Rule(
        id="HTTP_DIR_LISTING",
        title="Directory listing enabled",
        severity="LOW",
        category="info-disclosure",
        scripts=("http-enum",),
        pattern=r"(Directory (?:listing|index))",
        recommendation="Disable automatic directory indexing.",
    ),
    Rule(
        id="LDAP_ANONYMOUS_BIND",
        title="LDAP anonymous bind permitted",
        severity="MEDIUM",
        category="auth",
        scripts=("ldap-rootdse", "ldap-search"),
        pattern=r"(namingContexts|dsServiceName)",
        recommendation="Disable anonymous bind. It exposes the directory structure and "
        "often the full user list.",
    ),
    Rule(
        id="RDP_NLA_DISABLED",
        title="RDP Network Level Authentication not enforced",
        severity="MEDIUM",
        category="auth",
        scripts=("rdp-enum-encryption", "rdp-ntlm-info"),
        pattern=r"(Native RDP:\s*SUCCESS|CredSSP.*?:\s*(?:FAIL|not supported))",
        recommendation="Require NLA. Without it, RDP is exposed to pre-authentication "
        "attacks and credential capture.",
    ),
    Rule(
        id="VNC_NO_AUTH",
        title="VNC accessible without authentication",
        severity="CRITICAL",
        category="auth",
        scripts=("vnc-info", "realvnc-auth-bypass"),
        pattern=r"(Security types:.*?None|no authentication)",
        recommendation="Enable VNC authentication and place the service behind a VPN. "
        "Unauthenticated VNC is full interactive access to the desktop.",
    ),
    Rule(
        id="MONGODB_NO_AUTH",
        title="MongoDB accessible without authentication",
        severity="CRITICAL",
        category="auth",
        scripts=("mongodb-info", "mongodb-databases"),
        pattern=r"(totalSize|databases|ok\s*=\s*1)",
        recommendation="Enable authentication and bind MongoDB to localhost or a private "
        "interface. Unauthenticated instances are mass-scanned and ransomed.",
    ),
    Rule(
        id="REDIS_NO_AUTH",
        title="Redis accessible without authentication",
        severity="CRITICAL",
        category="auth",
        scripts=("redis-info",),
        pattern=r"(redis_version|Server version)",
        recommendation="Set requirepass, enable protected-mode and bind to a private "
        "interface. Unauthenticated Redis leads to code execution via config rewrite.",
    ),
    Rule(
        id="ELASTICSEARCH_EXPOSED",
        title="Elasticsearch accessible without authentication",
        severity="CRITICAL",
        category="auth",
        scripts=("http-elasticsearch-head",),
        pattern=r"(Elasticsearch)",
        recommendation="Enable authentication and restrict network access; open "
        "Elasticsearch clusters expose the entire indexed dataset.",
    ),
    Rule(
        id="MYSQL_EMPTY_PASSWORD",
        title="MySQL account with an empty password",
        severity="CRITICAL",
        category="auth",
        scripts=("mysql-empty-password",),
        pattern=r"(account has empty password)",
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


def _apply_rules(
    scripts: list[Script], host: Host, port: Optional[Port], scan: ScanRun
) -> list[Weakness]:
    out: list[Weakness] = []
    for script in scripts:
        if not script.output:
            continue
        matched_specific = False
        for rule in ALL_RULES:
            if rule.scripts and script.id not in rule.scripts:
                continue
            match = re.search(rule.pattern, script.output, rule.flags)
            if not match:
                continue
            if rule.check is not None:
                value = match.group(1) if match.groups() else ""
                if not rule.check(value):
                    continue
            matched_specific = True
            out.append(
                Weakness(
                    host=host.address,
                    hostnames=", ".join(host.hostnames),
                    port=port.key if port else "host",
                    service=port.service.name if port else "",
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    category=rule.category,
                    evidence=_evidence(script.output, match),
                    recommendation=rule.recommendation,
                    source_script=script.id,
                    scan_file=scan.source,
                )
            )

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
                Weakness(
                    host=host.address,
                    hostnames=", ".join(host.hostnames),
                    port=port.key if port else "host",
                    service=port.service.name if port else "",
                    rule_id="NSE_VULNERABLE_STATE",
                    title=f"{title} (reported by {script.id})",
                    severity="HIGH",
                    category="nse",
                    evidence=_evidence(script.output, state, span=3),
                    recommendation="Review the script output on the host and confirm the "
                    "finding manually; nmap declared this check VULNERABLE.",
                    source_script=script.id,
                    scan_file=scan.source,
                )
            )
    return out


def _exposure_weaknesses(host: Host, port: Port, scan: ScanRun) -> list[Weakness]:
    out: list[Weakness] = []
    name = (port.service.name or "").lower()

    # Cleartext protocols are a weakness by virtue of being reachable — unless
    # the port is running them inside TLS, which nmap records as a tunnel.
    if name in EXPOSURE_RULES and port.service.tunnel != "ssl":
        rule_id, title, severity, recommendation = EXPOSURE_RULES[name]
        out.append(
            Weakness(
                host=host.address,
                hostnames=", ".join(host.hostnames),
                port=port.key,
                service=name,
                rule_id=rule_id,
                title=title,
                severity=severity,
                category="exposure",
                evidence=f"{port.key} open, service identified as {port.service.banner}",
                recommendation=recommendation,
                source_script="(service inventory)",
                scan_file=scan.source,
            )
        )

    if name in EXPOSED_DATA_SERVICES:
        out.append(
            Weakness(
                host=host.address,
                hostnames=", ".join(host.hostnames),
                port=port.key,
                service=name,
                rule_id="DATA_SERVICE_EXPOSED",
                title=f"{EXPOSED_DATA_SERVICES[name]} reachable on the scanned interface",
                severity="MEDIUM",
                category="exposure",
                evidence=f"{port.key} open, service identified as {port.service.banner}",
                recommendation="Confirm whether this datastore is meant to be reachable "
                "from where the scan ran. Bind it to a private interface or firewall it; "
                "verify authentication is enforced.",
                source_script="(service inventory)",
                scan_file=scan.source,
            )
        )

    return out


def detect(scans: list[ScanRun], include_exposure: bool = True) -> list[Weakness]:
    """Run every rule over every scan and return deduplicated weaknesses."""
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

    deduped: dict[tuple, Weakness] = {}
    for w in found:
        key = (w.host, w.port, w.rule_id)
        if key not in deduped:
            deduped[key] = w
    return sorted(deduped.values(), key=lambda w: w.sort_key)
