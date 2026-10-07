"""Per-service enumeration playbook.

The rest of the tool identifies services and correlates them with CVEs, then
says — correctly — that a banner match is a lead to verify, not a confirmed
vulnerability. This module supplies the missing half: given an open port and
whatever was detected on it, what an analyst runs next to confirm or rule the
lead out, and what the output of each step means.

Scope and intent. Everything here is *enumeration* — reconnaissance that reads
what a service already exposes (versions, configuration, cipher support,
anonymous access, shares, exports, directory structure). It is non-destructive
and standard practice on an authorised engagement. It is deliberately not
exploitation: steps that would change state, deny service, or require credential
attacks are left out, and authenticated testing is named only as a scope-gated
category. The tool emits the checklist; it never runs any of it against a host.

The playbook is declarative. Each service maps to a list of steps, and a step
is a command template with a description of the output to expect. Adding or
adjusting coverage is editing a table.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Host, Port


@dataclass(frozen=True)
class Step:
    action: str  # what the step establishes
    command: str  # the command to run; {ip} and {port} are substituted
    expect: str  # what the output tells you
    note: str = ""  # scope caveat or caution, when one applies


# Service names nmap emits are mapped onto a smaller set of canonical tags, so
# "ms-wbt-server", "microsoft-ds" and "ssl/http" resolve to the right playbook.
_ALIASES = {
    "http": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "https": "http",
    "https-alt": "http",
    "ssl/http": "http",
    "ssh": "ssh",
    "ftp": "ftp",
    "ftp-data": "ftp",
    "smtp": "smtp",
    "smtps": "smtp",
    "submission": "smtp",
    "domain": "dns",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "ms-sql-s": "mssql",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "mongod": "mongodb",
    "ldap": "ldap",
    "ldapssl": "ldap",
    "snmp": "snmp",
    "snmptrap": "snmp",
    "telnet": "telnet",
    "vnc": "vnc",
    "vnc-http": "vnc",
    "nfs": "nfs",
    "rpcbind": "rpcbind",
    "pop3": "mail-retrieval",
    "pop3s": "mail-retrieval",
    "imap": "mail-retrieval",
    "imaps": "mail-retrieval",
}

# TLS enumeration applies to anything negotiating TLS, named or tunnelled.
_TLS_SERVICE_NAMES = {
    "https", "https-alt", "ssl/http", "smtps", "imaps", "pop3s", "ldapssl", "ftps",
}


SERVICE_STEPS: dict[str, list[Step]] = {
    "http": [
        Step(
            "Identify the stack",
            "whatweb -a 3 http://{ip}:{port}/",
            "Server, framework, CMS and version; a named CMS redirects the rest of "
            "the work to that CMS's own checks.",
        ),
        Step(
            "Read the response headers",
            "curl -sSI http://{ip}:{port}/",
            "Server/X-Powered-By versions, redirect targets, and any security "
            "headers that are missing.",
        ),
        Step(
            "Run nmap's HTTP scripts",
            "nmap -p {port} --script http-headers,http-title,http-methods,http-enum {ip}",
            "Page title, allowed methods (PUT/DELETE/TRACE are worth noting), and "
            "common paths nmap already recognises.",
        ),
        Step(
            "Check the obvious files",
            "curl -s http://{ip}:{port}/robots.txt http://{ip}:{port}/sitemap.xml",
            "Disallowed paths and sitemap entries often name admin and backup URLs "
            "the author did not intend to advertise.",
        ),
        Step(
            "Content discovery",
            "gobuster dir -u http://{ip}:{port}/ -w <wordlist> -t 20",
            "Directories and files not linked from the site. Start small; a full "
            "wordlist against a production host is noisy.",
            note="Confirm the host is in scope and the rate is acceptable before "
            "brute-forcing paths.",
        ),
        Step(
            "Known-issue scan",
            "nikto -host http://{ip}:{port}/",
            "Outdated-component and misconfiguration findings; treat each as a lead "
            "to confirm by hand, not a result.",
        ),
    ],
    "ssh": [
        Step(
            "Enumerate algorithms and host keys",
            "nmap -p {port} --script ssh2-enum-algos,ssh-hostkey {ip}",
            "KEX, cipher, MAC and host-key algorithms, plus the host-key "
            "fingerprints — the same data the weakness rules read.",
        ),
        Step(
            "Graded algorithm audit",
            "ssh-audit {ip}:{port}",
            "A pass/fail verdict per algorithm with the reason, and the OpenSSH "
            "version range the banner implies.",
        ),
        Step(
            "Read the banner",
            "nc -nv {ip} {port}",
            "The identification string; a distribution suffix (for example "
            "'Ubuntu-...') signals backported patches, so a version-based CVE match "
            "may not apply.",
        ),
    ],
    "ftp": [
        Step(
            "Test anonymous access",
            "nmap -p {port} --script ftp-anon {ip}",
            "Whether anonymous login is accepted, and if so the top-level listing.",
        ),
        Step(
            "Browse if anonymous is allowed",
            "ftp {ip} {port}   # log in as 'anonymous'",
            "Readable files, and whether the root is writable — a writable anonymous "
            "root under a web server is a common path to code execution.",
        ),
        Step(
            "Read the banner",
            "nc -nv {ip} {port}",
            "The server software and version string.",
        ),
    ],
    "smtp": [
        Step(
            "Enumerate commands and relay state",
            "nmap -p {port} --script smtp-commands,smtp-open-relay {ip}",
            "Supported verbs and whether the server will relay mail for arbitrary "
            "senders.",
        ),
        Step(
            "Check for user enumeration",
            "nc -nv {ip} {port}   # then try VRFY <user> / EXPN <list>",
            "A distinct reply for valid vs invalid names means usernames can be "
            "enumerated; most hardened MTAs disable this.",
        ),
    ],
    "dns": [
        Step(
            "Ask the server its version",
            "dig @{ip} version.bind chaos txt",
            "The resolver software and version, when it is not hidden.",
        ),
        Step(
            "Attempt a zone transfer",
            "dig @{ip} <domain> AXFR",
            "A full zone dump if transfers are unrestricted — every record at once. "
            "Normally refused.",
        ),
        Step(
            "Run nmap's DNS scripts",
            "nmap -p {port} --script dns-recursion,dns-nsid {ip}",
            "Whether recursion is open (abusable for reflection) and any server "
            "identifier.",
        ),
    ],
    "smb": [
        Step(
            "Enumerate protocol and signing",
            "nmap -p {port} --script smb-protocols,smb-security-mode,smb-os-discovery {ip}",
            "Offered dialects (SMBv1 is a red flag), whether signing is required, and "
            "the OS and domain.",
        ),
        Step(
            "List shares over a null session",
            "smbclient -L //{ip}/ -N",
            "Shares readable without credentials; 'NT_STATUS_ACCESS_DENIED' means the "
            "null session was refused.",
        ),
        Step(
            "Full null-session enumeration",
            "enum4linux-ng -A {ip}",
            "Users, groups, shares and password policy reachable anonymously.",
        ),
    ],
    "rdp": [
        Step(
            "Enumerate encryption and NLA",
            "nmap -p {port} --script rdp-enum-encryption,rdp-ntlm-info {ip}",
            "Whether Network Level Authentication is required, the encryption level, "
            "and the AD domain and hostname leaked over NTLM.",
        ),
    ],
    "mssql": [
        Step(
            "Enumerate instance details",
            "nmap -p {port} --script ms-sql-info,ms-sql-ntlm-info {ip}",
            "Instance name, version, and the hostname and domain from NTLM.",
        ),
    ],
    "mysql": [
        Step(
            "Enumerate server details",
            "nmap -p {port} --script mysql-info {ip}",
            "Version, protocol, capabilities and salt; confirms the service is a real "
            "MySQL/MariaDB and reachable.",
        ),
        Step(
            "Check for an open instance",
            "mysql -h {ip} -P {port} -u root --connect-timeout=5",
            "Whether a passwordless account answers; normally access is denied.",
            note="Only against a host you are authorised to test.",
        ),
    ],
    "postgresql": [
        Step(
            "Enumerate server details",
            "nmap -p {port} --script pgsql-info {ip}",
            "Version and whether the service responds to an unauthenticated probe.",
        ),
    ],
    "redis": [
        Step(
            "Check for unauthenticated access",
            "redis-cli -h {ip} -p {port} info",
            "A full INFO dump means no password is set; 'NOAUTH Authentication "
            "required' means it is protected.",
        ),
    ],
    "mongodb": [
        Step(
            "Check for unauthenticated access",
            "nmap -p {port} --script mongodb-info,mongodb-databases {ip}",
            "Build info and a database list if auth is off; an authorisation error if "
            "it is on.",
        ),
    ],
    "ldap": [
        Step(
            "Query the root DSE anonymously",
            "ldapsearch -x -H ldap://{ip}:{port} -s base namingContexts",
            "The base DN and server capabilities if anonymous bind is allowed — the "
            "starting point for directory enumeration.",
        ),
    ],
    "snmp": [
        Step(
            "Try default community strings",
            "onesixtyone {ip}",
            "Which community string (often 'public') the agent answers to.",
        ),
        Step(
            "Walk the MIB",
            "snmpwalk -v2c -c public {ip}",
            "With a valid community, the full MIB — processes, interfaces, software "
            "inventory, sometimes credentials.",
        ),
    ],
    "telnet": [
        Step(
            "Read the banner",
            "nc -nv {ip} {port}",
            "The login prompt and often the OS; note that telnet is cleartext and a "
            "finding in its own right.",
        ),
    ],
    "vnc": [
        Step(
            "Enumerate security types",
            "nmap -p {port} --script vnc-info {ip}",
            "The authentication types offered; a 'None' type means unauthenticated "
            "desktop access.",
        ),
    ],
    "nfs": [
        Step(
            "List exports",
            "showmount -e {ip}",
            "Exported paths and which hosts may mount them; a '*' client spec is "
            "world-mountable.",
        ),
        Step(
            "Enumerate with nmap",
            "nmap -p {port} --script nfs-showmount,nfs-ls {ip}",
            "Exports plus a listing of readable ones.",
        ),
    ],
    "rpcbind": [
        Step(
            "List registered RPC services",
            "rpcinfo -p {ip}",
            "The RPC programs and the ports they sit on — NFS, NIS and similar often "
            "appear here.",
        ),
    ],
    "mail-retrieval": [
        Step(
            "Read the banner and capabilities",
            "nc -nv {ip} {port}   # POP3: CAPA  /  IMAP: a CAPABILITY",
            "The server software and whether STARTTLS is offered; plain POP3/IMAP "
            "without TLS is cleartext authentication.",
        ),
    ],
}

TLS_STEPS: list[Step] = [
    Step(
        "Enumerate TLS",
        "sslscan {ip}:{port}",
        "Protocol versions, cipher suites and the certificate — corroborates the "
        "ssl-* weakness findings from a second tool.",
    ),
    Step(
        "Read the certificate",
        "openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -text",
        "Subject, issuer, validity dates and the Subject Alternative Names, which "
        "often reveal other hostnames served from the same address.",
    ),
]


def _canonical(name: str) -> str:
    name = (name or "").lower()
    if name in _ALIASES:
        return _ALIASES[name]
    # nmap sometimes prefixes the transport, e.g. "ssl/http" or "ssl/ms-wbt-server".
    if "/" in name:
        return _ALIASES.get(name.split("/", 1)[1], "")
    return ""


def _is_tls(port: Port) -> bool:
    name = (port.service.name or "").lower()
    return port.service.tunnel == "ssl" or name in _TLS_SERVICE_NAMES or name.startswith("ssl/")


def _version_steps(port: Port) -> list[Step]:
    """Steps that only make sense once a product and version are in hand."""
    svc = port.service
    if not (svc.probed and svc.product):
        return []
    query = svc.product + ((" " + svc.version) if svc.version else "")
    return [
        Step(
            "Look up public exploits for the version",
            f'searchsploit {query}',
            "Local Exploit-DB entries for this product and version; cross-check the "
            "CVE table in this report.",
            note="A version string can be backported or spoofed; confirm the issue "
            "applies before relying on it.",
        )
    ]


def steps_for(port: Port) -> list[Step]:
    """The ordered enumeration steps for one open port.

    A generic re-probe comes first, then any TLS steps, then the service-specific
    steps, then version-specific steps. Empty only when the service is unknown and
    not TLS, in which case the re-probe is still worth having.
    """
    out: list[Step] = [
        Step(
            "Re-probe the port directly",
            "nmap -sV -sC -p {port} {ip}",
            "A focused version scan with the default scripts; the baseline every "
            "later step builds on.",
        )
    ]
    tls = _is_tls(port)
    if tls:
        out.extend(TLS_STEPS)
    tag = _canonical(port.service.name)
    service_steps = SERVICE_STEPS.get(tag, [])
    if tls and tag == "http":
        # The web steps are written for cleartext HTTP; on a TLS port the URLs
        # must be https:// or every request lands on the wrong protocol.
        service_steps = [
            Step(s.action, s.command.replace("http://", "https://"), s.expect, s.note)
            for s in service_steps
        ]
    out.extend(service_steps)
    out.extend(_version_steps(port))
    return out


def _fill(step: Step, ip: str, port_id: int) -> Step:
    return Step(
        action=step.action,
        command=step.command.replace("{ip}", ip).replace("{port}", str(port_id)),
        expect=step.expect,
        note=step.note,
    )


@dataclass
class PortPlaybook:
    host: str
    hostnames: str
    port: str
    service: str
    steps: list[Step]


def build(hosts: list[Host]) -> list[PortPlaybook]:
    """One PortPlaybook per open port across every live host, commands filled in."""
    out: list[PortPlaybook] = []
    for host in hosts:
        if host.status == "down":
            continue
        for port in host.open_ports:
            if port.service.name == "tcpwrapped":
                continue
            steps = [_fill(s, host.address, port.portid) for s in steps_for(port)]
            out.append(
                PortPlaybook(
                    host=host.address,
                    hostnames=", ".join(host.hostnames),
                    port=port.key,
                    service=port.service.banner,
                    steps=steps,
                )
            )
    return out
