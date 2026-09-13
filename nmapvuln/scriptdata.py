"""Structural parsers for NSE script output.

Regexes over raw script text are the main source of false positives in a tool
like this. Two failure modes dominate:

  * A pattern matches text that means the opposite of what the rule assumes.
    ``ssl-cert`` prints "Not valid after: 2031-01-01" for *every* certificate,
    so a rule looking for the phrase "not valid after" flags every healthy
    certificate as expired.
  * A pattern matches in the wrong part of a structured block.
    ``ssh2-enum-algos`` prints four separate algorithm lists; a MAC pattern
    that scans the whole blob can fire on a string that appeared in the
    cipher list.

So the scripts that carry real structure are parsed into real values here, and
the rules in :mod:`nmapvuln.rules` reason over those values instead of over
text. Anything this module cannot parse confidently returns nothing, and the
rule does not fire — silence is preferable to a finding the user has to
disprove.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from typing import Optional

# nmap writes script output with a leading "| " or "|_" in .nmap files and
# without it in XML. Normalise so one parser handles both, but keep the
# remaining indentation: it carries the block structure.
_PIPE = re.compile(r"^[ \t]*\|_?[ ]?", re.M)


def normalise(output: str) -> str:
    return _PIPE.sub("", output or "")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


# ---------------------------------------------------------------------------
# Generic indent-structured blocks
# ---------------------------------------------------------------------------


def sections(output: str) -> dict[str, list[str]]:
    """Split indent-structured script output into ``name -> child lines``.

    ``ssh2-enum-algos`` and ``ssl-enum-ciphers`` both emit "key:" headers
    followed by a more deeply indented body. The body lines are returned
    stripped, in order, under the header's name.
    """
    out: dict[str, list[str]] = {}
    lines = [ln.rstrip() for ln in normalise(output).splitlines() if ln.strip()]

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = re.match(r"^([ ]*)([A-Za-z][\w .()/-]*):[ ]*(.*)$", line)
        if not match:
            idx += 1
            continue
        depth = len(match.group(1))
        name = match.group(2).strip()
        inline = match.group(3).strip()
        body: list[str] = []
        if inline and not inline.startswith("("):
            body.append(inline)
        idx += 1
        while idx < len(lines) and _indent(lines[idx]) > depth:
            body.append(lines[idx].strip())
            idx += 1
        out.setdefault(name, []).extend(body)
    return out


def fields(output: str) -> dict[str, str]:
    """Flat ``Key: value`` pairs, first occurrence wins."""
    out: dict[str, str] = {}
    for line in normalise(output).splitlines():
        match = re.match(r"^[ ]*([A-Za-z][\w .()/-]*):[ ]+(\S.*)$", line)
        if match:
            out.setdefault(match.group(1).strip(), match.group(2).strip())
    return out


# ---------------------------------------------------------------------------
# ssl-cert
# ---------------------------------------------------------------------------

_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2}))?")


def _parse_date(value: str) -> Optional[datetime.datetime]:
    match = _ISO.search(value or "")
    if not match:
        return None
    try:
        return datetime.datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4) or 0),
            int(match.group(5) or 0),
            int(match.group(6) or 0),
        )
    except ValueError:
        return None


@dataclass
class Certificate:
    subject: str = ""
    issuer: str = ""
    key_type: str = ""
    key_bits: Optional[int] = None
    signature_algorithm: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer

    def expired_at(self, when: datetime.datetime) -> bool:
        return self.not_after is not None and self.not_after < when

    def not_yet_valid_at(self, when: datetime.datetime) -> bool:
        return self.not_before is not None and self.not_before > when

    @property
    def weak_key(self) -> bool:
        """Undersized for the key's own algorithm.

        A 256-bit elliptic-curve key is roughly as strong as a 3072-bit RSA
        key. Comparing every key against one RSA-shaped threshold reports
        every modern certificate as weak, which is the opposite of useful.
        """
        if self.key_bits is None:
            return False
        family = (self.key_type or "").lower()
        if family.startswith("ec"):
            return self.key_bits < 224
        if family in ("rsa", "dsa", "dh", ""):
            return self.key_bits < 2048
        return False

    @property
    def weak_signature(self) -> Optional[str]:
        """The hash in the signature algorithm, when it is a broken one."""
        algorithm = (self.signature_algorithm or "").lower()
        if not algorithm:
            return None
        # 'sha1WithRSAEncryption', 'ecdsa-with-SHA1', 'md5WithRSAEncryption'.
        # The lookarounds stop 'sha1' matching inside 'sha152' style strings
        # and stop 'sha256' being read as a weak digest.
        for weak in ("md2", "md4", "md5", "sha1"):
            if re.search(r"(?<![a-z0-9])" + weak + r"(?![0-9])", algorithm):
                return weak
        return None


def parse_certificate(output: str) -> Optional[Certificate]:
    data = fields(output)
    if not data:
        return None
    cert = Certificate(
        subject=data.get("Subject", ""),
        issuer=data.get("Issuer", ""),
        key_type=data.get("Public Key type", ""),
        signature_algorithm=data.get("Signature Algorithm", ""),
        not_before=_parse_date(data.get("Not valid before", "")),
        not_after=_parse_date(data.get("Not valid after", "")),
    )
    bits = data.get("Public Key bits", "")
    if bits.isdigit():
        cert.key_bits = int(bits)
    if not (cert.subject or cert.not_after or cert.key_bits):
        return None
    return cert


# ---------------------------------------------------------------------------
# ssh-hostkey
# ---------------------------------------------------------------------------

# "2048 aa:bb:...:99 (RSA)", and the SHA256 form nmap emits in newer releases.
_HOSTKEY = re.compile(
    r"^[ ]*(\d{2,5})[ ]+(?:[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5,}|SHA256:\S+)[ ]*\(([A-Za-z0-9-]+)\)",
    re.M,
)

# Minimum acceptable key size per algorithm family. Ed25519 is fixed at 256
# bits and ECDSA P-256 at 256; both are strong, and a flat 2048-bit threshold
# reports them as undersized. DSA is capped at 1024 bits by the protocol, so
# it is weak at any size and is handled by the algorithm rule instead.
HOSTKEY_MINIMUM = {"rsa": 2048, "ecdsa": 256, "ed25519": 256}


@dataclass
class HostKey:
    bits: int
    algorithm: str

    @property
    def family(self) -> str:
        return self.algorithm.lower().replace("ssh-", "").replace("-", "")

    @property
    def undersized(self) -> bool:
        floor = HOSTKEY_MINIMUM.get(self.family)
        if floor is None:
            return False
        return self.bits < floor


def parse_host_keys(output: str) -> list[HostKey]:
    keys = []
    for bits, algorithm in _HOSTKEY.findall(normalise(output)):
        try:
            keys.append(HostKey(bits=int(bits), algorithm=algorithm))
        except ValueError:
            continue
    return keys


# ---------------------------------------------------------------------------
# ssh2-enum-algos
# ---------------------------------------------------------------------------

_ALGO_LISTS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms",
    "mac_algorithms",
    "compression_algorithms",
)


def parse_ssh_algorithms(output: str) -> dict[str, list[str]]:
    """The named algorithm lists, each as a list of algorithm names.

    Scoping matters: ``hmac-sha1`` in the MAC list is a finding, the same
    string inside a cipher name is not, and a rule that greps the whole blob
    cannot tell the difference.
    """
    parsed = sections(output)
    out: dict[str, list[str]] = {}
    for name in _ALGO_LISTS:
        entries = parsed.get(name)
        if not entries:
            continue
        cleaned = [e.strip().rstrip(",") for e in entries if e.strip()]
        out[name] = [e for e in cleaned if e and not e.startswith("(")]
    return out


# ---------------------------------------------------------------------------
# ssl-enum-ciphers
# ---------------------------------------------------------------------------

_PROTOCOL = re.compile(r"^(SSLv2|SSLv3|TLSv1\.[0-3])$", re.I)
_CIPHER_LINE = re.compile(r"^(TLS_[A-Z0-9_]+|SSL_[A-Z0-9_]+)\b", re.I)


@dataclass
class TlsSurvey:
    protocols: list[str] = field(default_factory=list)
    ciphers: dict[str, list[str]] = field(default_factory=dict)  # protocol -> cipher names
    least_strength: str = ""
    warnings: list[str] = field(default_factory=list)

    def all_ciphers(self) -> list[tuple[str, str]]:
        return [(proto, name) for proto, names in self.ciphers.items() for name in names]


def parse_tls_ciphers(output: str) -> Optional[TlsSurvey]:
    """Protocol versions and the cipher suites offered under each.

    Only lines inside a protocol's ``ciphers:`` list are treated as cipher
    suites. The ``compressors:`` list (which contains the literal token NULL)
    and the ``warnings:`` list are kept separate, so neither can be mistaken
    for a NULL cipher suite.
    """
    lines = [ln.rstrip() for ln in normalise(output).splitlines() if ln.strip()]
    if not lines:
        return None

    survey = TlsSurvey()
    protocol = ""
    bucket = ""

    for line in lines:
        stripped = line.strip()
        header = re.match(r"^([A-Za-z][\w .]*):[ ]*(.*)$", stripped)
        if header:
            name, inline = header.group(1).strip(), header.group(2).strip()
            if _PROTOCOL.match(name):
                protocol, bucket = name, ""
                if protocol not in survey.protocols:
                    survey.protocols.append(protocol)
                    survey.ciphers.setdefault(protocol, [])
                continue
            key = name.lower()
            if key in ("ciphers", "compressors", "warnings"):
                bucket = key
                continue
            if key == "least strength":
                survey.least_strength = inline.upper()[:1]
                bucket = ""
                continue
            bucket = ""
            continue

        if bucket == "ciphers" and protocol:
            match = _CIPHER_LINE.match(stripped)
            if match:
                survey.ciphers.setdefault(protocol, []).append(match.group(1).upper())
        elif bucket == "warnings":
            survey.warnings.append(stripped)

    if not survey.protocols and not survey.least_strength:
        return None
    return survey


# ---------------------------------------------------------------------------
# ssl-dh-params
# ---------------------------------------------------------------------------


def parse_dh_moduli(output: str) -> list[int]:
    """Every DH modulus length in the output, not just the first one.

    ``ssl-dh-params`` can report several groups. Reading only the first means
    a 1024-bit group listed after a 2048-bit one is never reported.
    """
    out = []
    for value in re.findall(r"Modulus Length:[ ]*(\d+)", normalise(output), re.I):
        try:
            out.append(int(value))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# rdp-enum-encryption
# ---------------------------------------------------------------------------


def rdp_nla_enforced(output: str) -> Optional[bool]:
    """True when the server accepts only CredSSP, None when it cannot be told.

    "CredSSP with Early User Auth: FAILED" is normal on a server that does
    require NLA, so it must not be read as NLA being off. What actually
    matters is whether a non-CredSSP security layer was accepted.
    """
    text = normalise(output)
    layers = {
        name.strip().lower(): verdict.strip().upper()
        for name, verdict in re.findall(
            r"^[ ]*(Native RDP|SSL|CredSSP \(NLA\)|RDSTLS)[ ]*:[ ]*(\w+)", text, re.M
        )
    }
    if "credssp (nla)" not in layers:
        return None
    legacy = [
        name for name in ("native rdp", "ssl") if layers.get(name) in ("SUCCESS", "SUPPORTED")
    ]
    return not legacy


# ---------------------------------------------------------------------------
# Datastore probes
# ---------------------------------------------------------------------------

_AUTH_ERROR = re.compile(
    r"not authoriz|unauthoriz|authentication (?:required|failed)|"
    r"\bNOAUTH\b|requires? authentication|access denied|permission denied|"
    r"^\s*ERROR:|command not allowed|login failed",
    re.I | re.M,
)


def script_reports_auth_error(output: str) -> bool:
    """True when the script's own output says it was refused.

    Rules that read "the script returned data, therefore the service is
    unauthenticated" are wrong whenever the script returned an error string
    that happens to contain the keyword being matched: MongoDB's
    "not authorized on admin to execute command { listDatabases: 1.0 }"
    contains the word "databases".
    """
    return bool(_AUTH_ERROR.search(normalise(output)))
