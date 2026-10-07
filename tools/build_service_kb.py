"""Convert the per-service VAPT knowledge bank spreadsheet into shipped JSON.

The tool stays pure-stdlib at runtime, so the Excel source is converted here
(openpyxl, a dev-only dependency) into nmapvuln/data/service_kb.json, which the
report loads with the standard-library json module.

Each service sheet has an intro ("What is X?") followed by a header row and a
set of technique rows. The header wording and column order vary from sheet to
sheet, so columns are matched by keyword rather than position.

Run:  python tools/build_service_kb.py [path/to/network_vapt_knowledge_bank.xlsx]
"""

from __future__ import annotations

import json
import os
import re
import sys

try:
    import openpyxl
except ImportError:
    sys.exit("openpyxl is required to rebuild the knowledge bank: pip install openpyxl")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, "..", "..", "network_vapt_knowledge_bank.xlsx")
OUT = os.path.join(HERE, "..", "nmapvuln", "data", "service_kb.json")

# Sheets that are not per-service technique pages.
SKIP = {"Recommendations", "Index", "MindMap"}
# Sheets kept as general methodology rather than tied to a port.
METHODOLOGY = {"Initial-enumeration", "Enumerating  Ports"}

# Display name and ports, for sheets whose title is messy or carries no digits.
OVERRIDES: dict[str, tuple[str, list[int]]] = {
    "HTTPHTTPS": ("HTTP / HTTPS", [80, 443, 8080, 8443]),
    "Pop3": ("POP3", [110, 995]),
    "Elasticsearch": ("Elasticsearch", [9200, 9300, 9600]),
    "Rusersd": ("rusersd", [1026]),
    "Ldap": ("LDAP", [389, 636]),
    "MSSRPC135, 593": ("MS RPC", [135, 593]),
    "MYSQL3306": ("MySQL", [3306]),
    "SMTP25, 587": ("SMTP", [25, 587]),
    "postgreSQL(5432)": ("PostgreSQL", [5432]),
    "RPC(111)": ("RPC / Portmapper", [111]),
    "NetBIOS (137-139)": ("NetBIOS", [137, 138, 139]),
    "Cassandra (9042, 9160) NoSQL da": ("Cassandra", [9042, 9160]),
    "Https Proxy - 3128": ("HTTP Proxy", [3128]),
    "Memecache - 11211": ("Memcached", [11211]),
    "MS SQL - 1433": ("MS SQL", [1433]),
    "Oracle Database - 1521": ("Oracle Database", [1521]),
    "Docker (2375, 2376)": ("Docker", [2375, 2376]),
    "kubernetes 6443, 10259, 10250, ": ("Kubernetes", [6443, 10259, 10250, 10257]),
    "Consul  8500": ("Consul", [8500]),
    "RabbitMQ (5672, 15672)": ("RabbitMQ", [5672, 15672]),
    "IMAPS (993, 143)": ("IMAP / IMAPS", [143, 993]),
    "SNMP (161, 162)": ("SNMP", [161, 162]),
    "Mongo DB 27017": ("MongoDB", [27017]),
    "RTSP - 554,8554": ("RTSP", [554, 8554]),
    "Kerberos - 88": ("Kerberos", [88]),
    "SMB -139, 445": ("SMB", [139, 445]),
    "VNC - 5900": ("VNC", [5900, 5901]),
    "telnet - 23": ("Telnet", [23]),
    "ftp- 21": ("FTP", [21]),
    "ssh- 22": ("SSH", [22]),
    "DNS 53": ("DNS", [53]),
    "Redis - 6379": ("Redis", [6379]),
    "NFS 2049": ("NFS", [2049]),
}

# nmap service names that should resolve to a sheet, keyed by display name.
NAME_ALIASES: dict[str, list[str]] = {
    "SSH": ["ssh"],
    "FTP": ["ftp"],
    "Telnet": ["telnet"],
    "SMB": ["microsoft-ds", "netbios-ssn"],
    "NetBIOS": ["netbios-ssn", "netbios-ns"],
    "DNS": ["domain"],
    "HTTP / HTTPS": ["http", "https", "http-proxy", "http-alt"],
    "MySQL": ["mysql"],
    "PostgreSQL": ["postgresql"],
    "MS SQL": ["ms-sql-s"],
    "Oracle Database": ["oracle-tns", "oracle"],
    "SMTP": ["smtp", "submission"],
    "POP3": ["pop3", "pop3s"],
    "IMAP / IMAPS": ["imap", "imaps"],
    "Kerberos": ["kerberos-sec", "kerberos"],
    "LDAP": ["ldap", "ldapssl"],
    "SNMP": ["snmp"],
    "Redis": ["redis"],
    "MongoDB": ["mongodb", "mongod"],
    "Memcached": ["memcached"],
    "Cassandra": ["cassandra"],
    "VNC": ["vnc"],
    "RTSP": ["rtsp"],
    "NFS": ["nfs"],
    "RPC / Portmapper": ["rpcbind"],
    "MS RPC": ["msrpc"],
    "Elasticsearch": ["elasticsearch"],
    "Docker": ["docker"],
    "Kubernetes": ["kubernetes", "sun-sr-https"],
    "RabbitMQ": ["amqp"],
    "Consul": ["consul"],
    "HTTP Proxy": ["http-proxy", "squid-http"],
}


def _slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.strip().lower()).strip("-")


def _name_and_ports(title: str) -> tuple[str, list[int]]:
    if title in OVERRIDES:
        return OVERRIDES[title]
    ports = [int(n) for n in re.findall(r"\d+", title)]
    name = re.sub(r"[-_(].*$", "", title).strip() or title
    return name, ports


def _classify(header: str) -> str | None:
    h = header.strip().lower()
    if not h:
        return None
    if "phase" in h:
        return "phase"
    if "method" in h or h == "tool used":
        return "method"
    # Description-of-command columns come in many misspellings.
    if "descriptio" in h or "discriptio" in h:
        return "_desc"  # first -> command_desc, second -> description
    if h.startswith("command"):
        return "command"
    if "remark" in h:
        return "remarks"
    if "refe" in h or "refr" in h or "refen" in h:
        return "reference"
    if h == "details":
        return "description"
    if "command" in h:
        return "command"
    return None


def _find_header(rows: list) -> int | None:
    for i, r in enumerate(rows):
        vals = [str(c).lower() for c in r if c]
        if any("command" in v for v in vals) and any(
            ("phase" in v) or ("method" in v) or ("details" in v) for v in vals
        ):
            return i
    return None


def _cell(value) -> str:
    if value is None:
        return ""
    return "\n".join(ln.rstrip() for ln in str(value).splitlines()).strip()


# Conservative, whole-word spelling fixes seen across the sheets. Kept small and
# unambiguous so cleanup never changes a command's meaning.
_TYPOS = {
    "discription": "description",
    "discriptions": "descriptions",
    "whethere": "whether",
    "accecpted": "accepted",
    "accecept": "accept",
    "enumaration": "enumeration",
    "authetication": "authentication",
    "authentiction": "authentication",
    "vulnerabilites": "vulnerabilities",
    "recieve": "receive",
    "usernam": "username",
    "paswword": "password",
    "retreive": "retrieve",
    "informations": "information",
}
_WORD = re.compile(r"[A-Za-z]+")


def _fix_typos(match: re.Match) -> str:
    word = match.group(0)
    repl = _TYPOS.get(word.lower())
    if repl is None:
        return word
    return repl.capitalize() if word[0].isupper() else repl


def _clean_text(value: str, is_command: bool = False) -> str:
    """Tidy a cell: trim, fix a short list of typos, collapse stray double spaces.

    Commands are left byte-for-byte except for trailing whitespace, so nothing
    that matters to a shell is altered.
    """
    if not value:
        return value
    if is_command:
        return "\n".join(ln.rstrip() for ln in value.splitlines()).strip()
    lines = []
    for ln in value.splitlines():
        ln = _WORD.sub(_fix_typos, ln)
        ln = re.sub(r"[ \t]{2,}", " ", ln).rstrip()
        lines.append(ln)
    return "\n".join(lines).strip()


def _extract(ws) -> dict:
    rows = list(ws.iter_rows(values_only=True))
    hi = _find_header(rows)
    if hi is None:
        return {}

    header = rows[hi]
    mapping: dict[int, str] = {}
    desc_seen = False
    for idx, cell in enumerate(header):
        field = _classify(str(cell) if cell else "")
        if field == "_desc":
            field = "description" if desc_seen else "command_desc"
            desc_seen = True
        if field and idx not in mapping:
            mapping[idx] = field

    intro = ""
    for r in rows[:hi]:
        bits = [_cell(c) for c in r if _cell(c)]
        if bits:
            intro = max(bits, key=len)
            break

    out_rows = []
    for r in rows[hi + 1:]:
        rec = {"phase": "", "method": "", "command": "", "command_desc": "",
               "description": "", "remarks": "", "reference": ""}
        for idx, field in mapping.items():
            if idx < len(r):
                val = _cell(r[idx])
                if val:
                    rec[field] = _clean_text(val, is_command=(field == "command"))
        if any(rec[k] for k in ("method", "command", "command_desc", "description")):
            out_rows.append(rec)
    return {"intro": _clean_text(intro), "rows": out_rows}


def main() -> int:
    src = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC)
    if not os.path.exists(src):
        sys.exit(f"knowledge-bank spreadsheet not found: {src}")

    wb = openpyxl.load_workbook(src, read_only=True, data_only=True)
    services, methodology = [], []

    for ws in wb.worksheets:
        if ws.title in SKIP:
            continue
        data = _extract(ws)
        if not data or not data["rows"]:
            continue
        if ws.title in METHODOLOGY:
            methodology.append(
                {"key": _slug(ws.title), "name": ws.title.strip(),
                 "intro": data["intro"], "rows": data["rows"]}
            )
            continue
        name, ports = _name_and_ports(ws.title)
        services.append(
            {
                "key": _slug(ws.title),
                "name": name,
                "ports": ports,
                "aliases": NAME_ALIASES.get(name, []),
                "intro": data["intro"],
                "rows": data["rows"],
            }
        )

    services.sort(key=lambda s: (s["ports"][0] if s["ports"] else 99999, s["name"]))
    bundle = {
        "source": os.path.basename(src),
        "services": services,
        "methodology": methodology,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=1)

    total_rows = sum(len(s["rows"]) for s in services)
    print(f"{len(services)} services, {len(methodology)} methodology pages, "
          f"{total_rows} technique rows -> {os.path.normpath(OUT)}")
    for s in services:
        ports = ",".join(str(p) for p in s["ports"]) or "?"
        print(f"  {s['name'][:24]:24} ports={ports:16} rows={len(s['rows'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
