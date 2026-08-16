"""Parsers for the three nmap output formats.

XML is authoritative: it is the only format that carries CPEs, fingerprint
confidence, reasons and structured NSE output. The greppable and normal
formats are lossy, so anything parsed from them is downgraded in confidence
later on.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from .model import Host, Port, ScanRun, Script, Service

XML_EXTS = {".xml"}
GNMAP_EXTS = {".gnmap", ".gmap"}
NMAP_EXTS = {".nmap"}
ALL_EXTS = XML_EXTS | GNMAP_EXTS | NMAP_EXTS


def discover(paths: list[str], recursive: bool = True) -> list[str]:
    """Expand files and directories into a sorted list of nmap output files."""
    found: list[str] = []
    for p in paths:
        if os.path.isfile(p):
            found.append(p)
        elif os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for name in files:
                        if os.path.splitext(name)[1].lower() in ALL_EXTS:
                            found.append(os.path.join(root, name))
            else:
                for name in os.listdir(p):
                    full = os.path.join(p, name)
                    if os.path.isfile(full) and os.path.splitext(name)[1].lower() in ALL_EXTS:
                        found.append(full)
    return sorted(set(os.path.abspath(f) for f in found))


def parse_file(path: str) -> list[ScanRun]:
    ext = os.path.splitext(path)[1].lower()
    if ext in XML_EXTS:
        return parse_xml(path)
    if ext in GNMAP_EXTS:
        return [parse_gnmap(path)]
    if ext in NMAP_EXTS:
        return [parse_nmap(path)]
    # Unknown extension: sniff the first bytes.
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(400)
    except OSError as exc:
        run = ScanRun(source=path, fmt="unknown")
        run.parse_errors.append(f"cannot read file: {exc}")
        return [run]
    if "<nmaprun" in head:
        return parse_xml(path)
    if head.startswith("# Nmap") and "Ports:" in head:
        return [parse_gnmap(path)]
    return [parse_nmap(path)]


# --------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------


def _read_text(path: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    return raw.decode("utf-8", errors="replace")


def _recover_truncated_xml(text: str) -> str | None:
    """Cut a partially written nmap XML document back to a parseable prefix.

    Returns None when there is nothing salvageable — no <nmaprun> element, or
    the file was cut before the first host block finished.
    """
    open_tag = text.find("<nmaprun")
    if open_tag < 0:
        return None

    end = text.rfind("</host>")
    if end < 0:
        # No complete host yet, but the scan header may still be worth keeping.
        header_end = text.find(">", open_tag)
        if header_end < 0:
            return None
        return text[: header_end + 1] + "</nmaprun>"

    return text[: end + len("</host>")] + "</nmaprun>"


def parse_xml(path: str) -> list[ScanRun]:
    run = ScanRun(source=path, fmt="xml")
    try:
        text = _read_text(path)
    except OSError as exc:
        run.parse_errors.append(f"cannot read file: {exc}")
        return [run]

    if not text.strip():
        run.parse_errors.append("file is empty")
        return [run]

    truncated = "</nmaprun>" not in text
    root = None
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        # An interrupted scan (Ctrl-C, killed process, full disk) leaves the
        # document unterminated, often mid-tag. Rewind to the last complete
        # <host> block, close the document there, and salvage what was written
        # before the cut rather than discarding the whole file.
        recovered = _recover_truncated_xml(text)
        if recovered is None:
            run.parse_errors.append(f"malformed XML: {exc}")
            return [run]
        try:
            root = ET.fromstring(recovered)
            run.parse_errors.append(
                "XML was truncated mid-write and was recovered up to the last complete "
                "host block; any hosts scanned after that point are missing from this file"
            )
        except ET.ParseError as exc2:
            run.parse_errors.append(f"malformed XML: {exc2}")
            return [run]

    run.nmap_version = root.get("version", "")
    run.args = root.get("args", "")
    run.start = root.get("startstr", "") or root.get("start", "")

    finished = root.find("runstats/finished")
    if finished is not None:
        run.end = finished.get("timestr", "")
        run.elapsed = finished.get("elapsed", "")
        run.completed = finished.get("exit", "success") == "success" and not truncated
        if finished.get("exit") == "error":
            run.parse_errors.append(f"nmap reported an error: {finished.get('errormsg', '')}")
    else:
        run.completed = False
        if truncated:
            run.parse_errors.append("scan did not finish (no runstats, document truncated)")

    for host_el in root.findall("host"):
        run.hosts.append(_host_from_xml(host_el, path))

    return [run]


def _host_from_xml(el: ET.Element, source: str) -> Host:
    host = Host(source=source)

    status = el.find("status")
    if status is not None:
        host.status = status.get("state", "unknown")

    for addr in el.findall("address"):
        value = addr.get("addr", "")
        if not value:
            continue
        host.addresses.append(value)
        if addr.get("addrtype") in ("ipv4", "ipv6") and not host.address:
            host.address = value
    if not host.address and host.addresses:
        host.address = host.addresses[0]

    for hn in el.findall("hostnames/hostname"):
        name = hn.get("name", "")
        if name and name not in host.hostnames:
            host.hostnames.append(name)

    for osmatch in el.findall("os/osmatch"):
        host.os_matches.append(f"{osmatch.get('name', '')} ({osmatch.get('accuracy', '?')}%)")

    for extra in el.findall("ports/extraports"):
        state = extra.get("state", "")
        try:
            host.extraports[state] = int(extra.get("count", "0"))
        except ValueError:
            pass

    for port_el in el.findall("ports/port"):
        host.ports.append(_port_from_xml(port_el))

    for script_el in el.findall("hostscript/script"):
        host.scripts.append(Script(id=script_el.get("id", ""), output=script_el.get("output", "")))

    return host


def _port_from_xml(el: ET.Element) -> Port:
    port = Port(protocol=el.get("protocol", "tcp"))
    try:
        port.portid = int(el.get("portid", "0"))
    except ValueError:
        port.portid = 0

    state_el = el.find("state")
    if state_el is not None:
        port.state = state_el.get("state", "unknown")
        port.reason = state_el.get("reason", "")

    svc_el = el.find("service")
    if svc_el is not None:
        svc = Service(
            name=svc_el.get("name", ""),
            product=svc_el.get("product", ""),
            version=svc_el.get("version", ""),
            extrainfo=svc_el.get("extrainfo", ""),
            ostype=svc_el.get("ostype", ""),
            tunnel=svc_el.get("tunnel", ""),
            method=svc_el.get("method", ""),
        )
        try:
            svc.conf = int(svc_el.get("conf", "0"))
        except ValueError:
            svc.conf = 0
        for cpe_el in svc_el.findall("cpe"):
            if cpe_el.text:
                svc.cpes.append(cpe_el.text.strip())
        port.service = svc

    for script_el in el.findall("script"):
        port.scripts.append(Script(id=script_el.get("id", ""), output=script_el.get("output", "")))

    return port


# --------------------------------------------------------------------------
# Greppable (.gnmap)
# --------------------------------------------------------------------------

_GNMAP_HOST = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s*(.*)$")


def parse_gnmap(path: str) -> ScanRun:
    run = ScanRun(source=path, fmt="gnmap")
    try:
        text = _read_text(path)
    except OSError as exc:
        run.parse_errors.append(f"cannot read file: {exc}")
        return run

    hosts: dict[str, Host] = {}

    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue

        if line.startswith("# Nmap"):
            m = re.search(r"# Nmap (\S+) scan initiated .* as: (.*)$", line)
            if m:
                run.nmap_version, run.args = m.group(1), m.group(2)
            elif "done" in line:
                run.completed = True
                m2 = re.search(r"# Nmap done at (.*?) --", line)
                if m2:
                    run.end = m2.group(1)
            continue
        if line.startswith("#"):
            continue

        m = _GNMAP_HOST.match(line)
        if not m:
            continue
        ip, hostname, rest = m.group(1), m.group(2).strip(), m.group(3)

        host = hosts.get(ip)
        if host is None:
            host = Host(address=ip, addresses=[ip], source=path)
            hosts[ip] = host
        if hostname and hostname not in host.hostnames:
            host.hostnames.append(hostname)

        if rest.startswith("Status:"):
            host.status = rest.split(":", 1)[1].strip().lower()
            continue

        if "Ports:" in rest:
            _, ports_blob = rest.split("Ports:", 1)
            # "Ignored State:" trails the port list when present.
            ports_blob = ports_blob.split("Ignored State:")[0]
            host.status = host.status if host.status != "unknown" else "up"
            for chunk in ports_blob.split(","):
                port = _port_from_gnmap(chunk.strip())
                if port is not None:
                    host.ports.append(port)

    run.hosts = list(hosts.values())
    if not run.completed:
        run.parse_errors.append("no '# Nmap done' trailer — scan may have been interrupted")
    return run


def _port_from_gnmap(chunk: str) -> Port | None:
    # port/state/proto/owner/service/rpc_info/version/
    if not chunk:
        return None
    fields = chunk.split("/")
    if len(fields) < 5:
        return None
    try:
        portid = int(fields[0])
    except ValueError:
        return None

    port = Port(portid=portid, state=fields[1] or "unknown", protocol=fields[2] or "tcp")
    svc = Service(name=fields[4] or "", method="probed" if len(fields) > 6 and fields[6] else "table")

    if len(fields) > 6 and fields[6]:
        # The version field is a single blob; nmap escapes its separators as
        # "|" -> "&#124;" etc. Split product from version heuristically.
        blob = fields[6].replace("&#124;", "|").replace("&amp;", "&").strip()
        svc.product, svc.version, svc.extrainfo = _split_version_blob(blob)
    port.service = svc
    return port


def _split_version_blob(blob: str) -> tuple[str, str, str]:
    """Split a version string into (product, version, extrainfo).

    'OpenSSH 7.4 (protocol 2.0)'                 -> ('OpenSSH', '7.4', 'protocol 2.0')
    'OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu…)'  -> ('OpenSSH', '8.2p1 Ubuntu 4ubuntu0.5', …)
    'PostgreSQL DB 11.7'                         -> ('PostgreSQL DB', '11.7', '')

    The product is everything before the first token that starts with a digit,
    which is how nmap lays these strings out. Product names containing digits
    ('Node.js', 'MS SQL') survive because those tokens do not *start* with one.
    """
    extra = ""
    m = re.search(r"\(([^)]*)\)\s*$", blob)
    if m:
        extra = m.group(1)
        blob = blob[: m.start()].strip()

    tokens = blob.split()
    for idx, token in enumerate(tokens):
        if token[:1].isdigit():
            return " ".join(tokens[:idx]).strip(), " ".join(tokens[idx:]).strip(), extra
    return blob.strip(), "", extra


# --------------------------------------------------------------------------
# Normal (.nmap)
# --------------------------------------------------------------------------

_NMAP_REPORT = re.compile(r"^Nmap scan report for (.+)$")
_NMAP_PORTLINE = re.compile(r"^(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)\s*(.*)$")


def parse_nmap(path: str) -> ScanRun:
    run = ScanRun(source=path, fmt="nmap")
    try:
        text = _read_text(path)
    except OSError as exc:
        run.parse_errors.append(f"cannot read file: {exc}")
        return run

    lines = text.splitlines()
    host: Host | None = None
    current_port: Port | None = None
    script_id: str | None = None
    script_lines: list[str] = []

    def flush_script() -> None:
        nonlocal script_id, script_lines
        if script_id is None:
            return
        script = Script(id=script_id, output="\n".join(script_lines).strip())
        if current_port is not None:
            current_port.scripts.append(script)
        elif host is not None:
            host.scripts.append(script)
        script_id, script_lines = None, []

    for raw in lines:
        line = raw.rstrip()

        m = re.match(r"^Starting Nmap (\S+)", line)
        if m:
            run.nmap_version = m.group(1)
            continue
        if line.startswith("Nmap done:"):
            run.completed = True
            m = re.search(r"in ([\d.]+) seconds", line)
            if m:
                run.elapsed = m.group(1)
            continue

        # Script continuation lines begin with "|" or "|_".
        if line.startswith("|"):
            body = line[1:]
            if body.startswith("_"):
                body = body[1:]
            body = body.strip()
            m = re.match(r"^([a-z0-9][a-z0-9\-._]*):\s*(.*)$", body)
            if m and script_id is None:
                script_id = m.group(1)
                script_lines = [m.group(2)] if m.group(2) else []
            elif m and re.match(r"^[a-z0-9][a-z0-9\-._]*$", m.group(1)) and not script_lines:
                script_id = m.group(1)
                script_lines = [m.group(2)] if m.group(2) else []
            else:
                script_lines.append(body)
            if raw.lstrip().startswith("|_"):
                flush_script()
            continue
        flush_script()

        m = _NMAP_REPORT.match(line)
        if m:
            current_port = None
            target = m.group(1).strip()
            host = Host(status="up", source=path)
            m2 = re.match(r"^(.+?)\s+\(([^)]+)\)$", target)
            if m2:
                host.hostnames = [m2.group(1)]
                host.address = m2.group(2)
            else:
                host.address = target
            host.addresses = [host.address]
            run.hosts.append(host)
            continue

        if host is None:
            continue

        if line.startswith("Host is up") or line.startswith("Host seems down"):
            host.status = "up" if "is up" in line else "down"
            continue

        if line.startswith("MAC Address:"):
            continue

        m = re.match(r"^(?:Running|OS details|Aggressive OS guesses):\s*(.*)$", line)
        if m:
            host.os_matches.append(m.group(1))
            continue

        m = re.match(r"^Not shown:\s+(\d+)\s+(\S+)", line)
        if m:
            host.extraports[m.group(2)] = int(m.group(1))
            continue

        m = _NMAP_PORTLINE.match(line)
        if m:
            current_port = Port(
                portid=int(m.group(1)),
                protocol=m.group(2),
                state=m.group(3),
                service=Service(name=m.group(4)),
            )
            version_blob = m.group(5).strip()
            if version_blob:
                product, version, extra = _split_version_blob(version_blob)
                current_port.service.product = product
                current_port.service.version = version
                current_port.service.extrainfo = extra
                current_port.service.method = "probed"
            else:
                current_port.service.method = "table"
            host.ports.append(current_port)
            continue

    flush_script()

    if not run.completed:
        run.parse_errors.append("no 'Nmap done:' trailer — scan may have been interrupted")
    return run
