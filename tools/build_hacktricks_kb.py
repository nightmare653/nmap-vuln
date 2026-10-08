"""Build a service knowledge bank from the HackTricks network-services pages.

HackTricks (https://github.com/carlospolop/hacktricks) is licensed
CC BY-NC 4.0 (c) Carlos Polop. That license permits redistribution for
non-commercial use **with attribution**, so this converter keeps a reference URL
on every entry and the report credits the source and license. The promotional
blocks in each page are stripped; what is kept is the service name, ports, a
short summary, and the commands (fenced code blocks) grouped by their heading.

Run:  python tools/build_hacktricks_kb.py /path/to/network-services-pentesting
"""

from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "nmapvuln", "data", "hacktricks_kb.json")
BOOK = "https://book.hacktricks.wiki/en/network-services-pentesting"

# Promo / boilerplate <details> blocks to drop.
_PROMO = re.compile(
    r"<details>.*?(?:SUBSCRIPTION PLANS|HackTricks LIVE|PEASS|hacktricks repo).*?</details>",
    re.S | re.I,
)
_CODEFENCE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.S)
_HEADING = re.compile(r"^(#{1,4})\s+(.*)$")
_PORTS_IN_TITLE = re.compile(r"^#\s*([\d][\d,/\s-]*)\s*[-–]")


def _ports(title: str) -> list[int]:
    m = _PORTS_IN_TITLE.match(title)
    if not m:
        return []
    out: list[int] = []
    for token in re.split(r"[,/\s]+", m.group(1)):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, _, b = token.partition("-")
            if a.isdigit() and b.isdigit() and int(b) - int(a) < 64:
                out.extend(range(int(a), int(b) + 1))
            elif a.isdigit():
                out.append(int(a))
        elif token.isdigit():
            out.append(int(token))
    # de-dupe, keep order
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _service_name(title: str) -> str:
    # "# 6379 - Pentesting Redis" -> "Redis"
    body = re.sub(r"^#\s*[\d][\d,/\s-]*\s*[-–]\s*", "", title).strip()
    body = re.sub(r"(?i)\bpentesting\b", "", body).strip()
    return body or title.lstrip("# ").strip()


def _strip_links(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # [t](u) -> t
    text = re.sub(r"[*_`]+", "", text)
    return text.strip()


def _summary(lines: list[str]) -> str:
    """First real prose paragraph (skipping headings, code, html, tables)."""
    buf: list[str] = []
    in_code = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if not s:
            if buf:
                break
            continue
        if s.startswith(("#", "<", "|", "!", "PORT ", "-")) or s.startswith("**Default"):
            if buf:
                break
            continue
        buf.append(s)
        if sum(len(x) for x in buf) > 350:
            break
    return _strip_links(" ".join(buf))[:400]


def _extract(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return None
    raw = _PROMO.sub("", raw)
    lines = raw.splitlines()

    title = ""
    for ln in lines:
        if ln.startswith("# "):
            title = ln
            break
    if not title:
        return None
    ports = _ports(title)
    if not ports:
        return None  # only pages that name a port become service entries

    name = _service_name(title)
    summary = _summary(lines[lines.index(title) + 1:])

    # Walk headings and collect fenced code blocks under each.
    sections: list[dict] = []
    heading = "Commands"
    body: list[str] = []

    def flush():
        text = "\n".join(body)
        cmds = []
        for block in _CODEFENCE.findall(text):
            block = "\n".join(l.rstrip() for l in block.splitlines() if l.strip())
            block = block.strip()
            if block and len(block) < 1400:
                cmds.append(block)
        if cmds:
            sections.append({"heading": heading, "commands": cmds[:12]})

    for ln in lines:
        hm = _HEADING.match(ln)
        if hm:
            flush()
            body = []
            heading = _strip_links(hm.group(2)) or "Commands"
        else:
            body.append(ln)
    flush()

    if not sections:
        return None

    slug = os.path.splitext(os.path.basename(path))[0]
    if slug == "README":
        slug = os.path.basename(os.path.dirname(path))
    return {
        "key": "ht-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"),
        "name": name,
        "ports": ports,
        "summary": summary,
        "reference": f"{BOOK}/{slug}.html",
        "sections": sections[:8],
    }


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit("usage: build_hacktricks_kb.py <network-services-pentesting dir>")
    root = os.path.abspath(sys.argv[1])
    if not os.path.isdir(root):
        sys.exit(f"not a directory: {root}")

    entries: dict[tuple, dict] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            entry = _extract(os.path.join(dirpath, name))
            if not entry:
                continue
            key = tuple(entry["ports"])
            # Keep the richer page if two map to the same port set.
            cur = entries.get(key)
            if cur is None or _rows(entry) > _rows(cur):
                entries[key] = entry

    services = sorted(entries.values(), key=lambda e: (e["ports"][0], e["name"]))
    bundle = {
        "source": "HackTricks network-services-pentesting",
        "license": "CC BY-NC 4.0",
        "attribution": "HackTricks by Carlos Polop — https://github.com/carlospolop/hacktricks",
        "services": services,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=1)

    cmds = sum(sum(len(s["commands"]) for s in e["sections"]) for e in services)
    print(f"{len(services)} services, {cmds} command blocks -> {os.path.normpath(OUT)}")
    for e in services[:12]:
        print(f"  {e['name'][:24]:24} ports={','.join(map(str,e['ports']))[:16]:16} "
              f"cmds={sum(len(s['commands']) for s in e['sections'])}")
    print("  ...")
    return 0


def _rows(entry: dict) -> int:
    return sum(len(s["commands"]) for s in entry["sections"])


if __name__ == "__main__":
    raise SystemExit(main())
