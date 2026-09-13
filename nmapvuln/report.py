"""Report rendering: a self-contained HTML report and a flat CSV of findings."""

from __future__ import annotations

import csv
import datetime
import html
import os

from .model import Analysis, Finding

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

CSV_COLUMNS = [
    "host",
    "hostnames",
    "port",
    "service",
    "product",
    "cve",
    "severity",
    "cvss",
    "cvss_vector",
    "confidence",
    "source",
    "kev",
    "kev_due",
    "epss",
    "backport_suspected",
    "exploit_known",
    "published",
    "matched_on",
    "description",
    "references",
    "scan_file",
]


def write_csv(analysis: Analysis, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_COLUMNS)
        for f in analysis.findings:
            writer.writerow(
                [
                    f.host,
                    f.hostnames,
                    f.port,
                    f.service,
                    f.product,
                    f.cve,
                    f.severity,
                    "" if f.cvss is None else f"{f.cvss:.1f}",
                    f.cvss_vector,
                    f.confidence,
                    f.source,
                    "yes" if f.kev else "no",
                    f.kev_due,
                    "" if f.epss is None else f"{f.epss:.5f}",
                    "yes" if f.backport_suspected else "no",
                    "yes" if f.exploit_known else "no",
                    f.published,
                    f.matched_on,
                    " ".join((f.description or "").split()),
                    " | ".join(f.references),
                    f.scan_file,
                ]
            )
    return path


WEAKNESS_COLUMNS = [
    "host",
    "hostnames",
    "port",
    "service",
    "severity",
    "confidence",
    "rule_id",
    "title",
    "category",
    "evidence",
    "recommendation",
    "source_script",
    "scan_file",
]


def write_weakness_csv(analysis: Analysis, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(WEAKNESS_COLUMNS)
        for w in analysis.weaknesses:
            writer.writerow(
                [
                    w.host,
                    w.hostnames,
                    w.port,
                    w.service,
                    w.severity,
                    w.confidence,
                    w.rule_id,
                    w.title,
                    w.category,
                    " ".join((w.evidence or "").split()),
                    " ".join((w.recommendation or "").split()),
                    w.source_script,
                    w.scan_file,
                ]
            )
    return path


def write_validation_csv(analysis: Analysis, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "code", "scope", "target", "message"])
        for i in analysis.issues:
            writer.writerow([i.severity, i.code, i.scope, i.target, " ".join(i.message.split())])
    return path


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

CSS = """
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#14181f; --muted:#5c6673; --line:#e2e6eb;
  --accent:#2a5bd7; --chip:#eef1f6;
  --crit:#8b1a1a; --crit-bg:#fdeaea; --high:#b64a06; --high-bg:#fdf0e6;
  --med:#8a6100; --med-bg:#fcf5e2; --low:#2f6a4f; --low-bg:#eaf5ef;
  --unk:#4a5260; --unk-bg:#eef0f3;
  --err:#8b1a1a; --warn:#8a6100; --info:#3a5670;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0f1216; --panel:#161a21; --ink:#e6e9ee; --muted:#98a2b0; --line:#262c36;
    --accent:#7aa2f7; --chip:#1e242d;
    --crit:#ff8a8a; --crit-bg:#2c1618; --high:#ffb072; --high-bg:#2b1d12;
    --med:#f2d07a; --med-bg:#2a2413; --low:#8fd6b0; --low-bg:#132420;
    --unk:#aab3c0; --unk-bg:#1c212a;
    --err:#ff8a8a; --warn:#f2d07a; --info:#9dc0e8;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 6px} h2{font-size:19px;margin:36px 0 12px}
h3{font-size:15px;margin:22px 0 8px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em;font-weight:600}
a{color:var(--accent)} .sub{color:var(--muted);margin:0 0 24px;font-size:14px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:28px;font-weight:650;line-height:1.1}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
.card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)}
.card.med .n{color:var(--med)} .card.low .n{color:var(--low)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px;min-width:900px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--chip);font-size:12px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);position:sticky;top:0;white-space:nowrap}
tr:last-child td{border-bottom:none}
td.nowrap,th.nowrap{white-space:nowrap}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11.5px;
  font-weight:650;letter-spacing:.03em;white-space:nowrap}
.b-CRITICAL{background:var(--crit-bg);color:var(--crit)}
.b-HIGH{background:var(--high-bg);color:var(--high)}
.b-MEDIUM{background:var(--med-bg);color:var(--med)}
.b-LOW{background:var(--low-bg);color:var(--low)}
.b-UNKNOWN{background:var(--unk-bg);color:var(--unk)}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;background:var(--chip);
  color:var(--muted);font-size:11.5px;white-space:nowrap}
.tag.kev{background:var(--crit-bg);color:var(--crit);font-weight:600}
.tag.exp{background:var(--crit-bg);color:var(--crit);font-weight:650}
.desc{color:var(--muted);font-size:12.5px;max-width:520px}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.controls input,.controls select{background:var(--panel);color:var(--ink);
  border:1px solid var(--line);border-radius:7px;padding:7px 10px;font-size:13px}
.controls input{min-width:240px;flex:1}
.issue{display:flex;gap:12px;padding:9px 0;border-bottom:1px solid var(--line)}
.issue:last-child{border-bottom:none}
.issue .code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;
  white-space:nowrap;min-width:190px}
.issue.error .code{color:var(--err)} .issue.warn .code{color:var(--warn)}
.issue.info .code{color:var(--info)}
.issue .body{font-size:13.5px}
.issue .tgt{color:var(--muted);font-size:12px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
  background:var(--chip);padding:1px 5px;border-radius:4px}
.note{font-size:13px;color:var(--muted)}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
ul.tight{margin:6px 0;padding-left:20px} ul.tight li{margin:3px 0;font-size:13.5px}
"""

JS = """
(function(){
  var q=document.getElementById('q'), sev=document.getElementById('sev'),
      conf=document.getElementById('conf'), rows=[].slice.call(
        document.querySelectorAll('#findings tbody tr')), count=document.getElementById('count');
  function apply(){
    var t=(q.value||'').toLowerCase(), s=sev.value, c=conf.value, n=0;
    rows.forEach(function(r){
      if(!r.dataset.sev){return;}
      var ok=(s==='all'||r.dataset.sev===s)&&(c==='all'||r.dataset.conf===c)
             &&(!t||r.textContent.toLowerCase().indexOf(t)>-1);
      r.style.display=ok?'':'none'; if(ok)n++;
    });
    count.textContent=n+' of '+rows.length+' findings shown';
  }
  [q,sev,conf].forEach(function(el){el.addEventListener('input',apply)});
  apply();

  var wq=document.getElementById('wq'), wsev=document.getElementById('wsev'),
      wcat=document.getElementById('wcat'), wrows=[].slice.call(
        document.querySelectorAll('#weaknesses tbody tr')),
      wcount=document.getElementById('wcount');
  function wapply(){
    var t=(wq.value||'').toLowerCase(), s=wsev.value, c=wcat.value, n=0;
    wrows.forEach(function(r){
      if(!r.dataset.wsev){return;}
      var ok=(s==='all'||r.dataset.wsev===s)&&(c==='all'||r.dataset.cat===c)
             &&(!t||r.textContent.toLowerCase().indexOf(t)>-1);
      r.style.display=ok?'':'none'; if(ok)n++;
    });
    wcount.textContent=n+' of '+wrows.length+' weaknesses shown';
  }
  if(wq){[wq,wsev,wcat].forEach(function(el){el.addEventListener('input',wapply)}); wapply();}
})();
"""


def _sev_badge(sev: str) -> str:
    sev = sev if sev in SEVERITIES else "UNKNOWN"
    return f'<span class="badge b-{sev}">{sev}</span>'


def _finding_row(f: Finding) -> str:
    cvss = "—" if f.cvss is None else f"{f.cvss:.1f}"
    refs = ""
    if f.references:
        refs = f' <a href="{_esc(f.references[0])}" target="_blank" rel="noopener">ref</a>'
    nvd_link = (
        f'<a href="https://nvd.nist.gov/vuln/detail/{_esc(f.cve)}" '
        f'target="_blank" rel="noopener">{_esc(f.cve)}</a>'
        if f.cve.upper().startswith("CVE-")
        else _esc(f.cve)
    )
    exploit = ' <span class="tag exp">exploit</span>' if f.exploit_known else ""
    # CISA KEV is the strongest single signal in the row: the vulnerability has
    # been seen used against real targets, which no CVSS score tells you.
    if f.kev:
        due = f" (fix by {_esc(f.kev_due)})" if f.kev_due else ""
        exploit = f' <span class="tag kev">KEV{due}</span>' + exploit
    if f.epss is not None:
        exploit += f' <span class="tag">EPSS {f.epss * 100:.1f}%</span>'
    if f.backport_suspected:
        exploit += ' <span class="tag">backport?</span>'
    desc = " ".join((f.description or "").split())
    if len(desc) > 300:
        desc = desc[:300].rsplit(" ", 1)[0] + "…"

    return (
        f'<tr data-sev="{_esc(f.severity)}" data-conf="{_esc(f.confidence)}">'
        f'<td class="nowrap">{_sev_badge(f.severity)}</td>'
        f'<td class="nowrap">{cvss}</td>'
        f'<td class="nowrap">{nvd_link}{exploit}</td>'
        f'<td class="nowrap">{_esc(f.host)}<br><span class="tag">{_esc(f.hostnames) or "&nbsp;"}</span></td>'
        f'<td class="nowrap">{_esc(f.port)}</td>'
        f"<td>{_esc(f.product)}</td>"
        f'<td class="nowrap"><span class="tag">{_esc(f.confidence)}</span> '
        f'<span class="tag">{_esc(f.source)}</span></td>'
        f'<td class="desc">{_esc(desc)}{refs}</td>'
        "</tr>"
    )


def _weakness_rows(analysis: Analysis) -> str:
    rows = []
    for w in analysis.weaknesses:
        rows.append(
            f'<tr data-wsev="{_esc(w.severity)}" data-cat="{_esc(w.category)}">'
            f'<td class="nowrap">{_sev_badge(w.severity)}</td>'
            f'<td class="nowrap">{_esc(w.host)}<br>'
            f'<span class="tag">{_esc(w.hostnames) or "&nbsp;"}</span></td>'
            f'<td class="nowrap">{_esc(w.port)}</td>'
            f"<td>{_esc(w.title)}<br>"
            f'<span class="tag">{_esc(w.rule_id)}</span> '
            f'<span class="tag">{_esc(w.confidence)}</span> '
            f'<span class="tag">{_esc(w.source_script)}</span></td>'
            f'<td class="desc"><code>{_esc(w.evidence)}</code></td>'
            f'<td class="desc">{_esc(w.recommendation)}</td>'
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="6" class="empty">No non-CVE weaknesses detected.</td></tr>'
    return "".join(rows)


def _suppressed_block(analysis: Analysis) -> str:
    """What was deliberately left out, and why.

    A filtered report and a clean target look identical unless the filtering is
    stated, so every withheld row is accounted for here.
    """
    if not analysis.suppressed:
        return ""
    items = "".join(
        f"<li><strong>{count}</strong> {_esc(reason)}</li>"
        for reason, count in sorted(analysis.suppressed.items(), key=lambda kv: -kv[1])
    )
    return (
        '<h3>Withheld from the tables above</h3><div class="panel">'
        '<p class="note">Rows excluded to keep the findings actionable. Nothing here was '
        "discarded — each line says how to bring it back.</p>"
        f'<ul class="tight">{items}</ul></div>'
    )


def _issues_block(analysis: Analysis) -> str:
    if not analysis.issues:
        return '<div class="empty">No validation issues raised.</div>'
    out = []
    for i in analysis.issues:
        out.append(
            f'<div class="issue {_esc(i.severity)}">'
            f'<div class="code">{_esc(i.code)}</div>'
            f'<div class="body">{_esc(i.message)}'
            f'<div class="tgt">{_esc(i.scope)}: {_esc(i.target)}</div></div></div>'
        )
    return "".join(out)


def _merge_hosts(analysis: Analysis) -> list[tuple[str, list[str], list]]:
    """Collapse the same host seen in several scan files into one inventory entry.

    Where two files disagree about a port, the richer record wins — a probed
    fingerprint from XML beats a guess from greppable output.
    """
    names: dict[str, list[str]] = {}
    ports: dict[str, dict[str, object]] = {}

    for host in analysis.hosts:
        if host.status == "down":
            continue
        seen = names.setdefault(host.address, [])
        for name in host.hostnames:
            if name not in seen:
                seen.append(name)
        bucket = ports.setdefault(host.address, {})
        for port in host.open_ports:
            existing = bucket.get(port.key)
            if existing is None:
                bucket[port.key] = port
                continue
            better = (port.service.probed, len(port.service.banner), port.service.conf)
            worse = (existing.service.probed, len(existing.service.banner), existing.service.conf)
            if better > worse:
                bucket[port.key] = port

    out = []
    for address in sorted(names):
        port_list = sorted(
            ports.get(address, {}).values(), key=lambda p: (p.protocol, p.portid)
        )
        out.append((address, names[address], port_list))
    return out


def _inventory_block(analysis: Analysis) -> str:
    rows = []
    for address, hostnames, host_ports in _merge_hosts(analysis):
        if not host_ports:
            rows.append(
                f'<tr><td class="nowrap">{_esc(address)}</td>'
                f"<td>{_esc(', '.join(hostnames))}</td>"
                f'<td class="nowrap">—</td><td>no open ports</td>'
                f'<td class="nowrap">—</td><td class="nowrap">—</td></tr>'
            )
            continue

        for port in host_ports:
            svc = port.service
            per_port: dict[str, int] = {}
            for f in analysis.findings:
                if f.host == address and f.port == port.key:
                    per_port[f.severity] = per_port.get(f.severity, 0) + 1
            port_findings = sum(per_port.values())
            sev_bits = " ".join(
                f'<span class="badge b-{s}">{per_port[s]}</span>'
                for s in ("CRITICAL", "HIGH")
                if per_port.get(s)
            )
            method = "probed" if svc.probed else "guessed"
            conf = f" · conf {svc.conf}/10" if svc.conf else ""
            rows.append(
                f'<tr><td class="nowrap">{_esc(address)}</td>'
                f"<td>{_esc(', '.join(hostnames))}</td>"
                f'<td class="nowrap">{_esc(port.key)}</td>'
                f"<td>{_esc(svc.banner)}</td>"
                f'<td class="nowrap"><span class="tag">{method}{conf}</span></td>'
                f'<td class="nowrap">{port_findings or "—"} {sev_bits}</td></tr>'
            )

    if not rows:
        return '<div class="empty">No live hosts with open ports.</div>'
    return (
        '<div class="tablewrap"><table><thead><tr>'
        "<th>Host</th><th>Hostnames</th><th>Port</th><th>Service</th>"
        "<th>Detection</th><th>Findings</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _scans_block(analysis: Analysis) -> str:
    rows = []
    for scan in analysis.scans:
        status = "completed" if scan.completed else "INCOMPLETE"
        rows.append(
            f'<tr><td>{_esc(os.path.basename(scan.source))}</td>'
            f'<td class="nowrap">{_esc(scan.fmt)}</td>'
            f'<td class="nowrap">{_esc(scan.nmap_version) or "—"}</td>'
            f'<td class="nowrap">{_esc(status)}</td>'
            f'<td class="nowrap">{len(scan.hosts)}</td>'
            f"<td><code>{_esc(scan.args) or '—'}</code></td></tr>"
        )
    return (
        '<div class="tablewrap"><table><thead><tr>'
        "<th>File</th><th>Format</th><th>nmap</th><th>Status</th><th>Hosts</th>"
        "<th>Command line</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def write_html(analysis: Analysis, path: str, title: str = "Nmap Scan Validation & CVE Report") -> str:
    counts = analysis.combined_counts()
    cve_counts = analysis.counts_by_severity()
    weak_counts = analysis.weakness_counts_by_severity()

    # A host scanned in several files must count once, and its open ports are the
    # union across those files rather than the sum.
    live_ports: dict[str, set[str]] = {}
    for host in analysis.hosts:
        if host.status == "down":
            continue
        live_ports.setdefault(host.address, set()).update(p.key for p in host.open_ports)
    live = live_ports
    open_ports = sum(len(ports) for ports in live_ports.values())
    errors = sum(1 for i in analysis.issues if i.severity == "error")
    warns = sum(1 for i in analysis.issues if i.severity == "warn")
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = "".join(_finding_row(f) for f in analysis.findings)
    if not rows:
        rows = '<tr><td colspan="8" class="empty">No findings.</td></tr>'

    skipped = ""
    if analysis.skipped_services:
        items = "".join(f"<li>{_esc(s)}</li>" for s in sorted(set(analysis.skipped_services))[:60])
        skipped = (
            '<h3>Services not matched</h3><div class="panel">'
            '<p class="note">These open services could not be matched to CVEs with any '
            "confidence, usually because no version was recovered. They are unassessed, "
            "not clean.</p>"
            f'<ul class="tight">{items}</ul></div>'
        )

    mode = "offline (NSE output only)" if analysis.offline else "NVD 2.0 + Vulners"

    withheld_block = _suppressed_block(analysis)
    weakness_rows = _weakness_rows(analysis)
    categories = "".join(
        f'<option value="{_esc(c)}">{_esc(c)}</option>'
        for c in sorted({w.category for w in analysis.weaknesses if w.category})
    )

    body = f"""
<div class="wrap">
  <h1>{_esc(title)}</h1>
  <p class="sub">Generated {generated} · {len(analysis.scans)} scan file(s) ·
     {len(live)} live host(s) · {open_ports} open port(s) ·
     lookup source: {_esc(mode)} · {analysis.queried} unique service signature(s) queried</p>

  <div class="cards">
    <div class="card crit"><div class="n">{counts['CRITICAL']}</div><div class="l">Critical</div></div>
    <div class="card high"><div class="n">{counts['HIGH']}</div><div class="l">High</div></div>
    <div class="card med"><div class="n">{counts['MEDIUM']}</div><div class="l">Medium</div></div>
    <div class="card low"><div class="n">{counts['LOW']}</div><div class="l">Low</div></div>
    <div class="card"><div class="n">{errors}</div><div class="l">Scan errors</div></div>
    <div class="card"><div class="n">{warns}</div><div class="l">Scan warnings</div></div>
  </div>
  <p class="note">Totals combine {len(analysis.findings)} CVE finding(s) and
     {len(analysis.weaknesses)} non-CVE weakness(es).
     CVE: {cve_counts['CRITICAL']}C/{cve_counts['HIGH']}H/{cve_counts['MEDIUM']}M/{cve_counts['LOW']}L ·
     non-CVE: {weak_counts['CRITICAL']}C/{weak_counts['HIGH']}H/{weak_counts['MEDIUM']}M/{weak_counts['LOW']}L</p>

  <h2>Scan validation</h2>
  <p class="note">Whether the scans themselves are trustworthy. Coverage gaps here limit
     what the findings below can prove — an absent finding is only as strong as the scan
     that looked for it.</p>
  <div class="panel">{_issues_block(analysis)}</div>

  <h3>Scan files</h3>
  {_scans_block(analysis)}

  <h2>CVE findings (version-matched)</h2>
  <p class="note">Confidence reflects how the match was made:
     <strong>high</strong> = nmap-supplied CPE with a version, range-matched by NVD;
     <strong>medium</strong> = version probed but CPE synthesised or keyword matched;
     <strong>low</strong> = no version, product-level match only.
     Everything here is a <em>potential</em> match derived from a banner — confirm before
     reporting.</p>
  <div class="controls">
    <input id="q" type="search" placeholder="Filter by host, CVE, product…">
    <select id="sev">
      <option value="all">All severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
      <option value="UNKNOWN">Unknown</option>
    </select>
    <select id="conf">
      <option value="all">All confidence</option>
      <option value="high">High confidence</option>
      <option value="medium">Medium confidence</option>
      <option value="low">Low confidence</option>
    </select>
  </div>
  <p class="note" id="count"></p>
  <div class="tablewrap"><table id="findings"><thead><tr>
    <th class="nowrap">Severity</th><th class="nowrap">CVSS</th><th>CVE</th><th>Host</th>
    <th>Port</th><th>Service</th><th>Match</th><th>Description</th>
  </tr></thead><tbody>{rows}</tbody></table></div>

  <h2>Configuration &amp; weak-crypto findings (non-CVE)</h2>
  <p class="note">Weaknesses that carry no CVE — weak Diffie-Hellman groups and cipher
     suites, missing SMB signing, anonymous access, expired certificates, cleartext and
     exposed services. These come from what the scan <em>observed</em> rather than from a
     version match, so they do not depend on banner accuracy and are generally the more
     directly reportable half of this report.</p>
  <div class="controls">
    <input id="wq" type="search" placeholder="Filter by host, rule, service…">
    <select id="wsev">
      <option value="all">All severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select id="wcat">
      <option value="all">All categories</option>
      {categories}
    </select>
  </div>
  <p class="note" id="wcount"></p>
  <div class="tablewrap"><table id="weaknesses"><thead><tr>
    <th class="nowrap">Severity</th><th>Host</th><th>Port</th><th>Weakness</th>
    <th>Evidence</th><th>Recommendation</th>
  </tr></thead><tbody>{weakness_rows}</tbody></table></div>

  <h2>Host &amp; service inventory</h2>
  {_inventory_block(analysis)}

  {skipped}
  {withheld_block}

  <h2>Method &amp; limitations</h2>
  <div class="panel"><ul class="tight">
    <li><strong>CVE findings</strong> are derived from <strong>service banners</strong>.
        Banners can be wrong, stale, deliberately altered, or backported — a matched CVE
        is a lead to verify, not a confirmed vulnerability.</li>
    <li><strong>Non-CVE weaknesses</strong> are derived from what the scan actually
        observed (negotiated ciphers, DH moduli, certificate fields, script results), so
        they do not share the banner-accuracy problem. Where a rule reads a script's own
        conclusion, it inherits that script's reliability.</li>
    <li>Backported security fixes are the most common false positive: distributions patch
        vulnerabilities without changing the advertised version string.</li>
    <li>Ports outside the scanned range, and services behind filtering, are untested rather
        than proven safe.</li>
    <li>No exploitation or active verification was performed by this tool; it only reads
        existing scan output.</li>
  </ul></div>
</div>
<script>{JS}</script>
"""

    doc = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)}</title><style>{CSS}</style></head><body>{body}</body></html>"
    )

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
