"""Report rendering: a self-contained HTML report and a flat CSV of findings."""

from __future__ import annotations

import csv
import datetime
import html
import os

from . import knowledge
from .model import Analysis, Finding, Port, Service
from .playbook import build as build_playbook


def _kb_key_for(port_str, service_name) -> str:
    """The Service-KB entry key for a port, for cross-linking. '' if none."""
    try:
        pid = int(str(port_str).split("/")[0])
    except (ValueError, IndexError):
        return ""
    entry = knowledge.for_port(Port(portid=pid, service=Service(name=service_name or "")))
    return entry["key"] if entry else ""

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


def _analysis_dict(analysis: Analysis) -> dict:
    """The whole analysis as plain data, for JSON/Markdown export."""
    inventory = []
    for address, hostnames, host_ports in _merge_hosts(analysis):
        for port in host_ports:
            svc = port.service
            inventory.append({
                "host": address, "hostnames": hostnames, "port": port.key,
                "service": svc.name, "product": svc.banner,
                "detection": "probed" if svc.probed else "guessed", "conf": svc.conf,
            })
    return {
        "tool": "nmapvuln",
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "scan_files": len(analysis.scans),
            "live_hosts": sum(1 for h in analysis.hosts if h.status != "down"),
            "findings": len(analysis.findings),
            "weaknesses": len(analysis.weaknesses),
            "severity_counts": analysis.combined_counts(),
        },
        "scans": [{"source": os.path.basename(s.source), "format": s.fmt,
                   "nmap_version": s.nmap_version, "args": s.args,
                   "completed": s.completed, "hosts": len(s.hosts)} for s in analysis.scans],
        "issues": [{"severity": i.severity, "code": i.code, "scope": i.scope,
                    "target": i.target, "message": i.message} for i in analysis.issues],
        "findings": [{
            "host": f.host, "hostnames": f.hostnames, "port": f.port, "service": f.service,
            "product": f.product, "cve": f.cve, "cvss": f.cvss, "severity": f.severity,
            "confidence": f.confidence, "source": f.source, "kev": f.kev, "kev_due": f.kev_due,
            "epss": f.epss, "backport_suspected": f.backport_suspected,
            "exploit_known": f.exploit_known, "published": f.published,
            "matched_on": f.matched_on, "description": f.description,
            "references": f.references, "scan_file": f.scan_file,
        } for f in analysis.findings],
        "weaknesses": [{
            "host": w.host, "hostnames": w.hostnames, "port": w.port, "service": w.service,
            "severity": w.severity, "confidence": w.confidence, "rule_id": w.rule_id,
            "title": w.title, "category": w.category, "evidence": w.evidence,
            "recommendation": w.recommendation, "source_script": w.source_script,
            "scan_file": w.scan_file,
        } for w in analysis.weaknesses],
        "inventory": inventory,
        "followup_scans": knowledge.followup_scan(analysis),
        "suppressed": analysis.suppressed,
    }


def write_json(analysis: Analysis, path: str) -> str:
    import json
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_analysis_dict(analysis), fh, ensure_ascii=False, indent=1)
    return path


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    def esc(cell):
        return " ".join(str(cell).split()).replace("|", "\\|")
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return "\n".join(out)


def write_markdown(analysis: Analysis, path: str,
                   title: str = "Nmap Scan Validation & CVE Report") -> str:
    data = _analysis_dict(analysis)
    s = data["summary"]
    c = s["severity_counts"]
    out = [f"# {title}", ""]
    out.append(f"Generated {data['generated']} · {s['scan_files']} scan file(s) · "
               f"{s['live_hosts']} live host(s) · {s['findings']} CVE finding(s) · "
               f"{s['weaknesses']} non-CVE weakness(es)")
    out.append("")
    out.append(f"**Severity (combined):** {c['CRITICAL']} critical · {c['HIGH']} high · "
               f"{c['MEDIUM']} medium · {c['LOW']} low")
    out.append("")

    if analysis.issues:
        out += ["## Scan validation", ""]
        out.append(_md_table(["Severity", "Code", "Scope", "Target", "Message"],
                             [[i.severity, i.code, i.scope, i.target, i.message]
                              for i in analysis.issues]))
        out.append("")

    out += ["## CVE findings", ""]
    if analysis.findings:
        out.append(_md_table(
            ["Sev", "CVSS", "CVE", "KEV", "EPSS", "Host", "Port", "Service", "Conf"],
            [[f.severity, "" if f.cvss is None else f"{f.cvss:.1f}", f.cve,
              "yes" if f.kev else "", "" if f.epss is None else f"{f.epss*100:.1f}%",
              f.host, f.port, f.product, f.confidence] for f in analysis.findings]))
    else:
        out.append("_No CVE findings._")
    out.append("")

    out += ["## Non-CVE weaknesses", ""]
    if analysis.weaknesses:
        out.append(_md_table(
            ["Sev", "Conf", "Host", "Port", "Weakness", "Evidence"],
            [[w.severity, w.confidence, w.host, w.port, w.title, w.evidence]
             for w in analysis.weaknesses]))
    else:
        out.append("_No non-CVE weaknesses._")
    out.append("")

    if data["followup_scans"]:
        out += ["## Suggested next scan", ""]
        for run in data["followup_scans"]:
            out.append(f"- **{run['label']}**")
            out.append(f"  ```\n  {run['command']}\n  ```")
        out.append("")

    out += ["## Inventory", ""]
    out.append(_md_table(["Host", "Hostnames", "Port", "Service", "Detection"],
                         [[r["host"], ", ".join(r["hostnames"]), r["port"],
                           r["product"], r["detection"]] for r in data["inventory"]]))
    out.append("")

    if analysis.suppressed:
        out += ["## Withheld", ""]
        for reason, n in sorted(analysis.suppressed.items(), key=lambda kv: -kv[1]):
            out.append(f"- **{n}** {reason}")
        out.append("")

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    return path


def write_enumeration_csv(analysis: Analysis, path: str) -> str:
    """One row per host/port/step, commands already filled in."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "hostnames", "port", "service", "action", "command", "expect", "note"])
        for entry in build_playbook(analysis.hosts):
            for step in entry.steps:
                writer.writerow(
                    [
                        entry.host,
                        entry.hostnames,
                        entry.port,
                        entry.service,
                        step.action,
                        step.command,
                        " ".join(step.expect.split()),
                        " ".join(step.note.split()),
                    ]
                )
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
details.pb{border:1px solid var(--line);border-radius:7px;margin:7px 0;background:var(--panel)}
details.pb summary{cursor:pointer;padding:9px 12px;font-size:14px}
details.pb[open] summary{border-bottom:1px solid var(--line)}
details.pb .tablewrap{padding:4px 10px 10px}
details.pb code{white-space:pre-wrap;word-break:break-all}
.tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:2px solid var(--line);
  margin:18px 0 0;position:sticky;top:0;background:var(--bg);z-index:5;padding-top:6px}
.tabs button{appearance:none;border:1px solid var(--line);border-bottom:none;
  background:var(--chip);color:var(--muted);padding:8px 14px;font-size:13.5px;
  border-radius:7px 7px 0 0;cursor:pointer;font-weight:600}
.tabs button:hover{color:var(--ink)}
.tabs button.active{background:var(--panel);color:var(--accent);
  box-shadow:inset 0 -2px 0 var(--accent)}
.tabs button .pill{display:inline-block;margin-left:6px;padding:0 6px;border-radius:9px;
  background:var(--bg);color:var(--muted);font-size:11.5px;font-weight:600}
.panel-tab{display:none;padding-top:14px} .panel-tab.active{display:block}
.kb-intro{color:var(--muted);font-size:13.5px;margin:4px 0 10px}
details.kb{border:1px solid var(--line);border-radius:7px;margin:7px 0;background:var(--panel)}
details.kb>summary{cursor:pointer;padding:10px 12px;font-size:14px;font-weight:600}
details.kb>summary .where{font-weight:400;color:var(--muted);font-size:12.5px}
details.kb[open]>summary{border-bottom:1px solid var(--line)}
.kb-body{padding:6px 10px 10px;overflow-x:auto}
.phase-head{margin:10px 0 2px;font-size:12px;letter-spacing:.04em;text-transform:uppercase;
  color:var(--accent);font-weight:700}
table.kb-tbl{width:100%;border-collapse:collapse;table-layout:fixed}
table.kb-tbl td{vertical-align:top;padding:7px 8px;border-top:1px solid var(--line);
  font-size:13px;overflow-wrap:anywhere}
table.kb-tbl td.m{width:22%;font-weight:600}
table.kb-tbl code{white-space:pre-wrap;overflow-wrap:anywhere;display:block;
  background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:5px 7px;margin:2px 0}
.kb-note{color:var(--muted)} .kb-note a{color:var(--accent)}
.warnbar{border:1px solid var(--high);background:var(--high-bg);color:var(--high);
  border-radius:7px;padding:9px 12px;font-size:13px;margin:6px 0 12px}
.relbox{border:1px solid var(--accent);background:var(--chip);border-radius:7px;
  padding:7px 10px;margin:4px 0 8px}
.relbox>strong{color:var(--accent);font-size:12.5px}
a.kblink{color:var(--accent);text-decoration:none;border-bottom:1px dotted var(--accent)}
a.kblink:hover{text-decoration:none;border-bottom-style:solid}
.tbar{display:flex;justify-content:flex-end;margin:4px 0}
.expbtn,.copybtn{appearance:none;border:1px solid var(--line);background:var(--chip);
  color:var(--muted);border-radius:6px;cursor:pointer;font-size:12px;padding:4px 10px}
.expbtn:hover,.copybtn:hover{color:var(--accent);border-color:var(--accent)}
.cmdwrap{position:relative}
.copybtn{position:absolute;top:4px;right:4px;padding:2px 8px;font-size:11px;opacity:.75}
.copybtn:hover{opacity:1}
.copybtn.ok{color:var(--low);border-color:var(--low)}
.srctag{display:inline-block;margin-left:4px;padding:0 7px;border-radius:9px;font-size:11px;
  font-weight:600;background:var(--accent);color:#fff;vertical-align:middle}
.htblock{margin-top:12px;border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:7px;padding:8px 10px;background:var(--chip)}
.htlabel{font-size:11.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
  color:var(--accent);margin-bottom:4px}
pre.htcmd{position:relative;margin:5px 0;overflow-x:auto;background:var(--bg);
  border:1px solid var(--line);border-radius:5px;padding:7px 9px}
pre.htcmd code{white-space:pre;font-size:12.5px}
.htcredit{margin-top:6px;font-size:11.5px;color:var(--muted)}
.htcredit a{color:var(--accent)}
.navbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 12px;
  position:sticky;top:46px;background:var(--bg);padding:6px 0;z-index:4}
.navbar input{flex:1;min-width:200px;padding:8px 11px;border:1px solid var(--line);
  border-radius:8px;background:var(--panel);color:var(--ink);font-size:14px}
.minibtn{appearance:none;border:1px solid var(--line);background:var(--chip);color:var(--muted);
  border-radius:8px;cursor:pointer;font-size:12.5px;padding:7px 12px;white-space:nowrap}
.minibtn:hover{color:var(--accent);border-color:var(--accent)}
.navcount{font-size:12.5px;color:var(--muted)}
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

  var tabs=[].slice.call(document.querySelectorAll('.tabs button')),
      panels=[].slice.call(document.querySelectorAll('.panel-tab'));
  function show(id){
    tabs.forEach(function(b){b.classList.toggle('active',b.dataset.tab===id);});
    panels.forEach(function(p){p.classList.toggle('active',p.id===id);});
    try{history.replaceState(null,'','#'+id);}catch(e){}
  }
  tabs.forEach(function(b){b.addEventListener('click',function(){show(b.dataset.tab);});});
  var start=(location.hash||'').replace('#','');
  show(tabs.some(function(b){return b.dataset.tab===start;})?start:(tabs[0]&&tabs[0].dataset.tab));

  var kq=document.getElementById('kbq');
  if(kq){
    var blocks=[].slice.call(document.querySelectorAll('#tab-kb details.kb'));
    kq.addEventListener('input',function(){
      var t=(kq.value||'').toLowerCase();
      blocks.forEach(function(d){
        var hit=d.textContent.toLowerCase().indexOf(t)>-1;
        d.style.display=hit?'':'none';
        if(t&&hit){d.open=true;} if(!t){d.open=d.dataset.detected==='1';}
      });
    });
  }

  // Copy buttons on every command block.
  function copyText(txt,btn){
    function done(){var o=btn.textContent;btn.textContent='copied';btn.classList.add('ok');
      setTimeout(function(){btn.textContent=o;btn.classList.remove('ok');},1200);}
    try{navigator.clipboard.writeText(txt).then(done,function(){fallback();});}
    catch(e){fallback();}
    function fallback(){var ta=document.createElement('textarea');ta.value=txt;
      document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}
      catch(e){}document.body.removeChild(ta);}
  }
  [].slice.call(document.querySelectorAll('.kb-body code, details.pb code, #tab-overview .kb-tbl code'))
    .forEach(function(code){
      var wrap=document.createElement('span');wrap.className='cmdwrap';
      code.parentNode.insertBefore(wrap,code);wrap.appendChild(code);
      var btn=document.createElement('button');btn.className='copybtn';btn.textContent='copy';
      btn.addEventListener('click',function(ev){ev.stopPropagation();copyText(code.textContent,btn);});
      wrap.appendChild(btn);
    });

  // CSV export of a table (visible rows only, so filters apply).
  function toCSV(table){
    var out=[];
    [].slice.call(table.querySelectorAll('tr')).forEach(function(tr){
      if(tr.offsetParent===null && tr.parentNode.tagName==='TBODY'){return;}
      var cells=[].slice.call(tr.querySelectorAll('th,td')).map(function(c){
        var t=(c.innerText||'').replace(/\\s+/g,' ').trim();
        return '"'+t.replace(/"/g,'""')+'"';
      });
      if(cells.length)out.push(cells.join(','));
    });
    return out.join('\\r\\n');
  }
  [].slice.call(document.querySelectorAll('.expbtn')).forEach(function(btn){
    btn.addEventListener('click',function(){
      var table=document.getElementById(btn.dataset.table); if(!table)return;
      var blob=new Blob(['\\ufeff'+toCSV(table)],{type:'text/csv;charset=utf-8;'});
      var a=document.createElement('a');a.href=URL.createObjectURL(blob);
      a.download=btn.dataset.file||'export.csv';document.body.appendChild(a);a.click();
      setTimeout(function(){URL.revokeObjectURL(a.href);document.body.removeChild(a);},100);
    });
  });

  // Per-host filter box.
  var hq=document.getElementById('hostq'), hc=document.getElementById('hostcount');
  if(hq){
    var hrows=[].slice.call(document.querySelectorAll('#tab-host details.kb'));
    function hfilter(){
      var t=(hq.value||'').toLowerCase(), n=0;
      hrows.forEach(function(d){
        var hit=d.querySelector('summary').textContent.toLowerCase().indexOf(t)>-1;
        d.style.display=hit?'':'none'; if(hit)n++;
      });
      if(hc)hc.textContent=n+' of '+hrows.length+' hosts';
    }
    hq.addEventListener('input',hfilter); hfilter();
  }

  // Expand all / collapse all buttons, scoped to a tab.
  [].slice.call(document.querySelectorAll('.minibtn')).forEach(function(btn){
    btn.addEventListener('click',function(){
      var scope=document.getElementById(btn.dataset.scope); if(!scope)return;
      var open=btn.dataset.act==='expand';
      [].slice.call(scope.querySelectorAll('details.kb')).forEach(function(d){
        if(d.style.display!=='none')d.open=open;
      });
    });
  });

  // Cross-link: a port in a findings/weakness row jumps to its Service-KB entry.
  [].slice.call(document.querySelectorAll('a.kblink')).forEach(function(a){
    a.addEventListener('click',function(ev){
      ev.preventDefault();
      var el=document.getElementById(a.dataset.kb); if(!el)return;
      show('tab-kb'); el.open=true;
      [].slice.call(document.querySelectorAll('#tab-kb details.kb')).forEach(function(d){d.style.display='';});
      el.scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
})();
"""


def _sev_badge(sev: str) -> str:
    sev = sev if sev in SEVERITIES else "UNKNOWN"
    return f'<span class="badge b-{sev}">{sev}</span>'


def _port_cell(port_str, service_name) -> str:
    """A port label that links to its Service-KB entry when one exists."""
    key = _kb_key_for(port_str, service_name)
    if not key:
        return _esc(port_str)
    return (f'<a class="kblink" href="#kb-{_esc(key)}" data-kb="kb-{_esc(key)}" '
            f'title="Jump to enumeration for this service">{_esc(port_str)}</a>')


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
        f'<td class="nowrap">{_port_cell(f.port, f.service)}</td>'
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
            f'<td class="nowrap">{_port_cell(w.port, w.service)}</td>'
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


def _playbook_block(analysis: Analysis) -> str:
    """Per-port enumeration steps: what to run next, and what the output means.

    Grouped under one host/port heading each, so the section reads as a
    checklist rather than a wall of commands.
    """
    entries = build_playbook(analysis.hosts)
    if not entries:
        return '<div class="empty">No open ports to enumerate.</div>'

    blocks = []
    for entry in entries:
        label = _esc(entry.host)
        if entry.hostnames:
            label += f' <span class="tag">{_esc(entry.hostnames)}</span>'
        rows = []
        for step in entry.steps:
            note = f'<div class="tgt">{_esc(step.note)}</div>' if step.note else ""
            rows.append(
                f"<tr><td>{_esc(step.action)}</td>"
                f'<td class="desc"><code>{_esc(step.command)}</code></td>'
                f'<td class="desc">{_esc(step.expect)}{note}</td></tr>'
            )
        blocks.append(
            f'<details class="pb"><summary><strong>{_esc(entry.port)}</strong> '
            f"{_esc(entry.service)} &mdash; {label}</summary>"
            '<div class="tablewrap"><table><thead><tr>'
            "<th>Step</th><th>Command</th><th>What the output tells you</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div></details>"
        )
    return "".join(blocks)


def _kb_rows_table(rows: list[dict], subst: Optional[tuple[str, int]] = None) -> str:
    """Render knowledge-bank technique rows, grouped under their phase headings."""
    out = []
    last_phase = None
    for row in rows:
        phase = row.get("phase") or ""
        if phase != last_phase:
            if last_phase is not None:
                out.append("</tbody></table>")
            heading = f'<div class="phase-head">{_esc(phase)}</div>' if phase else ""
            out.append(heading + '<table class="kb-tbl"><tbody>')
            last_phase = phase
        method = _esc(row.get("method") or "")
        command = row.get("command") or ""
        if subst and command:
            command = knowledge.substitute(command, subst[0], subst[1])
        desc = row.get("command_desc") or row.get("description") or ""
        remarks = row.get("remarks") or ""
        reference = row.get("reference") or ""
        cell = ""
        if command:
            cell += f"<code>{_esc(command)}</code>"
        if desc:
            cell += f"<div>{_esc(desc)}</div>"
        if remarks:
            cell += f'<div class="kb-note"><em>{_esc(remarks)}</em></div>'
        if reference and reference.startswith("http"):
            cell += (f'<div class="kb-note"><a href="{_esc(reference)}" target="_blank" '
                     f'rel="noopener">reference</a></div>')
        out.append(f'<tr><td class="m">{method or "&nbsp;"}</td><td>{cell}</td></tr>')
    if last_phase is not None:
        out.append("</tbody></table>")
    return "".join(out)


def _ht_section_html(ht: dict, subst: Optional[tuple[str, int]]) -> str:
    """Render a HackTricks entry's commands, grouped by heading, with credit."""
    parts = []
    summary = ht.get("summary")
    if summary:
        parts.append(f'<div class="kb-intro">{_esc(summary)}</div>')
    for section in ht.get("sections", []):
        heading = section.get("heading") or ""
        if heading:
            parts.append(f'<div class="phase-head">{_esc(heading)}</div>')
        for cmd in section.get("commands", []):
            text = knowledge.substitute(cmd, subst[0], subst[1]) if subst else cmd
            parts.append(f'<pre class="htcmd"><code>{_esc(text)}</code></pre>')
    ref = ht.get("reference")
    credit = (
        '<div class="htcredit">Source: '
        f'<a href="{_esc(ref)}" target="_blank" rel="noopener">HackTricks</a> '
        "by Carlos Polop, licensed CC BY-NC 4.0.</div>"
    )
    return f'<div class="htblock"><div class="htlabel">HackTricks commands</div>{"".join(parts)}{credit}</div>'


def _kb_block(analysis: Analysis) -> str:
    """Per-service knowledge bank. Each card merges the team spreadsheet bank and
    the HackTricks commands for that service. Detected services open first; the
    rest of both banks stay browsable below."""
    cards = knowledge.merged_service_cards(analysis.hosts)
    if not cards:
        return '<div class="empty">Knowledge bank is empty.</div>'

    blocks = []
    for card in cards:
        xlsx, ht = card["xlsx"], card["ht"]
        is_det = card["detected"]
        key = (xlsx or {}).get("key") or ht["key"]
        ports = ", ".join(str(p) for p in card["ports"])

        where, subst = "", None
        if is_det:
            seen = card["where"]
            where = f'<span class="where"> — detected on {_esc(", ".join(seen))}</span>'
            ip, pid = seen[0].rsplit(":", 1)
            subst = (ip, int(pid))

        body = ""
        if xlsx:
            if xlsx.get("intro"):
                body += f'<div class="kb-intro">{_esc(xlsx["intro"])}</div>'
            body += _kb_rows_table(xlsx["rows"], subst)
        if ht:
            body += _ht_section_html(ht, subst)

        tags = ""
        if xlsx and ht:
            tags = '<span class="srctag">team + HackTricks</span>'
        elif ht:
            tags = '<span class="srctag">HackTricks</span>'

        blocks.append(
            f'<details class="kb" id="kb-{_esc(key)}" '
            f'data-detected="{"1" if is_det else "0"}"{" open" if is_det else ""}>'
            f'<summary>{_esc(card["name"])} '
            f'<span class="where">[{_esc(ports)}]</span> {tags}{where}</summary>'
            f'<div class="kb-body">{body}</div></details>'
        )
    return "".join(blocks)


def _network_topic(topic: dict, reasons: Optional[list[str]] = None, is_open=False) -> str:
    rows = []
    for r in topic.get("rows", []):
        cell = ""
        if r.get("command"):
            cell += f'<code>{_esc(r["command"])}</code>'
        if r.get("expect"):
            cell += f'<div>{_esc(r["expect"])}</div>'
        if r.get("mitigation"):
            cell += f'<div class="kb-note"><strong>Fix:</strong> {_esc(r["mitigation"])}</div>'
        tool = _esc(r.get("tools") or "")
        tech = _esc(r.get("technique") or "")
        label = f"{tech}<br><span class='where'>{tool}</span>" if tool else tech
        rows.append(f'<tr><td class="m">{label}</td><td>{cell}</td></tr>')

    extra = ""
    if reasons:
        items = "".join(f"<li>{_esc(r)}</li>" for r in reasons)
        extra += f'<div class="relbox"><strong>Why it is relevant here</strong><ul class="tight">{items}</ul></div>'
    applies = topic.get("applies_when")
    if applies:
        extra += f'<div class="kb-note"><em>Applies when: {_esc(applies)}</em></div>'
    ref = topic.get("ref")
    if ref:
        extra += (f'<div class="kb-note">Further reading: <a href="{_esc(ref)}" target="_blank" '
                  f'rel="noopener">{_esc(ref)}</a></div>')
    return (
        f'<details class="kb"{" open" if is_open else ""}><summary>{_esc(topic["name"])}</summary>'
        f'<div class="kb-body"><div class="kb-intro">{_esc(topic.get("summary") or "")}</div>'
        f'{extra}<table class="kb-tbl"><tbody>{"".join(rows)}</tbody></table></div></details>'
    )


def _network_block(analysis: Analysis) -> str:
    bank = knowledge.network_bank()
    if not bank:
        return '<div class="empty">Network knowledge bank is empty.</div>'

    relevant, keys = knowledge.relevant_network_topics(analysis)
    blocks = []

    if relevant:
        blocks.append('<h3>Relevant to this scan</h3>')
        blocks.append('<p class="note">The scan found evidence that these are in reach. '
                      'These are preconditions met, not confirmed attacks.</p>')
        for topic, reasons in relevant:
            blocks.append(_network_topic(topic, reasons=reasons, is_open=True))

    rest = [t for t in bank.get("topics", []) if t["key"] not in keys]
    blocks.append('<h3>General reference</h3>')
    blocks.append('<p class="note">Network-wide techniques worth knowing on any engagement. '
                  'Layer-2 and routing attacks (VLAN hopping, HSRP/GLBP/EIGRP) and IDS/IPS '
                  'evasion are not derivable from a port scan, so they always live here.</p>')
    for topic in rest:
        blocks.append(_network_topic(topic))
    for topic in bank.get("reference", []):
        blocks.append(_network_topic(topic))
    return "".join(blocks)


def _methodology_block() -> str:
    pages = knowledge.methodology()
    if not pages:
        return ""
    blocks = ['<h3>General methodology</h3>']
    for page in pages:
        blocks.append(
            f'<details class="kb"><summary>{_esc(page["name"])}</summary>'
            f'<div class="kb-body">{_kb_rows_table(page["rows"])}</div></details>'
        )
    return "".join(blocks)


def _followup_block(analysis: Analysis) -> str:
    """The targeted next nmap run, derived from the services found."""
    runs = knowledge.followup_scan(analysis)
    if not runs:
        return ""
    rows = "".join(
        f'<tr><td class="m">{_esc(r["label"])}</td>'
        f'<td><code>{_esc(r["command"])}</code></td></tr>'
        for r in runs
    )
    return (
        "<h2>Suggested next scan</h2>"
        '<p class="note">A deeper nmap run built from the services this scan already found — '
        "the script set is chosen per host. Review before running, and only against systems "
        "you are authorised to test.</p>"
        f'<table class="kb-tbl"><tbody>{rows}</tbody></table>'
    )


def _triage_block(analysis: Analysis) -> str:
    """Everything for one host in one place: findings, weaknesses, open ports, leads."""
    rel_by_host: dict[str, list[str]] = {}
    relevant, _ = knowledge.relevant_network_topics(analysis)

    # Group hosts (union across scan files), reusing the inventory merge.
    merged = _merge_hosts(analysis)
    if not merged:
        return '<div class="empty">No live hosts with open ports.</div>'

    findings_by_host: dict[str, list[Finding]] = {}
    for f in analysis.findings:
        findings_by_host.setdefault(f.host, []).append(f)
    weak_by_host: dict[str, list] = {}
    for w in analysis.weaknesses:
        weak_by_host.setdefault(w.host, []).append(w)

    blocks = []
    for address, hostnames, host_ports in merged:
        n_f = len(findings_by_host.get(address, []))
        n_w = len(weak_by_host.get(address, []))
        names = f' <span class="where">{_esc(", ".join(hostnames))}</span>' if hostnames else ""

        # Open ports with KB links.
        port_bits = []
        for port in host_ports:
            cell = _port_cell(port.key, port.service.name)
            port_bits.append(f"<li>{cell} — {_esc(port.service.banner)}</li>")
        ports_html = f'<strong>Open ports</strong><ul class="tight">{"".join(port_bits)}</ul>' if port_bits else ""

        # Findings and weaknesses, compact.
        fw = []
        for f in sorted(findings_by_host.get(address, []), key=lambda x: x.sort_key)[:12]:
            fw.append(f'<li>{_sev_badge(f.severity)} {_esc(f.cve)} on {_esc(f.port)}</li>')
        for w in sorted(weak_by_host.get(address, []), key=lambda x: x.sort_key)[:12]:
            fw.append(f'<li>{_sev_badge(w.severity)} {_esc(w.title)} ({_esc(w.port)})</li>')
        fw_html = f'<strong>Findings &amp; weaknesses</strong><ul class="tight">{"".join(fw)}</ul>' if fw else ""

        # Network leads that name this host.
        leads = []
        for topic, reasons in relevant:
            hits = [r for r in reasons if address in r]
            if hits:
                leads.append(f'<li><strong>{_esc(topic["name"])}</strong>: {_esc(hits[0])}</li>')
        leads_html = f'<strong>Network leads</strong><ul class="tight">{"".join(leads)}</ul>' if leads else ""

        open_attr = " open" if (n_f or n_w) else ""
        blocks.append(
            f'<details class="kb"{open_attr}><summary>{_esc(address)}{names} '
            f'<span class="where">{len(host_ports)} ports · {n_f} CVE · {n_w} weakness</span>'
            f'</summary><div class="kb-body">{ports_html}{fw_html}{leads_html}</div></details>'
        )
    return "".join(blocks)


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
        '<div class="tablewrap"><table id="inventory"><thead><tr>'
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


def write_html(
    analysis: Analysis,
    path: str,
    title: str = "Nmap Scan Validation & CVE Report",
    include_playbook: bool = True,
) -> str:
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

    # Tab pill counts.
    n_cve = len(analysis.findings)
    n_weak = len(analysis.weaknesses)
    n_enum = len(build_playbook(analysis.hosts)) if include_playbook else 0
    n_kb = sum(1 for c in knowledge.merged_service_cards(analysis.hosts) if c["detected"])
    n_net = len(knowledge.network_bank().get("topics", []))

    def tab_btn(tab_id: str, label: str, pill=None) -> str:
        p = f' <span class="pill">{pill}</span>' if pill is not None else ""
        return f'<button data-tab="{tab_id}">{label}{p}</button>'

    enum_tab = ""
    if include_playbook:
        enum_tab = (
            '<div class="panel-tab" id="tab-enum">'
            "<h2>Enumeration playbook (manual next steps)</h2>"
            '<div class="warnbar">Reconnaissance commands you run yourself — the tool does '
            "not run them. Only run them against systems you are authorised to test.</div>"
            f"{_playbook_block(analysis)}"
            "</div>"
        )

    tabs = (
        tab_btn("tab-overview", "Overview")
        + tab_btn("tab-cve", "CVE Findings", n_cve)
        + tab_btn("tab-weak", "Weaknesses", n_weak)
        + (tab_btn("tab-enum", "Enumeration", n_enum) if include_playbook else "")
        + tab_btn("tab-kb", "Service KB", n_kb)
        + tab_btn("tab-net", "Network Attacks", n_net)
        + tab_btn("tab-host", "Per-host", len(live))
        + tab_btn("tab-inv", "Inventory")
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

  <div class="tabs">{tabs}</div>

  <div class="panel-tab" id="tab-overview">
    <p class="note">Totals combine {len(analysis.findings)} CVE finding(s) and
       {len(analysis.weaknesses)} non-CVE weakness(es).
       CVE: {cve_counts['CRITICAL']}C/{cve_counts['HIGH']}H/{cve_counts['MEDIUM']}M/{cve_counts['LOW']}L ·
       non-CVE: {weak_counts['CRITICAL']}C/{weak_counts['HIGH']}H/{weak_counts['MEDIUM']}M/{weak_counts['LOW']}L</p>

    <h2>Scan validation</h2>
    <p class="note">Whether the scans themselves are trustworthy. Coverage gaps here limit
       what the findings can prove — an absent finding is only as strong as the scan
       that looked for it.</p>
    <div class="panel">{_issues_block(analysis)}</div>

    <h3>Scan files</h3>
    {_scans_block(analysis)}
    {skipped}
    {withheld_block}

    {_followup_block(analysis)}

    <h2>Method &amp; limitations</h2>
    <div class="panel"><ul class="tight">
      <li><strong>CVE findings</strong> are derived from <strong>service banners</strong>.
          Banners can be wrong, stale, deliberately altered, or backported — a matched CVE
          is a lead to verify, not a confirmed vulnerability.</li>
      <li><strong>Non-CVE weaknesses</strong> are derived from what the scan actually
          observed (negotiated ciphers, DH moduli, certificate fields, script results), so
          they do not share the banner-accuracy problem.</li>
      <li>Backported security fixes are the most common false positive: distributions patch
          vulnerabilities without changing the advertised version string.</li>
      <li>Ports outside the scanned range, and services behind filtering, are untested rather
          than proven safe.</li>
      <li>No exploitation or active verification was performed by this tool; it only reads
          existing scan output.</li>
    </ul></div>
  </div>

  <div class="panel-tab" id="tab-cve">
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
        <option value="CRITICAL">Critical</option><option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option><option value="LOW">Low</option>
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
    <div class="tbar"><button class="expbtn" data-table="findings" data-file="findings.csv">⬇ Export CSV</button></div>
    <div class="tablewrap"><table id="findings"><thead><tr>
      <th class="nowrap">Severity</th><th class="nowrap">CVSS</th><th>CVE</th><th>Host</th>
      <th>Port</th><th>Service</th><th>Match</th><th>Description</th>
    </tr></thead><tbody>{rows}</tbody></table></div>
  </div>

  <div class="panel-tab" id="tab-weak">
    <h2>Configuration &amp; weak-crypto findings (non-CVE)</h2>
    <p class="note">Weaknesses that carry no CVE — weak Diffie-Hellman groups and cipher
       suites, missing SMB signing, anonymous access, expired certificates, cleartext and
       exposed services. These come from what the scan <em>observed</em> rather than from a
       version match, so they do not depend on banner accuracy.</p>
    <div class="controls">
      <input id="wq" type="search" placeholder="Filter by host, rule, service…">
      <select id="wsev">
        <option value="all">All severities</option>
        <option value="CRITICAL">Critical</option><option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option><option value="LOW">Low</option>
      </select>
      <select id="wcat"><option value="all">All categories</option>{categories}</select>
    </div>
    <p class="note" id="wcount"></p>
    <div class="tbar"><button class="expbtn" data-table="weaknesses" data-file="weaknesses.csv">⬇ Export CSV</button></div>
    <div class="tablewrap"><table id="weaknesses"><thead><tr>
      <th class="nowrap">Severity</th><th>Host</th><th>Port</th><th>Weakness</th>
      <th>Evidence</th><th>Recommendation</th>
    </tr></thead><tbody>{weakness_rows}</tbody></table></div>
  </div>

  {enum_tab}

  <div class="panel-tab" id="tab-kb">
    <h2>Service knowledge base</h2>
    <p class="note">Per-service enumeration and exploitation methodology. Services found in
       this scan are expanded first (commands filled in for the detected host); the rest of
       the bank is below, collapsed. <strong>Authorised testing only.</strong></p>
    <div class="navbar">
      <input id="kbq" type="search" placeholder="Filter the knowledge base…">
      <button class="minibtn" data-act="expand" data-scope="tab-kb">Expand all</button>
      <button class="minibtn" data-act="collapse" data-scope="tab-kb">Collapse all</button>
    </div>
    {_kb_block(analysis)}
  </div>

  <div class="panel-tab" id="tab-net">
    <h2>Network-layer attacks</h2>
    <div class="warnbar">Network-wide techniques (spoofing, IPv6 takeover, VLAN hopping,
      routing and first-hop-redundancy attacks). Methodology reference — the tool runs none
      of it. Only against systems you are authorised to test.</div>
    {_network_block(analysis)}
    {_methodology_block()}
  </div>

  <div class="panel-tab" id="tab-host">
    <h2>Per-host triage</h2>
    <p class="note">Everything the scan knows about each host in one place — open ports
       (each links to its enumeration), findings, weaknesses, and the network leads that
       name this host.</p>
    <div class="navbar">
      <input id="hostq" type="search" placeholder="Filter hosts by IP or name…">
      <button class="minibtn" data-act="expand" data-scope="tab-host">Expand all</button>
      <button class="minibtn" data-act="collapse" data-scope="tab-host">Collapse all</button>
      <span class="navcount" id="hostcount"></span>
    </div>
    {_triage_block(analysis)}
  </div>

  <div class="panel-tab" id="tab-inv">
    <h2>Host &amp; service inventory</h2>
    <div class="tbar"><button class="expbtn" data-table="inventory" data-file="inventory.csv">⬇ Export CSV</button></div>
    {_inventory_block(analysis)}
  </div>
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
