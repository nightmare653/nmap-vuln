# nmapvuln

**Turn an nmap scan into a clear vulnerability report.** You run nmap and save
its output; nmapvuln reads that output, matches the services it found against
known CVEs, flags weak configuration and crypto, ranks everything by what is
actually being exploited in the wild, and writes a self-contained HTML report
(plus CSV, Markdown and JSON) with a step-by-step enumeration playbook.

> [!IMPORTANT]
> **nmapvuln does not scan anything itself.** It never touches a target. You run
> `nmap` first and save the output to a file, then point nmapvuln at that file.
> Everything in the report comes from reading your existing scan.

Pure Python standard library — **no `pip install` needed**, works on Python 3.9+.

---

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Quick start (3 steps)](#quick-start-3-steps)
- [Command-line options — every flag explained](#command-line-options--every-flag-explained)
- [Understanding the report](#understanding-the-report)
- [The output files](#the-output-files)
- [Getting a free NVD API key](#getting-a-free-nvd-api-key)
- [Troubleshooting](#troubleshooting)
- [How it stays accurate](#how-it-stays-accurate)
- [What it checks for](#what-it-checks-for)
- [Knowledge base & enumeration playbook](#knowledge-base--enumeration-playbook)
- [Running the tests](#running-the-tests)
- [Project layout](#project-layout)
- [Authorisation & legal](#authorisation--legal)

---

## Requirements

| You need | Why | Check it with |
|---|---|---|
| **Python 3.9 or newer** | runs the tool | `python --version` |
| **nmap** | produces the scan nmapvuln reads | `nmap --version` |

That is all. nmapvuln has **no third-party dependencies** — you do not run
`pip install` for anything. (The only optional extra, `openpyxl`, is needed just
to rebuild the bundled knowledge base from its spreadsheet, which you will
probably never do.)

On Windows, if `python` is not found, try `py` instead of `python` in every
command below.

---

## Install

```bash
git clone https://github.com/nightmare653/nmap-vuln.git
cd nmap-vuln
```

That is the whole install. You now run it with `python nmapvuln.py …`.

---

## Quick start (3 steps)

### Step 1 — Scan a target with nmap and save the output

nmapvuln reads nmap's output, so you need a saved scan first. Use `-oA` to save
the result (the `-oA target` part writes `target.xml`, `target.nmap` and
`target.gnmap` — nmapvuln prefers the `.xml`):

```bash
nmap -sV -sC -oA target 192.0.2.10
```

What those nmap flags mean:

- `-sV` — detect the **version** of each service. **This is the most important
  one**: without it nmapvuln only knows "something is on port 80", not "Apache
  2.4.49", and cannot match CVEs.
- `-sC` — run nmap's default scripts (gets you TLS cipher info, SMB settings,
  etc. that power the weakness checks).
- `-oA target` — save the output to files named `target.*`.
- `192.0.2.10` — the target (use a hostname, IP, or range you are allowed to
  scan).

For the **best** coverage, use this scan instead — it adds the scripts the
weakness checks rely on:

```bash
nmap -sV -sC --script "vuln,ssl-enum-ciphers,ssl-dh-params,ssh2-enum-algos,smb-security-mode,smb-protocols" -p- -oA target 192.0.2.10
```

### Step 2 — Run nmapvuln on the saved output

Point it at the file (or a folder of scans — it searches folders for you):

```bash
python nmapvuln.py target.xml -o report
```

- `target.xml` — the scan file from step 1 (you can also pass `target.nmap`,
  `target.gnmap`, or a whole directory).
- `-o report` — write the report into a folder called `report`.

The first run with no API key is a little slow because the public CVE database
(NVD) limits anonymous requests. Results are cached for a week, so the next run
over the same services is instant. See [Getting a free NVD API
key](#getting-a-free-nvd-api-key) to speed it up, or add `--offline` to skip the
network entirely.

### Step 3 — Open the report

Open `report/report.html` in any browser. It is a single self-contained file —
no internet needed to view it, works in light and dark mode. Start on the
**Overview** tab and click through the others.

```bash
# macOS
open report/report.html
# Windows
start report/report.html
# Linux
xdg-open report/report.html
```

---

## Command-line options — every flag explained

Run `python nmapvuln.py --help` to see this list any time. Below, each flag is
explained in plain language with when you would use it.

### Where the report goes

| Flag | What it does | When to use it |
|---|---|---|
| `-o DIR`, `--out DIR` | Folder to write the report into. Default: `nmapvuln-report`. | Always — give each engagement its own folder, e.g. `-o client-report`. |
| `--name NAME` | Base filename for the outputs. Default: `report` (so you get `report.html`, `report-findings.csv`, …). | If you want files named after the target, e.g. `--name web01`. |
| `--title TEXT` | The heading shown at the top of the HTML report. | To label the report, e.g. `--title "Acme external scan"`. |

### Speed and data sources

| Flag | What it does | When to use it |
|---|---|---|
| `--nvd-key KEY` | Your free NVD API key (or set the `NVD_API_KEY` environment variable). Raises the request limit from 5 to 50 per 30 seconds — about 10× faster. | Strongly recommended. Get one free in [Step-by-step below](#getting-a-free-nvd-api-key). |
| `--vulners-key KEY` | Optional Vulners API key (or `VULNERS_API_KEY`). Adds extra exploit-availability data. | Only if you have a Vulners account. Safe to ignore. |
| `--offline` | Do not use the network at all. Reports only the CVEs nmap itself already found (via its `vuln`/`vulners` scripts). | No internet, air-gapped work, or a quick first pass. |
| `--no-enrich` | Skip the CISA KEV and EPSS lookups (the "is it being exploited?" ranking data). | Rarely. The ranking is one of the most useful parts. |
| `--kev-only` | Show **only** CVEs that appear in CISA's Known Exploited Vulnerabilities catalog — i.e. the ones confirmed to be used in real attacks. | When you want the shortest "fix these first" list. (Needs the internet; cannot be combined with `--offline`.) |

### Controlling noise vs. completeness

By default nmapvuln **hides** low-quality matches to keep the report trustworthy,
and tells you how many it hid. These flags bring the hidden items back.

| Flag | What it does | When to use it |
|---|---|---|
| `--include-unversioned` | Also match services where no version was detected ("this software has had CVEs" rather than "this host is vulnerable"). Very noisy. | When you want leads even without versions. Expect many more rows. |
| `--include-backported` | Include CVEs matched against a distribution build (e.g. `OpenSSH 8.2p1 Ubuntu…`). These are usually false positives because the vendor patched without changing the version string. | When you specifically want to review those possibilities yourself. |
| `--include-tentative` | Include weaknesses the scan could not confirm — e.g. a service guessed from the port number because `-sV` was not used. | When a scan lacked `-sV` and you want best-effort guesses. |
| `--keyword-search` | For products with no known CPE mapping, fall back to searching NVD by keyword. Returns anything whose text mentions the words — lots of unrelated CVEs. | Last resort for an unusual product. Expect noise. |
| `--no-verify-cpe` | Turn off the local double-check that a returned CVE actually lists the matched product. | Debugging only. Leave it on. |

### Turning features off

| Flag | What it does | When to use it |
|---|---|---|
| `--no-rules` | Skip the non-CVE weakness detection entirely (weak crypto, SMB signing, anonymous access, …). | If you only care about CVE matches. |
| `--no-exposure` | Keep the script-based weakness rules but drop the ones raised purely because a service is reachable (e.g. "a database is exposed"). | To cut down "reachability" noise on a big internal range. |
| `--no-playbook` | Leave the per-port enumeration playbook out of the report (and skip its CSV). | If you only want findings, not next-step guidance. |

### Filtering and pass/fail (useful in CI)

| Flag | What it does | When to use it |
|---|---|---|
| `--min-cvss N` | Drop CVE findings scoring below `N` (0–10). Does **not** affect non-CVE weaknesses, which have no score. | Focus on serious CVEs, e.g. `--min-cvss 7.0`. |
| `--fail-on LEVEL` | Make the program exit with code `2` if any finding **or** weakness is at or above `LEVEL` (`low`, `medium`, `high`, or `critical`). | In automation/CI, to fail a build when something serious is present: `--fail-on critical`. |

### The cache

Lookups are cached so repeat runs are fast and free.

| Flag | What it does | When to use it |
|---|---|---|
| `--cache PATH` | Where to store the cache database. Default: `~/.cache/nmapvuln/cve-cache.sqlite`. | To put the cache somewhere specific. |
| `--cache-ttl SECS` | How long cached results stay valid, in seconds. Default: `604800` (7 days). | To refresh more or less often. |
| `--no-cache` | Do not read or write the cache at all. | To force completely fresh lookups. |

### Input and logging

| Flag | What it does | When to use it |
|---|---|---|
| `--no-recurse` | When you pass a folder, do **not** look in sub-folders. | If a folder has nested scans you want to ignore. |
| `-v`, `--verbose` | Print every database query and extra detail while running. | To see what it is doing, or to debug. |
| `--version` | Print the version and exit. | — |
| `-h`, `--help` | Print the full option list and exit. | Any time. |

### Exit codes (for scripts)

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | No nmap output files were found in what you pointed it at. |
| `2` | The `--fail-on` threshold was met, **or** you used the options wrong. |

### Copy-paste examples

```bash
# Simplest run: one scan file, report into ./report
python nmapvuln.py target.xml -o report

# A whole folder of scans, with a free API key for speed
python nmapvuln.py scans/ -o report --nvd-key "$NVD_API_KEY"

# No internet — use only what nmap already found
python nmapvuln.py target.xml -o report --offline

# CI gate: only serious CVEs, fail the build if anything critical exists
python nmapvuln.py scans/ --min-cvss 7.0 --fail-on critical

# Shortest "fix these first" list — only actively-exploited CVEs
python nmapvuln.py scans/ -o report --kev-only

# Show everything, including the items hidden by default
python nmapvuln.py scans/ -o report --include-backported --include-tentative --include-unversioned
```

---

## Understanding the report

Open `report.html` and use the tabs across the top:

| Tab | What's in it |
|---|---|
| **Overview** | The headline counts, whether the scan is trustworthy, the list of scan files, and a **Suggested next scan** (ready-made nmap commands built from what was found). |
| **CVE Findings** | Known CVEs for the detected services. Filter by severity/confidence/text, export to CSV, and **click a port to jump to how to enumerate it**. |
| **Weaknesses** | Problems with no CVE: weak TLS/SSH, missing SMB signing, anonymous access, expired certificates, cleartext services. These come from what the scan *observed*, so they are usually the most reliable findings. |
| **Enumeration** | For each open port, the exact commands to run next to confirm a finding, with the host and port already filled in. Every command has a **copy** button. |
| **Service KB** | A deep per-service knowledge base (what to try, what to expect) for 33 services. Services you found are expanded first; the rest are searchable below. |
| **Network Attacks** | Network-wide techniques (LLMNR poisoning, mitm6, VLAN hopping, …). A "Relevant to this scan" group at the top shows which ones your scan gives evidence for, and why. |
| **Per-host** | Everything about one host — its ports, CVEs, weaknesses and leads — in one place. |
| **Inventory** | Every host and open port found, with an **Export CSV** button. |

Two ideas that make the report trustworthy:

- **Nothing is silently hidden.** When a filter removes rows (e.g. likely
  backported CVEs), the report shows a *"Withheld"* note with the exact count and
  the flag that brings them back. A short report never looks the same as a clean
  target.
- **Findings are ranked by real-world risk**, not just CVSS. A CVE in CISA's
  exploited catalog sorts to the top and is tagged `KEV`; each row also shows its
  EPSS score (the probability it will be exploited in the next 30 days).

---

## The output files

All written into your `-o` folder:

| File | What it is |
|---|---|
| `report.html` | The main report (the tabs above). Self-contained, open in any browser. |
| `report.md` | The whole report as Markdown — paste into notes or a ticket. |
| `report.json` | The same data as JSON — feed it to other tools or scripts. |
| `report-findings.csv` | One row per host/port/CVE (with KEV flag, EPSS, CISA due date). |
| `report-weaknesses.csv` | One row per non-CVE weakness, with evidence and a fix. |
| `report-validation.csv` | One row per scan-quality issue. |
| `report-enumeration.csv` | One row per enumeration step, commands filled in. (Skipped with `--no-playbook`.) |

---

## Getting a free NVD API key

Without a key, the public CVE database limits you to 5 requests every 30 seconds
(slow but it works). A free key raises that to 50 — about 10× faster.

1. Go to <https://nvd.nist.gov/developers/request-an-api-key>.
2. Fill in the short form; the key is emailed to you instantly.
3. Use it one of two ways:

```bash
# Pass it on the command line
python nmapvuln.py scans/ --nvd-key YOUR-KEY-HERE

# …or set it once in your shell so you don't repeat it
export NVD_API_KEY=YOUR-KEY-HERE        # macOS/Linux
setx NVD_API_KEY YOUR-KEY-HERE          # Windows (new terminals)
python nmapvuln.py scans/
```

Results are cached for a week, so repeat runs over the same services cost nothing
either way.

---

## Troubleshooting

**"No nmap output files found (.xml, .nmap, .gnmap)."**
You pointed nmapvuln at something with no scan files in it. Make sure you ran
nmap with `-oA` (or `-oX`) first, and that you are passing the right file or
folder. Remember: nmapvuln reads nmap's output — it does not scan.

**The report has very few findings.**
Check the **Overview** tab first. If it shows warnings like `NO_VERSION_DETECTION`
or `ALL_FILTERED`, the thin result is the scan's fault, not a clean target. Re-run
nmap with `-sV -sC`. Also check the *"Withheld"* note — some rows may be hidden by
default (bring them back with `--include-*` flags).

**It is slow / it pauses.**
That is the anonymous NVD rate limit. Get a [free API key](#getting-a-free-nvd-api-key),
or run with `--offline` for a quick first pass.

**`python: command not found` (Windows).**
Use `py` instead: `py nmapvuln.py target.xml -o report`.

**I see a CVE I think is wrong.**
Likely a backported fix (the vendor patched without changing the version string).
nmapvuln hides these by default; `--include-backported` shows them. Treat all CVE
matches as **leads to verify**, not proof — see below.

---

## How it stays accurate

The goal is precision: a finding you have to disprove wastes more time than it
saves. Three kinds of weak match are **hidden by default** (and counted, with the
flag to show them):

- **Backported fixes** — distributions patch CVEs without changing the version
  string, so `OpenSSH 8.2p1 Ubuntu…` would otherwise match every 8.2 CVE while
  being vulnerable to none. (`--include-backported`)
- **Keyword matches** — for products with no CPE mapping, a keyword search returns
  dozens of unrelated CVEs. Those products are listed as "unassessed" instead.
  (`--keyword-search`)
- **Unconfirmable weaknesses** — a service guessed from the port number (no
  `-sV`) is a guess, not an observation, so weaknesses resting on it are held
  back. (`--include-tentative`)

Everything kept is double-checked: each CVE is re-read locally to confirm it
really lists the matched product, and structured scripts are parsed into real
values (so, for example, a certificate's expiry date is compared to the scan
date rather than matching the words "not valid after", which every healthy
certificate also prints).

**Match confidence** on each CVE row:

| Confidence | Meaning |
|---|---|
| **high** | nmap gave a CPE with a version; NVD did exact version-range matching |
| **medium** | version known, but the CPE was synthesised or keyword-matched |
| **low** | product known but no version — "has had CVEs", not "is vulnerable" (hidden unless `--include-unversioned`) |

**Weakness confidence:** `confirmed` (the scan saw it), `firm` (parsed from
structured output), or `tentative` (a guess; hidden by default).

---

## What it checks for

**CVE correlation** matches detected services against the NVD database (and
optionally Vulners), then ranks by CISA KEV and EPSS.

**Non-CVE weakness rules** cover, among others:

| Area | Examples |
|---|---|
| **TLS** | weak/export/anonymous Diffie-Hellman, SSLv2/SSLv3, TLS 1.0/1.1, NULL/RC4/3DES/export ciphers, expired or self-signed certs, MD5/SHA-1 signatures, undersized keys, Heartbleed, CCS injection |
| **SSH** | weak key exchange/MAC/cipher, DSA host keys, undersized host keys, SSHv1 |
| **SMB** | signing not required, SMBv1, guest/anonymous access |
| **Services** | anonymous FTP, open DNS recursion, default SNMP community, NFS exports, risky HTTP methods, exposed `.git`/backups, LDAP anonymous bind, RDP without NLA, VNC without auth, unauthenticated MongoDB/Redis/Elasticsearch, empty-password MySQL |
| **Exposure** | cleartext protocols and internal datastores reachable on the scanned interface |

**Scan validation** flags problems with the scan itself so you don't mistake a
bad scan for a clean target: incomplete scans, no version detection, all-filtered
hosts, aggressive timing, the same host disagreeing between two scans, and more.

---

## Knowledge base & enumeration playbook

The report includes reference material to help you act on findings:

- **Enumeration playbook** — per open port, the standard commands to confirm a
  finding, with host and port filled in.
- **Service KB** — a deep per-service knowledge bank organised by phase
  (enumeration → exploitation). Each service merges two sources: a curated
  spreadsheet bank, and commands extracted from **HackTricks** (clearly labelled
  and attributed). Services found in your scan are expanded first with the host
  filled in; the rest are searchable, with Expand-all / Collapse-all.
- **Network Attacks** — network-wide techniques, with a scan-aware "Relevant to
  this scan" group that explains *why* each one applies to your target.

> [!NOTE]
> The HackTricks commands come from
> [HackTricks](https://github.com/carlospolop/hacktricks) by Carlos Polop,
> licensed **CC BY-NC 4.0**. That licence is **non-commercial** — see
> [CREDITS.md](CREDITS.md) for the attribution and what it means for using this
> tool commercially.

> [!WARNING]
> This material is **methodology reference**. The tool never runs any of it —
> it only prints the checklist. Everything in the playbook is *enumeration*
> (reading what a service exposes), not exploitation. **Only run these commands
> against systems you are authorised to test.**

---

## Running the tests

```bash
python tests/test_nmapvuln.py
```

153 tests covering the parsers, CVE matching, the weakness rules, the knowledge
banks, the exports, and one regression test for every false positive the tool has
ever produced. No test touches the network. Test fixtures live in `samples/` and
can be rebuilt with `python tests/make_samples.py`.

---

## Project layout

```
nmap-vuln/
├── nmapvuln.py            # run this
├── nmapvuln/              # the package
│   ├── cli.py             # command-line handling
│   ├── parsers.py         # read nmap .xml / .nmap / .gnmap
│   ├── match.py           # service → CVE matching
│   ├── rules.py           # non-CVE weakness rules
│   ├── sources.py         # NVD, Vulners, CISA KEV, EPSS
│   ├── report.py          # the HTML/CSV/MD/JSON report
│   ├── playbook.py        # per-port enumeration steps
│   ├── knowledge.py       # loads the knowledge banks
│   └── data/              # bundled knowledge banks (JSON)
├── tools/                 # scripts to rebuild the knowledge banks
├── tests/                 # test suite + sample scans
└── README.md
```

---

## Authorisation & legal

nmapvuln only reads scan files you already have; it does not connect to or attack
anything. But scanning and testing networks you do not own or have **written
permission** to test is illegal in most places. Only scan and test systems you
own or are explicitly authorised to assess. You are responsible for how you use
this tool and anything in its knowledge base.

**Third-party content.** The "HackTricks commands" in the Service KB are from
HackTricks (Carlos Polop), licensed CC BY-NC 4.0 (non-commercial). See
[CREDITS.md](CREDITS.md) for attribution and the commercial-use caveat.
