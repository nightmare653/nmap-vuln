# nmapvuln

Validates nmap scan output and correlates the detected services with known CVEs,
then writes a self-contained HTML report and CSVs.

It does three separate jobs, and keeps them separate in the report:

1. **Validation** — is the scan itself trustworthy? Did it finish? Was `-sV` used?
   Did every port come back filtered? Do two scans of the same host disagree?
   A thin vulnerability list caused by a bad scan looks identical to a clean
   target unless someone says so explicitly.
2. **CVE correlation** — which known CVEs affect the services that were
   identified, and how confident is each match.
3. **Non-CVE weaknesses** — weak Diffie-Hellman groups, RC4/3DES/export cipher
   suites, SSLv3, expired and self-signed certificates, weak SSH algorithms,
   SMB signing disabled, SMBv1, anonymous FTP, open DNS recursion, exposed
   datastores, cleartext protocols. None of this has a CVE, so none of it shows
   up in a CPE match — and in bug bounty work it is often the more directly
   reportable half.

The design goal is precision. A finding you have to disprove costs more time
than it saves, so anything the scan data cannot actually support is withheld and
counted rather than printed — see [Accuracy](#accuracy). Findings are then ranked
by whether the vulnerability is known to be exploited in the wild, not by CVSS
alone.

Pure stdlib, no dependencies, Python 3.9+.

## Usage

```bash
python nmapvuln.py scans/ -o report/
```

Takes `.xml`, `.nmap`, `.gnmap` (and `.gmap`) files or directories, in any mix.
Directories are searched recursively. Files with unknown extensions are sniffed
by content.

```bash
# with an NVD API key (10x the rate limit — free, strongly recommended)
python nmapvuln.py scans/ --nvd-key "$NVD_API_KEY"

# no network at all: report only CVEs the scan itself already found via NSE
python nmapvuln.py scans/ --offline

# only serious, and exit non-zero if anything critical is present (for CI)
python nmapvuln.py scans/ --min-cvss 7.0 --fail-on critical

# include services where no version was detected (noisy, low confidence)
python nmapvuln.py scans/ --include-unversioned

# only what is known to be exploited in the wild
python nmapvuln.py scans/ --kev-only

# show everything, including what is withheld by default
python nmapvuln.py scans/ --include-backported --include-tentative --keyword-search
```

### Options

| Flag | Meaning |
|---|---|
| `-o, --out DIR` | output directory (default `nmapvuln-report`) |
| `--name NAME` | base filename for the outputs (default `report`) |
| `--title TEXT` | report title |
| `--nvd-key KEY` | NVD API key, or set `NVD_API_KEY`. Raises the limit from 5 to 50 requests/30s |
| `--vulners-key KEY` | Vulners API key, or set `VULNERS_API_KEY`. Optional; adds exploit availability |
| `--offline` | no network; NSE-derived findings only |
| `--include-unversioned` | also match products with no detected version |
| `--include-backported` | include CVEs matched against a distribution-packaged banner |
| `--include-tentative` | include weaknesses the scan data could not confirm |
| `--keyword-search` | fall back to NVD keyword search for products with no CPE mapping |
| `--no-verify-cpe` | skip the local re-check of a CVE's own applicability data |
| `--kev-only` | report only CVEs in CISA's Known Exploited Vulnerabilities catalog |
| `--no-enrich` | skip the CISA KEV and EPSS lookups |
| `--no-rules` | skip non-CVE weakness detection entirely |
| `--no-exposure` | keep the script-based rules but drop weaknesses raised purely from a service being reachable |
| `--min-cvss N` | drop CVE findings scoring below N. Does not apply to non-CVE weaknesses, which carry no score |
| `--fail-on LEVEL` | exit 2 if any CVE finding **or** non-CVE weakness is at or above `low\|medium\|high\|critical` |
| `--cache PATH` | cache database (default `~/.cache/nmapvuln/cve-cache.sqlite`) |
| `--cache-ttl SECS` | cache lifetime, default 7 days |
| `--no-cache` | bypass the cache |
| `--no-recurse` | do not descend into subdirectories |
| `-v, --verbose` | log every API query |

Exit codes: `0` success, `1` no input files found, `2` `--fail-on` threshold met
(or a usage error, which argparse also reports as 2).

`--kev-only` needs the CISA catalog, so it overrides `--no-enrich` and is
rejected together with `--offline` rather than silently emptying the report.

## Output

- `report.html` — the report: validation issues, CVE findings table, non-CVE
  weakness table (both with live severity/category/text filters), host and
  service inventory, limitations. Self-contained, no external resources, works
  in light and dark.
- `report-findings.csv` — one row per host/port/CVE, with the KEV flag, the CISA
  remediation date, the EPSS probability and the backport suspicion.
- `report-weaknesses.csv` — one row per non-CVE weakness, with its confidence,
  the evidence line and a remediation note.
- `report-validation.csv` — one row per scan-quality issue.

Every row withheld by a default filter is counted in the report, under
*Withheld from the tables above*, with the flag that brings it back. A filtered
report and a clean target are otherwise indistinguishable.

## Accuracy

Three things are withheld by default, because each is wrong far more often than
it is right.

**Backported fixes.** Distributions patch vulnerabilities without changing the
advertised version, so an Ubuntu `OpenSSH 8.2p1` matches every CVE ever filed
against upstream 8.2 while being vulnerable to none of them. When the banner
names a distribution build (`8.2p1 Ubuntu 4ubuntu0.5`, `1.1.1f-1ubuntu2.16`,
`2.4.6-1.el7`), the CVE rows are withheld and counted. `--include-backported`
returns them.

**Keyword search.** With no CPE mapping for a product, the only option is an NVD
keyword query, which returns everything whose text mentions the words. That is
dozens of unrelated CVEs per port. Unmapped products are now listed as
unassessed instead, and `--keyword-search` restores the old behaviour.

**Unconfirmable weaknesses.** Without `-sV`, nmap names a service from the port
number alone, so "MySQL on 3306" is a guess about what is listening. Weaknesses
resting on a guess are graded `tentative` and withheld; `--include-tentative`
shows them.

Two checks run on everything that is kept. Each CVE returned by NVD is re-read
locally to confirm its own applicability data names the product that was matched
(`--no-verify-cpe` disables this), and every script with structured output is
parsed into values rather than pattern-matched, so a rule compares a certificate
date against the scan clock rather than looking for the phrase "not valid after"
— which nmap prints for healthy certificates too.

The measurable effect, on the two fixtures in `samples/`:

| Fixture | Before | After |
|---|---|---|
| `sample-healthy.xml` (nothing wrong with it) | 9 weaknesses, incl. 1 critical | 2, both plain reachability, graded low |
| `sample-scripts.xml` (genuinely broken) | 31 weaknesses | 31, same 30 rule ids |

## Ranking: what to look at first

A correct CVE list for an old Apache still runs to a hundred rows. Two free
sources, neither needing a key, decide the order:

- **CISA KEV** — the Known Exploited Vulnerabilities catalog. A CVE listed here
  has been observed in real attacks, which is a stronger signal than any score.
  KEV rows sort to the top of every table and carry CISA's remediation date.
  `--kev-only` drops everything else.
- **EPSS** (FIRST.org) — the probability a CVE will be exploited in the next 30
  days, shown as a percentage on each row.

Both are cached like every other lookup, and `--no-enrich` skips them.

## Match confidence

This is the part that decides whether the report is useful or noise:

| Confidence | How the match was made |
|---|---|
| **high** | nmap emitted a CPE including a version; NVD did the version-range matching |
| **medium** | version was probed, but the CPE was synthesised from a product-name map, or matched by keyword |
| **low** | product identified but no version — "this software has had CVEs", not "this host is vulnerable" |

Low-confidence matches are **excluded by default**; `--include-unversioned`
turns them on. On the sample data that flag takes the finding count from 152 to
1480, which is the entire reason it is off by default.

Findings parsed from `.nmap` and `.gnmap` are capped at medium, because those
formats carry no CPEs.

Non-CVE weaknesses carry their own, separate confidence:

| Confidence | Meaning |
|---|---|
| **confirmed** | the scan observed the condition, or the script said so outright |
| **firm** | derived from structured script output that was parsed, not pattern-matched |
| **tentative** | suggestive, but could be something else. Withheld by default |

Sources are merged rather than ranked: when NVD and an NSE script both report a
CVE, the row shows `nse+nvd` and keeps NVD's score, vector and description
alongside the script's exploit flag.

## Non-CVE weakness rules

Rules live in [`nmapvuln/rules.py`](nmapvuln/rules.py) and fire two ways.

**Analysers** handle every script with real structure. The script's output is
parsed into values by [`nmapvuln/scriptdata.py`](nmapvuln/scriptdata.py) and the
rule reasons over those: `ssl-cert` becomes a certificate with a key type, a bit
count and two dates; `ssh2-enum-algos` becomes four separate algorithm lists;
`ssl-enum-ciphers` becomes a set of protocol versions each with its own cipher
list. This is what stops a MAC name matching inside a cipher list, a `NULL`
compressor being read as a NULL cipher suite, and a 256-bit Ed25519 key being
called undersized against an RSA threshold.

**Pattern rules** cover scripts whose whole output is already a verdict, such as
`ftp-anon`'s "Anonymous FTP login allowed". These scan every match in the output,
not just the first, so a 1024-bit value listed after a 2048-bit one is still
found.

Adding a rule is an entry in `SPECS` plus either a table row or a few lines in an
analyser.

| Area | Rules |
|---|---|
| **TLS** | weak DH group (`< 2048`), export-grade DH (Logjam), anonymous DH, SSLv2 (DROWN), SSLv3 (POODLE), TLS 1.0/1.1, NULL cipher, export cipher (FREAK), RC4, 3DES (Sweet32), weak nmap cipher grade, expired cert, self-signed cert, MD5/SHA-1 signature, undersized key, Heartbleed, CCS injection |
| **SSH** | weak KEX (`group1-sha1`, `group-exchange-sha1`), weak MACs (`hmac-md5`, `hmac-sha1-96`, bare `umac-64`), CBC/arcfour ciphers, `ssh-dss` host key, undersized host key (per algorithm), SSHv1 |
| **SMB** | signing disabled or not required, SMBv1, guest/anonymous access |
| **Services** | anonymous FTP (and writable anonymous FTP), open DNS recursion, default SNMP community, NFS exports, HTTP PUT/DELETE, TRACE, open proxy, exposed `.git`, backup/config files, directory listing, LDAP anonymous bind, RDP without NLA, VNC without auth, unauthenticated MongoDB/Redis/Elasticsearch, empty-password MySQL |
| **Exposure** | cleartext protocols reachable (telnet, FTP, rlogin, rsh, finger, POP3/IMAP without TLS), datastores reachable (MySQL, MSSQL, PostgreSQL, MongoDB, Redis, memcached, Elasticsearch, Docker/Kubernetes API, …) |
| **Catch-all** | any NSE script declaring `State: VULNERABLE` that cites no CVE — suppressed when a specific rule already covered that script, so nothing is reported twice |

Host scripts (`hostscript`, where `smb-*` results live) are examined as well as
per-port scripts. Exposure rules skip ports nmap recorded as TLS-tunnelled, so
FTPS on 990 is not flagged as cleartext FTP, and they are graded `tentative` when
the service was guessed from the port number rather than probed.

Rules deliberately left conservative, because flagging them buries everything
else: `hmac-sha1` and `ssh-rsa` in SSH, `diffie-hellman-group14-sha1`, and a null
SMB session used only to read the security mode. Genuine guest access and
readable shares are still reported.

## Validation checks

Scan-level: `SCAN_INCOMPLETE`, `PARSE_ERROR`, `NO_VERSION_DETECTION`, `NO_NSE`,
`DEFAULT_PORT_RANGE`, `NO_UDP`, `AGGRESSIVE_TIMING`, `NO_RETRIES`, `PN_USED`,
`LOSSY_FORMAT`, `NO_HOSTS`, `NO_COMMAND_LINE`.

Host-level: `HOST_DOWN`, `HOST_UP_NO_OPEN`, `ALL_FILTERED`, `TCPWRAPPED`,
`NO_PRODUCT`, `NO_VERSION`, `LOW_CONFIDENCE_FINGERPRINT`.

Cross-file: `DUPLICATE_HOST`, `STATE_CONFLICT`, `VERSION_CONFLICT` — the same
host scanned twice with different results, which usually means filtering or
rate limiting interfered with one of the runs.

A truncated XML file (interrupted scan) is rewound to the last complete `<host>`
block and parsed anyway, with the truncation reported.

## Limitations

**CVE findings** come from **service banners**, so they are leads to verify, not
confirmed vulnerabilities. The dominant false positive is **backported patches**:
distributions fix CVEs without changing the advertised version string, so a
Debian `OpenSSH 7.4` may well be patched against everything listed against it.
Those rows are withheld by default now, but the detection is a heuristic over the
banner text: a distribution build whose banner says nothing about the
distribution still slips through, and `--include-backported` shows what was held
back. Neither direction is a substitute for asking the host what it has patched.

**Non-CVE weaknesses** do not share that problem — they come from what the scan
actually observed (negotiated ciphers, DH moduli, certificate fields, script
conclusions), so they do not depend on banner accuracy. Where a rule reads a
script's own verdict, it inherits that script's reliability.

Both kinds are limited by coverage: ports outside the scanned range and services
behind filtering are untested rather than proven safe, and a rule can only fire
if the script that feeds it was actually run — so scan with `-sV -sC` at minimum.
The tool only reads existing scan output; it never touches the target.

## Getting an NVD API key

Free, issued instantly: <https://nvd.nist.gov/developers/request-an-api-key>.
Without one you get 5 requests per 30 seconds, which is slow but works — results
are cached for a week, so repeat runs over the same services cost nothing.

## Tests

```bash
python tests/test_nmapvuln.py
```

111 tests covering the three parsers, truncation recovery, CPE construction,
version-string splitting, confidence assignment, source merging, validation, the
weakness rules, and one regression test per false positive the tool has produced.
No test touches the network.

The `samples/` directory holds the fixtures:

| Fixture | What it is for |
|---|---|
| `sample.xml`, `sample.gnmap`, `sample.nmap` | one host across all three formats, plus a filtered host and a truncation source |
| `sample-scripts.xml` | realistic NSE output for a genuinely broken host, exercising every rule |
| `sample-healthy.xml` | a well-configured host. Anything reported against it beyond plain reachability is a false positive, and a test asserts so |

Script output in the XML fixtures encodes newlines as `&#10;`, the way nmap does,
because a literal newline in an XML attribute is normalised to a space.

## Recommended scan for best coverage

```bash
nmap -sV -sC --script "vuln,ssl-enum-ciphers,ssl-dh-params,ssh2-enum-algos,smb-security-mode,smb-protocols" -p- -oA target
```

`-oA` writes all three formats; point nmapvuln at the directory and it will
prefer the XML automatically.
