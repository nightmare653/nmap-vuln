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
| `--no-rules` | skip non-CVE weakness detection entirely |
| `--no-exposure` | keep the script-based rules but drop weaknesses raised purely from a service being reachable |
| `--min-cvss N` | drop findings scoring below N |
| `--fail-on LEVEL` | exit 2 if any finding is at or above `low\|medium\|high\|critical` |
| `--cache PATH` | cache database (default `~/.cache/nmapvuln/cve-cache.sqlite`) |
| `--cache-ttl SECS` | cache lifetime, default 7 days |
| `--no-cache` | bypass the cache |
| `--no-recurse` | do not descend into subdirectories |
| `-v, --verbose` | log every API query |

Exit codes: `0` success, `1` no input files found, `2` `--fail-on` threshold met.

## Output

- `report.html` — the report: validation issues, CVE findings table, non-CVE
  weakness table (both with live severity/category/text filters), host and
  service inventory, limitations. Self-contained, no external resources, works
  in light and dark.
- `report-findings.csv` — one row per host/port/CVE.
- `report-weaknesses.csv` — one row per non-CVE weakness, with the evidence line
  and a remediation note.
- `report-validation.csv` — one row per scan-quality issue.

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

Sources are merged rather than ranked: when NVD and an NSE script both report a
CVE, the row shows `nse+nvd` and keeps NVD's score, vector and description
alongside the script's exploit flag.

## Non-CVE weakness rules

Rules are declarative and live in [`nmapvuln/rules.py`](nmapvuln/rules.py). Each
one matches a regex over a named NSE script's output, optionally gated by a
numeric check — so "DH modulus below 2048 bits" is expressed as a real
comparison rather than a list of literals. Adding a rule is a few lines in the
relevant table.

| Area | Rules |
|---|---|
| **TLS** | weak DH group (`< 2048`), export-grade DH (Logjam), anonymous DH, SSLv2 (DROWN), SSLv3 (POODLE), TLS 1.0/1.1, NULL cipher, export cipher (FREAK), RC4, 3DES (Sweet32), weak nmap cipher grade, expired cert, self-signed cert, MD5/SHA-1 signature, undersized key, Heartbleed, CCS injection |
| **SSH** | weak KEX (`group1-sha1`, `group-exchange-sha1`), weak MACs (`hmac-md5`, `hmac-sha1-96`, `umac-64`), CBC/arcfour/3DES ciphers, `ssh-dss` host key, undersized host key, SSHv1 |
| **SMB** | signing disabled or not required, SMBv1, guest/anonymous access |
| **Services** | anonymous FTP (and writable anonymous FTP), open DNS recursion, default SNMP community, NFS exports, HTTP PUT/DELETE, TRACE, open proxy, exposed `.git`, backup/config files, directory listing, LDAP anonymous bind, RDP without NLA, VNC without auth, unauthenticated MongoDB/Redis/Elasticsearch, empty-password MySQL |
| **Exposure** | cleartext protocols reachable (telnet, FTP, rlogin, rsh, finger, POP3/IMAP without TLS), datastores reachable (MySQL, MSSQL, PostgreSQL, MongoDB, Redis, memcached, Elasticsearch, Docker/Kubernetes API, …) |
| **Catch-all** | any NSE script declaring `State: VULNERABLE` that cites no CVE — suppressed when a specific rule already covered that script, so nothing is reported twice |

Host scripts (`hostscript`, where `smb-*` results live) are examined as well as
per-port scripts. Exposure rules skip ports nmap recorded as TLS-tunnelled, so
FTPS on 990 is not flagged as cleartext FTP.

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

60 tests covering the three parsers, truncation recovery, CPE construction,
version-string splitting, confidence assignment, source merging, validation and
the weakness rules. The `samples/` directory holds the fixtures they run
against — `sample-scripts.xml` in particular carries realistic NSE output for
the rule tests.

## Recommended scan for best coverage

```bash
nmap -sV -sC --script "vuln,ssl-enum-ciphers,ssl-dh-params,ssh2-enum-algos,smb-security-mode,smb-protocols" -p- -oA target
```

`-oA` writes all three formats; point nmapvuln at the directory and it will
prefer the XML automatically.
