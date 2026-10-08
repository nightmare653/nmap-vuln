# Credits & third-party content

## HackTricks

The per-service commands shown in the report's **Service KB** tab under the
heading *"HackTricks commands"* are derived from **HackTricks**:

> **HackTricks** by Carlos Polop — <https://github.com/carlospolop/hacktricks>
> Licensed under **Creative Commons Attribution-NonCommercial 4.0 International
> (CC BY-NC 4.0)** — <https://creativecommons.org/licenses/by-nc/4.0/>

Each entry links back to its source page, and the report credits HackTricks and
the licence inline. The content was adapted (promotional blocks removed, commands
extracted and grouped) for use in this tool; it has been modified from the
original.

> [!IMPORTANT]
> CC BY-NC 4.0 is a **NonCommercial** licence. This means the HackTricks-derived
> content — and therefore this tool while it bundles that content — may be used
> and shared for non-commercial purposes only. If you intend to use nmapvuln
> commercially (for example, selling it or using it as part of a paid product),
> you must remove the HackTricks-derived knowledge bank
> (`nmapvuln/data/hacktricks_kb.json`) first, or obtain separate permission from
> the HackTricks author. Everything else in this repository is unaffected.

The bundled file `nmapvuln/data/hacktricks_kb.json` is rebuilt from a local copy
of the HackTricks `network-services-pentesting` pages with
[`tools/build_hacktricks_kb.py`](tools/build_hacktricks_kb.py).

## Other data sources (looked up at runtime, not bundled)

- **NVD** (National Vulnerability Database) — CVE data, U.S. NIST, public domain.
- **CISA KEV** (Known Exploited Vulnerabilities) — U.S. CISA, public.
- **EPSS** (Exploit Prediction Scoring System) — FIRST.org.
- **Vulners** — optional, via the user's own API key.
