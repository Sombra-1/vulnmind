# VulnMind

![VulnMind — turn scanner output into prioritized, explainable security findings](docs/assets/vulnmind-banner.png)

[![CI](https://github.com/Sombra-1/vulnmind/actions/workflows/ci.yml/badge.svg)](https://github.com/Sombra-1/vulnmind/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Security scan analyzer for pentesters. Parse nmap, Nuclei, nikto, and Metasploit console output into structured findings with explicit match confidence, CVE/CVSS context, CISA Known Exploited Vulnerabilities (KEV), public ExploitDB references, remediation advice, suggested commands, and Metasploit modules. Finding analysis is offline by default and requires no API key; normal text output may separately check GitHub Releases for an update.

VulnMind is not a scanner replacement. It turns scanner output into prioritized, explainable findings you can review, pipe to JSON, or export as a PDF report.

![VulnMind analyzing sanitized local scanner output](docs/assets/vulnmind-demo.gif)

![Watch the VulnMind technical demo](docs/assets/video-thumbnail.png)

The full-resolution video stays out of normal Git history. See the
[reproducible demo package](tools/demo/README.md) to render and verify it.

```
vulnmind analyze scan.xml --deep
```

```
VulnMind BASIC  ·  1 critical  2 high  2 medium  0 low  (5 total)

  CRITICAL  http-vuln-cve2021-41773 on 192.168.1.10:80
  Target: 192.168.1.10:80  [http]
  Confidence: Scanner Reported
  CVEs:   CVE-2021-41773
  Threat intel: Known Exploited CVE — CISA KEV · Public Exploit Reference · Metasploit Module
  Why critical: Apache 2.4.49 path-traversal / RCE — trivially exploitable and widely weaponised.

  Apache 2.4.49 has a path traversal and remote code execution
  vulnerability. Widely exploited in the wild.

  Next steps:
    $ curl -s --path-as-is http://192.168.1.10/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd
    $ curl -s --path-as-is http://192.168.1.10/icons/.%2e/%2e%2e/%2e%2e/etc/passwd

  Metasploit:
    msf > use exploit/multi/http/apache_normalize_path_rce

  MEDIUM  Open port 22/tcp — OpenSSH 7.2p2
  Target: 192.168.1.10:22  [ssh]
  CVEs:   CVE-2018-15473, CVE-2019-6111
  Why medium: Matched offline KB entry for 'openssh' — known vulnerable service with 2 associated CVE(s).
  ...
```

---

## Install

The recommended install uses pipx, which keeps VulnMind in an isolated environment:

```bash
pipx install "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.1.tar.gz"
```

Or use pip inside a virtual environment:

```bash
python -m venv .venv
./.venv/bin/python -m pip install "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.1.tar.gz"
```

VulnMind is currently distributed through GitHub Releases rather than PyPI.

Or from source:

```bash
git clone https://github.com/sombra-1/vulnmind
cd vulnmind
python -m venv .venv
./.venv/bin/python -m pip install -e .
```

**Supported distros:** Kali Linux, Ubuntu, Arch Linux, Parrot OS, BlackArch

**Requirements:** Python 3.10+

---

## Usage

### Basic — no setup required

```bash
# nmap scan
nmap -sV -sC -oX scan.xml 192.168.1.0/24
vulnmind analyze scan.xml

# nikto scan
nikto -h 192.168.1.10 -o nikto.txt
vulnmind analyze nikto.txt

# multiple files at once
vulnmind analyze scan.xml nuclei.jsonl nikto.txt
```

### Nuclei JSONL *(new in v0.5.0)*

```bash
nuclei -u https://target.local -jsonl -o nuclei.jsonl
vulnmind analyze nuclei.jsonl
```

### Scan — let VulnMind run nmap for you *(new in v0.4.0)*

```bash
# scan + analyze in one step (defaults: -sV -sC --top-ports 1000)
vulnmind scan 192.168.1.1

# CIDR range with NVD enrichment
vulnmind scan 10.0.0.0/24 --deep

# custom ports + pass-through nmap flags
vulnmind scan target.local -p 22,80,443 --nmap-args "-T4 -Pn"
```

Requires the `nmap` binary on PATH. VulnMind prints an authorisation notice
before every scan — only run against systems you own or have permission to test.

### Deep mode — NVD + exploit intelligence

```bash
# refresh NVD CVSS data, CISA KEV, and ExploitDB references
vulnmind analyze scan.xml --deep
```

`--deep` pulls each CVE from the NVD API 2.0, populates `cvss_score`, and can **lift a finding's priority** when the official CVSS is more severe than the offline KB suggested. It also refreshes the official CISA KEV catalog and ExploitDB CVE index. NVD results are cached for 30 days; CISA KEV for 24 hours; and ExploitDB for seven days under `~/.vulnmind/cache/`.

Exploit signals are deliberately annotation-only. A public exploit reference or Metasploit module does not prove that the scanned target is vulnerable and never raises priority by itself. `actively_exploited: true` is emitted only for an exact CVE match in CISA KEV.

### AI enrichment (free Groq API key)

```bash
# get a free key at console.groq.com
vulnmind config set-key gsk_...

# plain-English analysis + richer commands
vulnmind analyze scan.xml --enrich

# combine deep NVD lookup with AI enrichment for maximum signal
vulnmind analyze scan.xml --deep --enrich
```

`--enrich` adds AI explanations, remediation steps, more specific commands, and false positive assessment.

### PDF report

```bash
vulnmind analyze scan.xml --report pdf
vulnmind analyze scan.xml --enrich --report pdf --output pentest_report.pdf
```

### Machine-readable output

```bash
vulnmind analyze scan.xml --format json > findings.json
```

Exploit-intelligence fields are always present with stable types, even when no cache or network data is available:

| Field | Type | Meaning |
|---|---|---|
| `confidence` | string | `confirmed`, `scanner-reported`, `strong`, or `weak` |
| `actively_exploited` | boolean | An associated CVE is in the official CISA KEV catalog |
| `exploit_available` | boolean | ExploitDB has an exact associated-CVE reference |
| `metasploit_available` | boolean | A Metasploit module is associated with the finding |
| `exploit_confidence` | string | Best source: `cisa-kev`, `metasploit-module`, `exploitdb-cve`, or `none` |
| `exploit_references` | array of strings | At most five supporting source URLs or module IDs |

### Updates

Normal text-mode runs make a short GitHub Releases check at most once per day and show a notice when a newer version exists. The check overlaps analysis and waits no more than a brief bounded grace period at the end. JSON mode never checks. Disable or re-enable automatic checks with `vulnmind config set-update-checks off|on`, or set `VULNMIND_UPDATE_CHECKS=off`. To check or update explicitly:

```bash
vulnmind update --check-only
vulnmind update
```

Pip and pipx installations update from the exact SemVer release tag returned by GitHub. Source checkouts and system-package installations are not modified automatically; the command prints safe, installation-specific instructions instead.

#### Verify release downloads

For a checksum-verified installation, download the wheel, source distribution, and `SHA256SUMS` from the [v0.6.1 release](https://github.com/Sombra-1/vulnmind/releases/tag/v0.6.1) into an empty directory. With the GitHub CLI:

```bash
gh release download v0.6.1 --repo Sombra-1/vulnmind --pattern 'vulnmind-*' --pattern SHA256SUMS
sha256sum --check SHA256SUMS
# Continue only if both files report OK. Install into your existing virtualenv:
python -m pip install ./vulnmind-0.6.1-py3-none-any.whl
```

On macOS, use `shasum -a 256 --check SHA256SUMS`. Checksums apply to the attached wheel and source distribution, not GitHub's automatically generated source archives. They detect damaged or changed downloads; they are not signatures or independent publisher verification. The `vulnmind update` command installs a tag archive and does not verify these asset checksums.

#### Manual rollback

To return a pipx installation to v0.6.0:

```bash
pipx install --force "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.0.tar.gz"
vulnmind --version
```

For a virtualenv installation, run its `python -m pip install --force-reinstall "vulnmind @ https://github.com/Sombra-1/vulnmind/archive/refs/tags/v0.6.0.tar.gz"`, then its `vulnmind --version`. Keep any custom `PIPX_HOME` setting when using pipx. For source checkouts, preserve local work and check out the desired tag in a separate worktree; use your package manager's downgrade procedure for system packages. Config and caches remain under `~/.vulnmind`; v0.6.1 adds no config or finding-schema migration.

---

## Supported formats

| Tool | Format | Flag |
|---|---|---|
| nmap | XML | `-oX scan.xml` |
| nmap | Text | `-oN scan.txt` |
| nmap | All formats | `-oA scan` |
| Nuclei | JSONL | `-jsonl -o nuclei.jsonl` |
| nikto | Text | `-o scan.txt` |
| Metasploit | Console log | `spool console.log` inside msfconsole |

VulnMind auto-detects the format — no need to specify it.

---

## Verified media

![Standard terminal analysis](docs/assets/terminal-analysis.png)

![Confidence, CVE, KEV, exploit-reference, remediation, and module context](docs/assets/deep-intelligence.png)

![Generated PDF report preview](docs/assets/pdf-report-preview.png)

The screenshots above are generated from committed, sanitized loopback
fixtures and the real CLI output.

```bash
tools/demo/prepare_demo.sh
tools/demo/render_assets.sh
tools/demo/verify_media.sh
```

---

## Features

- Parse **nmap** XML and text output, **Nuclei** JSONL, **nikto** output, **Metasploit** console logs
- Offline CVE knowledge base — instant, no internet required
- **Live NVD lookups** in `--deep` mode — official CVSS scores from nvd.nist.gov
- **CISA KEV intelligence** — distinguishes CVEs known to be exploited in the wild
- **ExploitDB references** — exact-CVE public exploit availability, kept separate from KEV
- Explicit evidence confidence: confirmed, scanner-reported, strong product/version match, or weak service guidance
- Trust scanner-reported CVEs from Nuclei classification metadata without inventing CVEs from template names
- 50+ service types detected (ssh, ftp, http, smb, rdp, mysql, redis, mongodb, elasticsearch, smtp, ldap, snmp, vnc, docker, kubernetes, jenkins, and more)
- Accurate product & version matching — strong vs weak match confidence, no more false-positive CVE merges from unrelated vendors
- Priority ratings with explanation — know *why* something is critical, not just *that* it is
- Remediation advice — concrete fix steps, not generic "patch your software"
- Suggested shell commands targeting your actual scan host
- Metasploit module paths + active module tracking in msfconsole logs
- False positive likelihood assessment
- Multi-file analysis with automatic deduplication
- PDF report generation (cover page, executive summary table, per-finding detail sections)
- JSON output for piping and CI integration
- Bounded GitHub release notices and an explicit `vulnmind update` command

---

## All flags

```
vulnmind analyze <files> [OPTIONS]

  --deep            Refresh NVD, CISA KEV, and ExploitDB intelligence
  --enrich          AI analysis via Groq API (free tier)
  --report pdf      Generate a PDF report
  --output PATH     Output filename for the PDF (default: vulnmind_report.pdf)
  --format text|json  Output format (default: text)

vulnmind scan <target> [OPTIONS]          # new in v0.4.0 — runs nmap for you

  -p, --ports       Port spec passed to nmap (e.g. '22,80,443'); disables --top-ports
  --nmap-args STR   Extra flags forwarded to nmap, shell-quoted (e.g. "-T4 -Pn")
  --deep / --enrich / --report / --output / --format   (same as analyze)

vulnmind config set-key <key>   Save your Groq API key
vulnmind config set-update-checks off|on
vulnmind config show            Show current config
vulnmind config clear           Remove all saved config

vulnmind update [--check-only]  Check/install the latest GitHub release
```

---

## Adding a parser

1. Create `vulnmind/parsers/yourparser.py`, subclass `BaseParser`
2. Implement `can_parse()` and `parse()`
3. Register in `vulnmind/parsers/__init__.py`

```python
class MyParser(BaseParser):
    def can_parse(self, file_path, content_preview):
        return "MyTool v" in content_preview

    def parse(self, file_path, content):
        # return List[Finding]
        ...
```

Supported tools wanted: OpenVAS, Burp Suite, Nessus.

---

## Development

Run the test suite from a project-local virtualenv:

```bash
python -m venv .venv
./.venv/bin/pip install -e .
./.venv/bin/pip install -r dev-requirements.txt
./.venv/bin/python -m pytest
```

The GitHub Actions workflow runs the same suite on Python 3.10, 3.11, and 3.12,
then builds and installs the wheel in a fresh virtualenv outside the checkout.
It checks all five sample formats, JSON fields, bundled KB access, and PDF output.
Tag pushes also test installation directly from the exact published GitHub tag
archive on Python 3.10. The smoke checks can be repeated with
`/path/to/fresh/venv/bin/python tools/check_installed.py tests --version 0.6.1`.

## Planned updates

- **Next hardening patch:** automate bundled Metasploit module validation against Rapid7 metadata; add cache-health diagnostics and interrupted-write coverage; exercise custom pipx homes and assess signed release attestations.
- **v0.7.0 candidates:** Nessus input, SARIF/HTML reports, and conservative cross-tool deduplication that retains each scanner's evidence.
- **Later:** scan comparisons, engagement policy files, and broader CPE-based matching with explicit accuracy tests.

These are priorities for evaluation, not committed release dates. Matching accuracy, offline behavior, and stable JSON remain the release gates.

---

## Changelog

### v0.6.1
- **Parser fixes** — Nikto multi-target reports retain the correct host/port and exclude target metadata from findings; invalid ports no longer leak through. Nuclei format detection accepts Go-style keys, leading malformed records within the preview, and UTF-8 BOMs.
- **Config resilience** — owner-only atomic saves preserve the previous config if replacement fails; invalid file encoding falls back to defaults, and non-string secret values remain masked in config display.
- **IPv6 accuracy** — canonical IPv6 parsing and finding IDs across nmap, Nuclei, and Metasploit; bracketed host/port rendering in terminal, PDF, and AI status output; invalid Metasploit ports rejected.
- **Scan cleanup** — nmap launch failures, including permission errors, remove temporary XML and produce the normal scanner error.
- **Release verification** — documented asset checksum verification and manual rollback; fresh installed-wheel smoke checks across Python 3.10/3.11/3.12 and a published-tag installation check on Python 3.10.
- **Regression coverage** — 174 tests, including reproductions for the parser, config, and scanner fixes. No finding JSON schema changes.

### v0.6.0
- **Exploit intelligence** — exact-CVE lookups against the official CISA KEV catalog and ExploitDB CSV, with offline-first caches, stale-cache fallback, bounded downloads, and silent network failure handling.
- **Explicit confidence model** — every finding reports `confirmed`, `scanner-reported`, `strong`, or `weak` evidence confidence.
- **Stable JSON signals** — added `actively_exploited`, `exploit_available`, `metasploit_available`, `exploit_confidence`, and bounded `exploit_references` fields with stable types.
- **Careful risk wording** — CISA KEV, public exploit references, and Metasploit modules render as separate terminal/PDF signals; exploit availability alone never raises priority.
- **Safe updates** — release checks are bounded and optional, failed checks back off for 24 hours, SemVer prereleases compare correctly, and `vulnmind update` installs exact GitHub tag archives for pip/pipx while protecting source/system-package installs.
- **Bug fixes** — fixed cross-file deduplication, ignored explicit nmap `NOT VULNERABLE` results, kept JSON clean during enrichment/errors, validated optional-enrichment field types, and prevented unsupported weak KB fallbacks from inflating priority.
- **Expanded regression suite** — coverage for data-source caches/parsing/download limits, integration policy, updater safety, JSON schema, PDF rendering, and parser/matcher regressions.

### v0.5.0
- **Nuclei JSONL support** — parses Nuclei findings from `-jsonl` output, including severity, host/port, matched URL, extracted results, reproduction curl command, CVSS score, and CVEs from `info.classification.cve-id`.
- **CVE accuracy guard** — Nuclei parser trusts explicit classification CVEs but does not invent CVEs from template IDs or names.
- **Matcher confidence polish** — scanner-reported CVEs that confirm a weak SMB KB fallback are treated as lower false-positive risk without merging unrelated fallback CVEs.
- **Test suite and CI foundation** — pytest coverage for matcher safeguards, nmap/nikto/Metasploit/Nuclei parser fixtures, mocked NVD cache/fetch/rate-limit behavior, and GitHub Actions on Python 3.10, 3.11, and 3.12.
- **Development docs** — added `dev-requirements.txt` and local pytest setup instructions for contributors.

### v0.4.1
- **Packaging fix** — `setup.py` declares `package_data` so the offline CVE knowledge base (`vulnmind/knowledge/services.json`) is bundled into built wheels.
- License metadata added: `license="MIT"` + MIT classifier.
- No behavioural changes versus v0.4.0.

### v0.4.0
- **`vulnmind scan <target>` subcommand** — runs nmap for you and feeds the XML straight into the existing analyze pipeline. Defaults to `-sV -sC --top-ports 1000`; accepts `-p/--ports` for custom port ranges and `--nmap-args "..."` for arbitrary pass-through flags (shell-quoted). Prints an authorisation notice on every text-mode run and streams nmap's progress to the terminal so you see the scan as it happens. Temp XML is cleaned up automatically. Fails loudly with install instructions if `nmap` is not on PATH.
- **Pipeline refactor** — `analyze` and `scan` now share a single internal pipeline function, so any future change to parse → match → NVD → AI → render applies to both paths.
- **Bug fixes** — empty-findings JSON output now bypasses Rich (consistent with the rest of JSON mode, avoids stray ANSI); removed a dead `picked_priority` variable in the NVD enrichment path.

### v0.3.0
- **Metasploit parser** — full implementation. Parses `spool` / piped msfconsole logs, tracks the active module across `use <module>` and `msf6 exploit(...) >` prompts, filters out progress noise and failed attempts, promotes `meterpreter session opened` / `login successful` to critical/high.
- **Live NVD enrichment (`--deep`)** — fetches each CVE from the NVD 2.0 API, populates `cvss_score`, and lifts priority when the NVD CVSS is higher than the offline KB's rating. Per-CVE cache with 30-day TTL. Rate-limit aware with retry + exponential backoff.
- **Matcher rewrite** — explicit strong-vs-weak match confidence. Never merges KB CVEs on weak (service-only) matches. Never picks a product-specific KB entry when the finding text does not mention that product — eliminates the "TP-LINK cascade" where every HTTP finding without a detected product inherited unrelated CVEs.
- **Accurate version extraction** — version tokens must contain at least one dot, and are searched in a 200-char window after the matched product name. No more port numbers (`:21`) misread as versions.
- **Knowledge base enrichment** — 33 entries now include a `priority_reason` and concrete `remediation` field. Coverage expanded for vsftpd, ProFTPD, Apache 2.4.49, IIS, Drupal, WordPress, Joomla 3.7, OpenSSH <8.0, Dropbear, EternalBlue, SambaCry, BlueKeep, Telnet, Tomcat, WebLogic, OpenSSL, Exim, MySQL, Redis, MongoDB, PostgreSQL, MSSQL, VNC.
- **NSE findings carry service context** — both XML and text nmap parsers attach `product:` / `version:` lines into `raw_evidence` so the matcher sees version info even when the NSE output line doesn't mention it.
- **Bug fixes** — JSON output no longer corrupted by Rich word-wrap; duplicate CVE IDs now deduped across nmap/nikto parsers; Apache regex no longer eats the first digit of the version.

### v0.2.1 (+ post-release)
- Update checker — notifies you when a new version is available (background thread, 24h cache, silent on no internet)

### v0.2.1 features
- 50+ service aliases and 40+ product patterns for better offline detection
- Smarter version extraction — no longer misreads port numbers as version strings
- Every finding now explains why its priority was assigned
- New `remediation` field — concrete fix steps in terminal output, PDF, and JSON
- Open port findings include product and version in evidence for accurate KB matching
- AI prompt improved: requires at least 2 commands and specific remediation steps
- AI `max_tokens` increased for richer output

### v0.2.0
- Upgraded AI model to `llama-3.3-70b-versatile`
- `--deep` flag wired up in CLI
- `--output PATH` for custom PDF filename
- `--format json` for machine-readable output
- `vulnmind config clear` subcommand
- PDF no longer requires `--enrich`

### v0.1.0
- Initial release

---

## License

MIT — free to use, modify, and distribute.

---

## Author

**sombra-1** — [github.com/Sombra-1](https://github.com/Sombra-1)
