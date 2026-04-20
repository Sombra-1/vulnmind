# VulnMind

Security scan analyzer for pentesters. Parse nmap, nikto, and Metasploit console output into structured findings with CVE matches, live CVSS scores from NVD, priority ratings, remediation advice, suggested commands, and Metasploit modules — instantly, mostly offline, no API keys required by default.

```
vulnmind analyze scan.xml
```

```
VulnMind BASIC  ·  1 critical  2 high  2 medium  0 low  (5 total)

  CRITICAL  http-vuln-cve2021-41773 on 192.168.1.10:80
  Target: 192.168.1.10:80  [http]
  CVEs:   CVE-2021-41773, CVE-2021-42013
  Why critical: Matched offline KB entry for 'apache' — known vulnerable service with 2 associated CVE(s).

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

```bash
pip install vulnmind
```

Or from source:

```bash
git clone https://github.com/sombra-1/vulnmind
cd vulnmind
pip install -e .
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
vulnmind analyze scan.xml nikto.txt
```

### Deep mode — live CVE lookups from NVD

```bash
# fetch official CVSS scores and authoritative CVE descriptions from nvd.nist.gov
vulnmind analyze scan.xml --deep
```

`--deep` pulls each CVE from the NVD API 2.0, populates `cvss_score`, and can **lift a finding's priority** if the highest associated CVSS is more severe than the offline KB suggested. Results are cached for 30 days at `~/.vulnmind/cache/nvd/`. No API key required.

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

---

## Supported formats

| Tool | Format | Flag |
|---|---|---|
| nmap | XML | `-oX scan.xml` |
| nmap | Text | `-oN scan.txt` |
| nmap | All formats | `-oA scan` |
| nikto | Text | `-o scan.txt` |
| Metasploit | Console log | `spool console.log` inside msfconsole |

VulnMind auto-detects the format — no need to specify it.

---

## Features

- Parse **nmap** XML and text output, **nikto** output, **Metasploit** console logs
- Offline CVE knowledge base — instant, no internet required
- **Live NVD lookups** in `--deep` mode — official CVSS scores and descriptions from nvd.nist.gov
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

---

## All flags

```
vulnmind analyze <files> [OPTIONS]

  --deep            Live CVE lookup against the NVD API (populates cvss_score, may lift priority)
  --enrich          AI analysis via Groq API (free tier)
  --report pdf      Generate a PDF report
  --output PATH     Output filename for the PDF (default: vulnmind_report.pdf)
  --format text|json  Output format (default: text)

vulnmind config set-key <key>   Save your Groq API key
vulnmind config show            Show current config
vulnmind config clear           Remove all saved config
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

Supported tools wanted: OpenVAS, Burp Suite, Nessus, Nuclei.

---

## Changelog

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
