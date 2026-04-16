# VulnMind

Security scan analyzer for pentesters. Parse nmap and nikto output, get structured findings with CVE matches, priority ratings, remediation advice, suggested commands, and Metasploit modules — instantly, offline, no setup required.

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

### Deep analysis — AI enrichment (free Groq API key)

```bash
# get a free key at console.groq.com
vulnmind config set-key gsk_...

# plain-English analysis + richer commands
vulnmind analyze scan.xml --enrich

# send more scanner evidence for better accuracy
vulnmind analyze scan.xml --enrich --deep
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

VulnMind auto-detects the format — no need to specify it.

---

## Features

- Parse nmap XML and text output, nikto output
- Offline CVE knowledge base — instant, no internet required
- 50+ service types detected (ssh, ftp, http, smb, rdp, mysql, redis, mongodb, elasticsearch, smtp, ldap, snmp, vnc, docker, kubernetes, jenkins, and more)
- Priority ratings with explanation — know *why* something is critical, not just *that* it is
- Remediation advice — concrete fix steps, not generic "patch your software"
- Suggested shell commands targeting your actual scan host
- Metasploit module paths
- False positive likelihood assessment
- Multi-file analysis with automatic deduplication
- PDF report generation (cover page, executive summary table, per-finding detail sections)
- JSON output for piping and CI integration
- CVSS score support (populated in `--deep` mode)

---

## All flags

```
vulnmind analyze <files> [OPTIONS]

  --enrich          AI analysis via Groq API (free tier)
  --deep            Send more evidence to the AI for richer output (requires --enrich)
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

Supported tools wanted: Metasploit, OpenVAS, Burp Suite, Nessus.

---

## Changelog

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
