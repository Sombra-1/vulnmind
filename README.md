# VulnMind

Security scan analyzer for pentesters. Parse nmap and nikto output, get structured findings with CVE matches, priority ratings, suggested commands, and Metasploit modules — instantly, offline, no setup required.

```
vulnmind analyze scan.xml
```

```
VulnMind  ·  1 critical  2 high  1 medium  1 low

  CRITICAL  smb-vuln-ms17-010 on 192.168.1.10:445
  Target: 192.168.1.10:445  [smb]
  CVEs:   CVE-2017-0144, CVE-2020-0796

  SMB service detected. Check for EternalBlue (MS17-010) and SMBGhost.
  These are among the most exploited vulnerabilities ever.

  Next steps:
    $ nmap --script smb-vuln-ms17-010 -p 445 192.168.1.10
    $ nmap --script smb-vuln-cve-2020-0796 -p 445 192.168.1.10

  Metasploit:
    msf > use exploit/windows/smb/ms17_010_eternalblue
    msf > use auxiliary/scanner/smb/smb_ms17_010
```

---

## Install

```bash
pip install vulnmind
```

Or from source:

```bash
git clone https://github.com/YOUR_USERNAME/vulnmind
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

### Deep analysis (requires free API key)

```bash
# get a free key at console.groq.com
vulnmind config set-key gsk_...

vulnmind analyze scan.xml --enrich
```

`--enrich` adds plain-English explanations, more specific commands, and false positive assessment.

### PDF report (Enrich)

```bash
vulnmind analyze scan.xml --enrich --report pdf
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

**Free (this repo)**
- Parse nmap XML and text output
- Parse nikto output
- Offline knowledge base — CVE matching, priority ratings, suggested commands
- Metasploit module suggestions
- Multi-file analysis with automatic deduplication
- Clean terminal output with Rich

**Enrich**
- Deep analysis via `--enrich` (plain-English explanations, false positive filtering)
- PDF report generation
- Priority support

Get a Enrich license at **vulnmind.io** (coming soon)

---

## Contributing

Pull requests welcome. The most useful contributions:

- New parsers (`vulnmind/parsers/`) — Metasploit, OpenVAS, Burp Suite, Nessus
- Knowledge base entries (`vulnmind/knowledge/services.json`) — more services, more CVEs
- Bug reports with sample scan files

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

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

---

## License

MIT — free to use, modify, and distribute.
