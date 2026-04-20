# CLAUDE.md — VulnMind

Guidance for Claude instances working on this repository.

## What this is

VulnMind is a Python CLI that ingests scanner output (nmap XML/text, nikto, Metasploit console logs) and produces structured findings with CVE matches, CVSS scores, priority ratings, remediation advice, and suggested follow-up commands. It runs offline by default and pulls live CVE data from NVD when `--deep` is passed.

- **Language:** Python 3.10+
- **CLI framework:** Click
- **Terminal UI:** Rich
- **PDF reports:** reportlab
- **HTTP:** requests (NVD + Groq AI enrichment)
- **Entry point:** `vulnmind.cli:cli` (see `setup.py`)

## Local development

Always use the project-local virtualenv — **never** install to system Python on this machine (Arch, externally-managed).

```bash
python -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -e .
./.venv/bin/vulnmind --version
```

If I ever catch myself about to run `pip install --break-system-packages`, stop and use the venv instead.

## Smoke tests

Fixtures in `tests/`:

```bash
./.venv/bin/vulnmind analyze tests/sample_nmap.xml --format json
./.venv/bin/vulnmind analyze tests/sample_nmap.txt --format json
./.venv/bin/vulnmind analyze tests/sample_nikto.txt --format json
./.venv/bin/vulnmind analyze tests/sample_metasploit.txt --format json
./.venv/bin/vulnmind analyze tests/sample_nmap.xml --deep --format json   # hits NVD
./.venv/bin/vulnmind analyze tests/sample_nmap.xml --report pdf --output /tmp/test.pdf
```

Expected baseline for `sample_nmap.xml --deep`:

| host:port | priority | cvss | cves |
|---|---|---|---|
| target.local:21 | critical | 9.8 | CVE-2011-2523 |
| target.local:22 | medium | 5.9 | CVE-2019-6111, CVE-2018-15473 |
| target.local:80 | critical | 9.8 | CVE-2021-41773, CVE-2021-42013 |
| target.local:445 | high | 8.8 | CVE-2017-0144 |
| target.local:3306 | medium | — | (none) |

If those numbers regress, something broke. The most common regression surfaces are (a) the matcher picking the wrong KB entry, or (b) the version extractor grabbing a port number.

## Architecture cheat-sheet

```
vulnmind/
├── cli.py               # Click entry point, orchestrates the pipeline
├── config.py            # ~/.vulnmind/config.json (API key, model override)
├── nvd.py               # NVD API 2.0 client (deep mode), per-CVE file cache
├── matcher.py           # Offline KB matcher — strong vs weak confidence
├── ai.py                # Groq enrichment (--enrich)
├── report.py            # reportlab PDF generator
├── knowledge/services.json  # offline CVE KB (22 services, ~70 entries)
└── parsers/
    ├── base.py          # BaseParser + Finding dataclass
    ├── nmap.py          # XML + text variants, attaches product/version to raw_evidence
    ├── nikto.py
    └── metasploit.py    # msfconsole logs, tracks active `use <module>` state
```

Pipeline: **parse → match (KB) → [optional NVD deep] → [optional AI enrich] → render (text/json/pdf)**.

## Design rules — non-obvious, easy to violate

1. **Never overwrite the parser's `description` with a KB description.** The parser built it from actual scan evidence; the KB is generic.
2. **Never merge KB CVEs on a weak (service-only) match.** That creates false-positive CVE IDs on every generic HTTP/SMB finding. Only strong matches (product detected + product matches KB entry) may merge CVEs, suggested commands, or Metasploit modules.
3. **Never pick a product-specific KB entry when the finding text does not mention that product.** The historical "TP-LINK cascade" bug: every HTTP finding without a detected product inherited the first product-specific KB entry (TP-LINK router CVEs). Fix lives in `matcher._find_best_match`.
4. **Version tokens must contain at least one dot.** `_VERSION_RE` in `matcher.py` deliberately requires `\d+(?:\.\d+)+` so `:21`, `1`, or `7601` don't masquerade as versions.
5. **Search for the version in a 200-char window *after* the matched product.** Prevents versions from a different port/service leaking in via the concatenated `title + description + raw_evidence` string.
6. **JSON output must bypass Rich.** Rich word-wraps long lines and injects ANSI that corrupts JSON. `cli.py` writes JSON via `sys.stdout.write(json.dumps(...))` directly.
7. **NVD fetches are silent on failure.** A missing CVE lookup must never crash the CLI — the offline KB already gave us something usable.
8. **Rate limit NVD.** Public limit is 5 req / 30 s. We sleep ≥6.5 s between calls and retry 429/5xx/timeout with exponential backoff.
9. **Priority only moves up, never down, via NVD.** `_lift_priority()` picks the higher of (current, NVD-derived).

## Git / release

- Remotes: `origin` → github.com:Sombra-1/vulnmind, `codeberg` → codeberg.org/sombra-1/vulnmind
- Branch: `main`
- **Never add `Co-Authored-By: Claude` to commit messages.** Commit as the user's configured git identity.
- Version bumps: edit both `vulnmind/__init__.py` and `setup.py`, and update the User-Agent string in `nvd.py`.

## Known limitations / roadmap

- No `--target` flag yet — v0.3.0 parses scanner output, it does not run nmap for you. Planned for v0.4.0.
- No unit tests under `tests/` beyond fixture files; parsers are exercised via CLI smoke tests only.
- KB is hand-curated; future work: pull version ranges from NVD's CPE data to auto-widen entries.
- Parsers still wanted: OpenVAS, Nuclei, Burp Suite, Nessus.
