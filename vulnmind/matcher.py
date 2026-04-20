"""
matcher.py — Offline knowledge base matcher.

Enriches Finding objects using a built-in database of known vulnerable
services, versions, and CVEs. No API, no internet, no AI — instant.

How it works:
  1. Takes a Finding with host, port, service, and description
  2. Looks up the service name in services.json
  3. Matches the product and version against known vulnerable entries
  4. Returns the Finding enriched with priority, CVEs, commands, modules

Matching logic — in decreasing order of confidence:
  STRONG  Exact product + exact version match      (high confidence)
  STRONG  Exact product + version-before match     (high confidence)
  MEDIUM  Exact product, no version constraint     (lower confidence)
  WEAK    Service fallback (no product constraint) (gated — only used when
          the finding has explicit CVE IDs that we're not overwriting)

Key accuracy rules:
  - Never pick a product-specific KB entry when the finding text does NOT
    mention that product. (Previous versions would fall through to TP-LINK
    for any HTTP finding.)
  - Never overwrite the parser's description with a KB description — the
    parser's description was built from the actual scan evidence.
  - Never add KB CVEs unless the KB product actually matched. Blindly
    merging CVEs from a fallback entry creates false-positive CVE IDs.

Version comparison:
  Versions like "2.4.49", "7.2p2", "2012.55" are normalised to numeric
  tuples for comparison. Non-numeric parts are stripped.
"""

import json
import re
from dataclasses import replace
from pathlib import Path

_KNOWLEDGE_FILE = Path(__file__).parent / "knowledge" / "services.json"
_knowledge: dict | None = None


def _load_knowledge() -> dict:
    global _knowledge
    if _knowledge is None:
        with open(_KNOWLEDGE_FILE) as f:
            _knowledge = json.load(f)
    return _knowledge


def match_finding(finding) -> object:
    """
    Enrich a Finding from the offline knowledge base.

    Returns an enriched copy of the finding, or the original if no match.
    """
    knowledge = _load_knowledge()

    service = (finding.service or "").lower().strip()
    if not service:
        return finding

    # Normalise service aliases
    service = _normalise_service(service)

    entries = knowledge.get(service)
    if not entries:
        return finding

    # Extract product and version from the finding description/title/evidence
    product, version = _extract_product_version(finding)

    # Find the best matching entry — returns (entry, confidence)
    # confidence is "strong" (product+version) or "weak" (product-only / service fallback)
    match_result = _find_best_match(entries, product, version)
    if not match_result:
        return finding

    match, confidence = match_result

    # CVE merging rules:
    #   - Strong match: merge KB CVEs with parser CVEs
    #   - Weak match (no product match): do NOT add KB CVEs — would be
    #     a false positive. Only use the entry for generic guidance.
    existing_cves = set(finding.cve_ids or [])
    if confidence == "strong":
        new_cves = set(match.get("cves", []))
        merged_cves = list(existing_cves | new_cves)
    else:
        merged_cves = list(existing_cves)

    # Build commands with host/port substituted in.
    # Only use KB commands on strong matches — weak matches would suggest
    # commands targeting the wrong product (e.g. TP-LINK hydra on Apache).
    host = finding.host
    port = str(finding.port) if finding.port else ""
    commands = []
    if confidence == "strong":
        commands = [
            cmd.replace("{host}", host).replace("{port}", port)
            for cmd in match.get("suggested_commands", [])
        ]

    # Metasploit modules — only on strong matches
    msf_modules = match.get("metasploit_modules", []) if confidence == "strong" else []

    # Priority — always use KB priority if present (even on weak match, because
    # it's service-level guidance like "any exposed SMB is risky")
    matched_priority = match.get("priority")

    # Priority reason — use KB's field if present, else build one
    kb_priority_reason = match.get("priority_reason")
    if not kb_priority_reason:
        if confidence == "strong" and merged_cves:
            kb_priority_reason = (
                f"Matched '{match.get('product')}' in offline KB — "
                f"associated with {len(match.get('cves', []))} known CVE(s)."
            )
        elif confidence == "strong":
            kb_priority_reason = f"Matched '{match.get('product')}' in offline KB."
        else:
            kb_priority_reason = (
                f"Service '{service}' exposed — general risk guidance from KB."
            )

    # Description — NEVER overwrite parser's description. Parser built it from
    # actual scan evidence. Only fill it if parser left it empty (rare).
    description = finding.description or match.get("description") or ""

    # Remediation — use KB if it has one
    remediation = finding.remediation or match.get("remediation")

    # False-positive assessment — strong match = low, weak match = medium
    fp_likelihood = finding.false_positive_likelihood
    if not fp_likelihood:
        fp_likelihood = "low" if confidence == "strong" else "medium"
    fp_reason = finding.false_positive_reason
    if not fp_reason:
        if confidence == "strong":
            fp_reason = "Matched product and/or version against known vulnerable entry."
        else:
            fp_reason = "Service-level match only — specific product/version not confirmed."

    return replace(
        finding,
        priority=finding.priority or matched_priority,
        priority_reason=finding.priority_reason or kb_priority_reason,
        cve_ids=merged_cves,
        description=description,
        suggested_commands=finding.suggested_commands or commands,
        metasploit_modules=finding.metasploit_modules or msf_modules,
        false_positive_likelihood=fp_likelihood,
        false_positive_reason=fp_reason,
        remediation=remediation,
    )


def match_findings(findings: list) -> list:
    """Enrich a list of findings from the knowledge base."""
    return [match_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_service(service: str) -> str:
    """Map service name variations to the key used in services.json."""
    aliases = {
        # SSH
        "ssh":              "ssh",
        "ssh-hostkey":      "ssh",
        # FTP
        "ftp":              "ftp",
        "ftp-data":         "ftp",
        "ftps":             "ftp",
        "sftp":             "ftp",
        # HTTP / HTTPS
        "http":             "http",
        "http-proxy":       "http",
        "https":            "http",
        "ssl/http":         "http",
        "http-alt":         "http",
        "https-alt":        "http",
        "http-mgmt":        "http",
        "ssl/https":        "http",
        "http?":            "http",
        # UPnP / SSDP
        "upnp":             "upnp",
        "ssdp":             "upnp",
        # SMB / NetBIOS / Samba
        "microsoft-ds":     "microsoft-ds",
        "netbios-ssn":      "microsoft-ds",
        "smb":              "microsoft-ds",
        "samba":            "microsoft-ds",
        "netbios-ns":       "microsoft-ds",
        "cifs":             "microsoft-ds",
        # DNS
        "domain":           "domain",
        "dns":              "domain",
        "mdns":             "domain",
        # Telnet
        "telnet":           "telnet",
        # RDP
        "ms-wbt-server":    "rdp",
        "rdp":              "rdp",
        # Databases
        "mysql":            "mysql",
        "mariadb":          "mysql",
        "redis":            "redis",
        "mongodb":          "mongodb",
        "mongod":           "mongodb",
        "mongodb-internal": "mongodb",
        "postgresql":       "postgresql",
        "postgres":         "postgresql",
        "ms-sql-s":         "mssql",
        "ms-sql-m":         "mssql",
        "mssql":            "mssql",
        "oracle":           "oracle",
        "oracle-tns":       "oracle",
        "cassandra":        "cassandra",
        "cql":              "cassandra",
        "elasticsearch":    "elasticsearch",
        "memcached":        "memcached",
        # Application servers
        "tomcat":           "tomcat",
        "http-tomcat":      "tomcat",
        "ajp13":            "tomcat",
        "weblogic":         "weblogic",
        "jboss":            "jboss",
        "jboss-remoting":   "jboss",
        "docker":           "docker",
        # SMTP / Mail
        "smtp":             "smtp",
        "smtps":             "smtp",
        "smtp-submission":  "smtp",
        "submission":       "smtp",
        # IMAP / POP3
        "imap":             "imap",
        "imaps":            "imap",
        "pop3":             "pop3",
        "pop3s":            "pop3",
        # SNMP
        "snmp":             "snmp",
        # LDAP
        "ldap":             "ldap",
        "ldaps":            "ldap",
        "msrpc":            "rpc",
        # VNC
        "vnc":              "vnc",
        "rfb":              "vnc",
        "vnc-http":         "vnc",
        # NFS / RPC
        "nfs":              "nfs",
        "sunrpc":           "rpc",
        "rpcbind":          "rpc",
        # Kubernetes / CI
        "kubernetes":       "kubernetes",
        "jenkins":          "jenkins",
        "kafka":            "kafka",
        "rabbitmq":         "rabbitmq",
        "amqp":             "rabbitmq",
        "zookeeper":        "zookeeper",
    }
    return aliases.get(service, service)


# Product detection patterns — ordered: specific before generic
_PRODUCT_PATTERNS = [
    # SSH
    (r"dropbear",               "dropbear"),
    (r"openssh",                "openssh"),
    # FTP
    (r"vsftpd",                 "vsftpd"),
    (r"proftpd",                "proftpd"),
    (r"pure-ftpd",              "pure-ftpd"),
    (r"filezilla\s+server",     "filezilla"),
    # HTTP servers
    (r"apache\s+httpd",         "apache"),
    (r"apache\s+http",          "apache"),
    (r"apache(?=/\d)",          "apache"),
    (r"\bapache\b",             "apache"),
    (r"nginx",                  "nginx"),
    (r"microsoft.iis",          "iis"),
    (r"\biis\b",                "iis"),
    (r"lighttpd",               "lighttpd"),
    (r"caddy",                  "caddy"),
    # Application servers
    (r"apache\s+tomcat",        "tomcat"),
    (r"tomcat",                 "tomcat"),
    (r"weblogic",               "weblogic"),
    (r"jboss",                  "jboss"),
    (r"wildfly",                "jboss"),
    (r"glassfish",              "glassfish"),
    (r"jetty",                  "jetty"),
    # CMS / frameworks
    (r"wordpress",              "wordpress"),
    (r"wp[\s/-]",               "wordpress"),
    (r"drupal",                 "drupal"),
    (r"joomla",                 "joomla"),
    (r"struts",                 "struts"),
    (r"spring\s+boot",          "spring"),
    (r"laravel",                "laravel"),
    (r"django",                 "django"),
    # Databases
    (r"mysql",                  "mysql"),
    (r"mariadb",                "mysql"),
    (r"postgresql",             "postgresql"),
    (r"microsoft\s+sql\s+server", "mssql"),
    (r"mssql",                  "mssql"),
    (r"redis",                  "redis"),
    (r"mongodb",                "mongodb"),
    (r"oracle",                 "oracle"),
    (r"cassandra",              "cassandra"),
    (r"elasticsearch",          "elasticsearch"),
    (r"memcached",              "memcached"),
    # Network devices
    (r"tp.?link",               "tp-link"),
    (r"cisco\s+ios",            "cisco"),
    (r"cisco",                  "cisco"),
    (r"juniper",                "juniper"),
    (r"fortinet",               "fortinet"),
    (r"palo\s+alto",            "palo-alto"),
    (r"netgear",                "netgear"),
    (r"ubiquiti",               "ubiquiti"),
    # UPnP / SSDP
    (r"portable sdk.*upnp",     "portable sdk for upnp"),
    (r"miniupnp",               "miniupnp"),
    # Samba / SMB
    (r"samba",                  "samba"),
    # Windows OS indicators (for SMB findings)
    (r"windows\s+7",            "windows 7"),
    (r"windows\s+xp",           "windows xp"),
    (r"windows\s+server\s+2003", "windows server 2003"),
    (r"windows\s+server\s+2008", "windows server 2008"),
    # Docker / Kubernetes
    (r"docker",                 "docker"),
    (r"kubernetes",             "kubernetes"),
    # Mail
    (r"postfix",                "postfix"),
    (r"exim",                   "exim"),
    (r"sendmail",               "sendmail"),
    (r"dovecot",                "dovecot"),
    # CI / DevOps
    (r"jenkins",                "jenkins"),
    (r"gitlab",                 "gitlab"),
    # Other
    (r"openssl",                "openssl"),
    (r"php",                    "php"),
    (r"python",                 "python"),
    (r"ruby",                   "ruby"),
    (r"node",                   "nodejs"),
    (r"vnc",                    "vnc"),
]

# Precompile for performance
_PRODUCT_PATTERNS_COMPILED = [
    (re.compile(pat, re.IGNORECASE), name) for pat, name in _PRODUCT_PATTERNS
]

# Version pattern — numeric with at least one dot, or a "p<N>" suffix
_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+)+(?:p\d+)?(?:[-_]\w+)?)\b")


def _extract_product_version(finding) -> tuple:
    """
    Extract product name and version string from a finding.

    Looks in: title, description, raw_evidence
    Returns: (product_str, version_str) — both lowercase, may be empty string

    Version extraction:
      Only matches tokens with at least one dot (e.g. "2.4.49", "7.2p2") to
      avoid mistaking port numbers or counts for versions. Searches AFTER
      the product match when a product is identified.
    """
    text = " ".join([
        finding.title or "",
        finding.description or "",
        finding.raw_evidence or "",
    ]).lower()

    product = ""
    product_end = 0

    for regex, name in _PRODUCT_PATTERNS_COMPILED:
        m = regex.search(text)
        if m:
            product = name
            product_end = m.end()
            break

    # Version extraction — search AFTER the product match
    version = ""
    if product:
        # Search a reasonable window after the product name
        window = text[product_end:product_end + 200]
        version_match = _VERSION_RE.search(window)
        if version_match:
            version = version_match.group(1)
    else:
        # No product detected — still try to find a version token anywhere
        # (helpful for CVE-only findings like "CVE-2021-41773")
        version_match = _VERSION_RE.search(text)
        if version_match:
            version = version_match.group(1)

    return product, version


def _find_best_match(entries: list, product: str, version: str):
    """
    Find the best matching entry from the knowledge base.

    Returns: (entry_dict, confidence_str) or None
      confidence is "strong" (product matched) or "weak" (service fallback only)

    Match priority:
      1. STRONG: product match + exact version match
      2. STRONG: product match + version-before match
      3. STRONG: product match + no version constraint on entry
      4. WEAK:   service fallback (entry with no product constraint)

    Critical rule: we NEVER return a product-specific entry for a different
    product just because product/version didn't match. That was the TP-LINK bug.
    """
    product = (product or "").lower()

    fallback = None  # entry with no product constraint
    best_product_match = None  # any entry whose product matches ours
    best_version_match = None  # same, but with a matching version

    for entry in entries:
        entry_product = (entry.get("product") or "").lower()
        version_match = entry.get("version_match")
        version_before = entry.get("version_before")

        # Entry with no product constraint — eligible as fallback
        if not entry_product:
            if fallback is None:
                fallback = entry
            continue

        # Entry has a product constraint. Does it match ours?
        if not product:
            # We couldn't detect a product — cannot pick a product-specific entry.
            continue

        product_ok = (
            entry_product in product
            or product in entry_product
            or _product_equivalent(product, entry_product)
        )
        if not product_ok:
            continue

        # Product matches. Now check version constraints.

        # 1. Exact version prefix match — highest confidence
        if version_match and version and version.startswith(version_match):
            return (entry, "strong")

        # 2. Version-before match
        if version_before and version and _version_less_than(version, version_before):
            if best_version_match is None:
                best_version_match = entry
            continue

        # 3. Product matched, no version constraint on entry
        if not version_match and not version_before:
            if best_product_match is None:
                best_product_match = entry

    # Prefer: version-match > product-match > service fallback
    if best_version_match:
        return (best_version_match, "strong")
    if best_product_match:
        return (best_product_match, "strong")
    if fallback:
        return (fallback, "weak")
    return None


def _product_equivalent(p1: str, p2: str) -> bool:
    """Return True if two product names refer to the same thing."""
    equivalents = [
        {"apache", "apache httpd", "apache http server"},
        {"mysql", "mariadb"},
        {"openssh", "ssh"},
        {"mssql", "microsoft sql server"},
    ]
    for group in equivalents:
        if p1 in group and p2 in group:
            return True
    return False


def _version_less_than(v1: str, v2: str) -> bool:
    """
    Return True if version v1 is less than v2.

    Handles versions like: "7.2p2", "2012.55", "2.4.49", "1.6.19"
    Non-numeric parts (like 'p2') are stripped for comparison.
    """
    def normalise(v: str) -> tuple:
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts)

    try:
        return normalise(v1) < normalise(v2)
    except (ValueError, TypeError):
        return False
