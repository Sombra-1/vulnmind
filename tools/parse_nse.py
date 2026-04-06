"""
tools/parse_nse.py — Extract knowledge base entries from nmap NSE vuln scripts.

Reads every .nse script in /usr/share/nmap/scripts/ that has the "vuln"
category, extracts CVE IDs, descriptions, service targets, and usage examples,
then writes them to tools/staging/nse_extracted.json in the services.json format.

Run once:
    python3 tools/parse_nse.py

Output: tools/staging/nse_extracted.json
Then run: python3 tools/merge_kb.py  to merge into services.json
"""

import json
import re
import sys
from pathlib import Path

NSE_DIR   = Path("/usr/share/nmap/scripts")
OUT_FILE  = Path(__file__).parent / "staging" / "nse_extracted.json"

# ---------------------------------------------------------------------------
# Service mapping — script name prefix / portrule keyword -> service key
# ---------------------------------------------------------------------------

# Maps patterns found in script filenames or content -> services.json key
SERVICE_PATTERNS = [
    (r"^smb",                  "microsoft-ds"),
    (r"^samba",                "microsoft-ds"),
    (r"^ms-sql|^mssql",       "mssql"),
    (r"^mysql",                "mysql"),
    (r"^ftp",                  "ftp"),
    (r"^ssh",                  "ssh"),
    (r"^smtp|^exim",           "smtp"),
    (r"^pop3",                 "pop3"),
    (r"^imap",                 "imap"),
    (r"^rdp|^ms-rdp",         "rdp"),
    (r"^vnc",                  "vnc"),
    (r"^snmp",                 "snmp"),
    (r"^ldap",                 "ldap"),
    (r"^afp",                  "afp"),
    (r"^nfs",                  "nfs"),
    (r"^rpc|^msrpc",           "rpc"),
    (r"^ssl|^tls|^https",      "ssl"),
    (r"^http",                 "http"),
    (r"^upnp",                 "upnp"),
    (r"^oracle",               "oracle"),
    (r"^postgres",             "postgresql"),
    (r"^redis",                "redis"),
    (r"^mongo",                "mongodb"),
    (r"^telnet",               "telnet"),
    (r"^ajp",                  "ajp"),
    (r"^cups",                 "cups"),
    (r"^distcc",               "distcc"),
    (r"^realvnc",              "vnc"),
]

# Fallback: look for these strings inside script content to guess service
CONTENT_SERVICE_HINTS = [
    (r'shortport\.http\b',             "http"),
    (r'shortport\.ssl\b',              "ssl"),
    (r'shortport\.portnumber\(21',     "ftp"),
    (r'shortport\.portnumber\(22',     "ssh"),
    (r'shortport\.portnumber\(25',     "smtp"),
    (r'shortport\.portnumber\(110',    "pop3"),
    (r'shortport\.portnumber\(143',    "imap"),
    (r'shortport\.portnumber\(445',    "microsoft-ds"),
    (r'shortport\.portnumber\(1433',   "mssql"),
    (r'shortport\.portnumber\(1521',   "oracle"),
    (r'shortport\.portnumber\(3306',   "mysql"),
    (r'shortport\.portnumber\(3389',   "rdp"),
    (r'shortport\.portnumber\(5432',   "postgresql"),
    (r'shortport\.portnumber\(5900',   "vnc"),
    (r'shortport\.portnumber\(6379',   "redis"),
    (r'shortport\.portnumber\(27017',  "mongodb"),
    (r'require\s+"smb"',               "microsoft-ds"),
    (r'require\s+"mysql"',             "mysql"),
    (r'require\s+"ftp"',               "ftp"),
    (r'require\s+"ssh',                "ssh"),
]

# Metasploit module hints — look for msf module paths mentioned in scripts
MSF_PATTERN = re.compile(
    r'metasploit[- ]framework/blob/master/modules/([^\s\'"]+\.rb)',
    re.IGNORECASE
)

# Risk factor -> priority mapping
RISK_PRIORITY = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_service(script_name: str, content: str) -> str:
    """Detect which service this script targets."""
    name = script_name.lower()

    # Try filename prefix first
    for pattern, service in SERVICE_PATTERNS:
        if re.match(pattern, name):
            return service

    # Try content hints
    for pattern, service in CONTENT_SERVICE_HINTS:
        if re.search(pattern, content):
            return service

    return "unknown"


def extract_cves(content: str) -> list:
    """Extract all CVE IDs from script content."""
    cves = re.findall(r'CVE[:\-](\d{4}[:\-]\d{4,7})', content, re.IGNORECASE)
    # Normalise to CVE-YYYY-NNNN format
    normalised = []
    for cve in cves:
        cve = cve.replace(":", "-")
        normalised.append(f"CVE-{cve}")
    # Deduplicate preserving order
    seen = set()
    result = []
    for c in normalised:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def extract_description(content: str) -> str:
    """
    Extract the description block from an NSE script.
    NSE descriptions are wrapped in [[ ]] or " ".
    """
    # Try [[ ... ]] multiline format first
    m = re.search(r'description\s*=\s*\[\[(.*?)\]\]', content, re.DOTALL)
    if m:
        desc = m.group(1).strip()
        # Clean up: collapse whitespace, remove @usage/@output sections
        desc = re.sub(r'\n\s*\n', ' ', desc)
        desc = re.sub(r'\s+', ' ', desc)
        # Take only the first 2 sentences (150-250 chars)
        sentences = re.split(r'(?<=[.!?])\s+', desc)
        short = " ".join(sentences[:2]).strip()
        return short[:300] if short else desc[:300]

    # Try single-line string format
    m = re.search(r'description\s*=\s*"([^"]+)"', content)
    if m:
        return m.group(1).strip()[:300]

    return ""


def extract_priority(content: str, cves: list) -> str:
    """Determine priority from Risk factor field or CVE presence."""
    m = re.search(r'Risk\s+factor\s*:\s*(\w+)', content, re.IGNORECASE)
    if m:
        risk = m.group(1).lower()
        if risk in RISK_PRIORITY:
            return RISK_PRIORITY[risk]

    # Fallback: scripts with CVEs default to high
    if cves:
        return "high"
    return "medium"


def extract_usage_command(script_name: str, content: str) -> list:
    """Extract the @usage example line from the script."""
    # Look for @usage lines
    usages = re.findall(r'@usage\s*\n--\s*(nmap[^\n]+)', content)
    commands = []
    for usage in usages[:2]:  # max 2 commands
        # Replace concrete IPs/hostnames with {host} placeholder
        cmd = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '{host}', usage)
        cmd = re.sub(r'\b(?:target|TARGET|<target>|TARGET_IP)\b', '{host}', cmd)
        cmd = cmd.strip()
        # Only keep commands that reference a host (skip broadcast/local scripts)
        if cmd and '{host}' in cmd and 'broadcast' not in cmd.lower():
            commands.append(cmd)

    # Always add the generic script invocation as a fallback
    # Detect the likely port from the script name
    port_hint = _guess_port(script_name)
    generic = f"nmap --script {script_name} -p {port_hint} {{host}}"
    if generic not in commands:
        commands.append(generic)

    return commands[:2]


def extract_msf_modules(content: str) -> list:
    """Extract Metasploit module paths mentioned in the script."""
    matches = MSF_PATTERN.findall(content)
    modules = []
    for m in matches:
        # Convert file path to module path: remove .rb, convert / to /
        mod = m.replace(".rb", "").strip("/")
        if mod not in modules:
            modules.append(mod)
    return modules[:2]


def extract_product_version(content: str, cves: list) -> tuple:
    """
    Try to extract product name and version constraint from the description.
    Returns (product, version_match, version_before).
    """
    product = None
    version_match = None
    version_before = None

    # Patterns like "versions < 7.32", "before 2.4.50", "prior to 1.3.6"
    m = re.search(
        r'(?:versions?\s*(?:before|prior to|<|up to)\s*)([\d\.]+)',
        content, re.IGNORECASE
    )
    if m:
        version_before = m.group(1)

    # Exact version: "version 2.3.4"
    m = re.search(r'version\s+([\d\.]+)\b', content, re.IGNORECASE)
    if m and not version_before:
        version_match = m.group(1)

    # Common product names
    product_map = [
        (r'\bDrupal\b',          "drupal"),
        (r'\bWordPress\b',       "wordpress"),
        (r'\bJoomla\b',          "joomla"),
        (r'\bApache\b',          "apache"),
        (r'\bnginx\b',           "nginx"),
        (r'\bOpenSSH\b',         "openssh"),
        (r'\bvsftpd\b',          "vsftpd"),
        (r'\bProFTPD\b',         "proftpd"),
        (r'\bSamba\b',           "samba"),
        (r'\bOpenSSL\b',         "openssl"),
        (r'\bMicrosoft\b.*\bSMB\b', "microsoft"),
        (r'\bElasticSearch\b',   "elasticsearch"),
        (r'\bStruts\b',          "struts"),
        (r'\bJBoss\b',           "jboss"),
        (r'\bWebLogic\b',        "weblogic"),
        (r'\bCisco\b',           "cisco"),
        (r'\bHuawei\b',          "huawei"),
        (r'\bVMware\b',          "vmware"),
        (r'\bphpMyAdmin\b',      "phpmyadmin"),
        (r'\bMongoDB\b',         "mongodb"),
        (r'\bRedis\b',           "redis"),
        (r'\bPostgreSQL\b',      "postgresql"),
        (r'\bMySQL\b',           "mysql"),
        (r'\bOracle\b',          "oracle"),
        (r'\bExim\b',            "exim"),
        (r'\bPostfix\b',         "postfix"),
        (r'\bSendmail\b',        "sendmail"),
        (r'\bTomcat\b',          "tomcat"),
        (r'\bJetty\b',           "jetty"),
        (r'\bIIS\b',             "iis"),
        (r'\bRealVNC\b',         "realvnc"),
        (r'\bNetBIOS\b',         "netbios"),
        (r'\bSNMP\b',            "snmp"),
    ]
    for pattern, name in product_map:
        if re.search(pattern, content, re.IGNORECASE):
            product = name
            break

    return product, version_match, version_before


def _guess_port(script_name: str) -> str:
    """Guess the likely port number from the script name."""
    port_map = {
        "smb": "445", "ftp": "21", "ssh": "22", "smtp": "25",
        "http": "80,443,8080", "ssl": "443", "mysql": "3306",
        "mssql": "1433", "rdp": "3389", "vnc": "5900",
        "oracle": "1521", "postgres": "5432", "snmp": "161",
        "ldap": "389", "telnet": "23", "redis": "6379",
        "mongodb": "27017", "upnp": "1900", "afp": "548",
        "nfs": "2049", "distcc": "3632", "ajp": "8009",
    }
    name = script_name.lower()
    for prefix, port in port_map.items():
        if name.startswith(prefix):
            return port
    return "0"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_all_scripts() -> dict:
    """Parse all vuln NSE scripts and return a services.json-format dict."""
    result = {}
    skipped = []
    processed = 0

    nse_files = sorted(NSE_DIR.glob("*.nse"))
    print(f"Found {len(nse_files)} NSE scripts total")

    for nse_path in nse_files:
        content = nse_path.read_text(encoding="utf-8", errors="replace")

        # Only process scripts with the "vuln" category
        if '"vuln"' not in content and "'vuln'" not in content:
            continue

        script_name = nse_path.stem  # filename without .nse

        # Extract data
        cves        = extract_cves(content)
        description = extract_description(content)
        priority    = extract_priority(content, cves)
        commands    = extract_usage_command(script_name, content)
        msf_modules = extract_msf_modules(content)
        service     = detect_service(script_name, content)
        product, version_match, version_before = extract_product_version(content, cves)

        # Skip if no useful data
        if not cves and not description:
            skipped.append(script_name)
            continue

        # Skip if description too short to be useful
        if len(description) < 30:
            skipped.append(script_name)
            continue

        entry = {
            "product":         product,
            "version_match":   version_match,
            "version_before":  version_before,
            "priority":        priority,
            "cves":            cves,
            "description":     description,
            "suggested_commands": commands,
            "metasploit_modules": msf_modules,
            "_source":         f"nse:{script_name}",  # tracking field, stripped at merge
        }

        if service not in result:
            result[service] = []
        result[service].append(entry)
        processed += 1

    print(f"Processed:  {processed} scripts")
    print(f"Skipped:    {len(skipped)} scripts (no CVEs + no description)")
    print(f"Services:   {len(result)}")
    print(f"Entries:    {sum(len(v) for v in result.values())}")

    if skipped:
        print(f"\nSkipped scripts:")
        for s in skipped:
            print(f"  - {s}")

    return result


if __name__ == "__main__":
    if not NSE_DIR.exists():
        print(f"ERROR: nmap scripts not found at {NSE_DIR}")
        print("Install nmap: sudo apt install nmap")
        sys.exit(1)

    print(f"Parsing NSE scripts from {NSE_DIR} ...\n")
    data = parse_all_scripts()

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nWritten to: {OUT_FILE}")
    print("\nNext step: python3 tools/merge_kb.py")
