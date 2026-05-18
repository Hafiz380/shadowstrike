"""
Security Bounty Hunter
=======================
Inspired by ECC's security-bounty-hunter skill. Focused on finding
exploitable, bounty-worthy vulnerabilities that qualify for real
security reports.

Bias toward remotely reachable, user-controlled attack paths.
Discard patterns that bounty platforms routinely reject.

In-Scope:
- SSRF through user-controlled URLs (CWE-918)
- Auth bypass in middleware/API guards (CWE-287)
- Remote deserialization/upload-to-RCE (CWE-502)
- SQL injection in reachable endpoints (CWE-89)
- Command injection in request handlers (CWE-78)
- Path traversal in file-serving paths (CWE-22)
- Auto-triggered XSS (CWE-79)

Out-of-Scope (usually rejected):
- Local-only pickle.loads with no remote path
- eval()/exec() in CLI-only tooling
- shell=True on hardcoded commands
- Missing security headers alone
- Self-XSS requiring victim paste
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class BountyPriority(str, Enum):
    """Priority ranking for bounty-worthy findings."""
    CRITICAL = "critical"  # Definitely reportable
    HIGH = "high"          # Likely reportable
    MEDIUM = "medium"      # Reportable with good narrative
    LOW = "low"            # Maybe reportable, needs strong PoC
    SKIP = "skip"          # Not bounty-worthy


@dataclass
class BountyFinding:
    """A bounty-worthy vulnerability finding."""
    title: str
    cwe_id: str
    severity: str
    priority: BountyPriority
    description: str
    file_path: str
    line_start: int
    line_end: int = 0
    evidence: str = ""
    exploitability: str = ""  # How exploitable is this?
    impact: str = ""          # What's the impact?
    attack_vector: str = ""   # How would an attacker reach this?
    poc_suggestion: str = ""  # Suggested PoC approach
    owasp_category: str = ""
    false_positive_likelihood: str = "low"
    bounty_platform_notes: str = ""
    tags: list[str] = field(default_factory=list)


# Patterns that are bounty-worthy
BOUNTY_PATTERNS = {
    "ssrf": {
        "patterns": [
            r"requests\.(get|post|put|delete|patch|head)\s*\(\s*(?!https?://(localhost|127\.0\.0\.1))",
            r"urllib\.request\.urlopen\s*\(",
            r"httpx\.(AsyncClient|Client)\.(get|post|put|delete)\s*\(",
            r"fetch\s*\(\s*[^)]*\+",
            r"axios\.(get|post|put|delete)\s*\(\s*[^)]*\+",
            r"curl_exec\s*\(",
            r"file_get_contents\s*\(\s*\$",
            r"HttpClient.*GetAsync\s*\(\s*[^)]*\+",
        ],
        "cwe": "CWE-918",
        "priority": BountyPriority.HIGH,
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "User-controlled URL passed to server-side HTTP request",
        "attack_vector": "Supply internal URLs (http://169.254.169.254, file://, gopher://)",
        "poc_suggestion": "Request http://169.254.169.254/latest/meta-data/ or internal service",
    },
    "sqli": {
        "patterns": [
            r"(execute|cursor\.execute|query)\s*\(\s*[\"'].*(%s|\?|:).*[\"'].*%",
            r"(execute|cursor\.execute|query)\s*\(\s*f[\"']",
            r"(execute|cursor\.execute|query)\s*\(\s*[\"'].*\+\s*",
            r"\.raw\s*\(\s*[\"'].*(%s|\?).*[\"'].*%",
            r"sequelize\.query\s*\(\s*[\"'].*\$\{",
            r"knex\.raw\s*\(\s*[\"'].*\$\{",
            r"pg\.query\s*\(\s*[\"'].*\$\{",
            r"\.queryRaw\s*\(\s*[\"'].*\$\{",
        ],
        "cwe": "CWE-89",
        "priority": BountyPriority.CRITICAL,
        "title": "SQL Injection",
        "description": "User input concatenated into SQL query without parameterization",
        "attack_vector": "Inject SQL via input parameters to extract/modify data",
        "poc_suggestion": "' OR 1=1 -- or UNION SELECT for data extraction",
    },
    "command_injection": {
        "patterns": [
            r"os\.system\s*\(\s*[^)]*\+",
            r"subprocess\.(run|call|Popen|check_output)\s*\(\s*[^)]*shell\s*=\s*True",
            r"exec\s*\(\s*[^)]*\+",
            r"eval\s*\(\s*[^)]*\+",
            r"child_process\.(exec|spawn)\s*\(\s*[^)]*\+",
            r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[^)]*\+",
            r"Process\.(Start|StartInfo)\s*\(\s*[^)]*\+",
            r"shell_exec\s*\(\s*\$",
            r"passthru\s*\(\s*\$",
            r"system\s*\(\s*\$",
        ],
        "cwe": "CWE-78",
        "priority": BountyPriority.CRITICAL,
        "title": "Command Injection",
        "description": "User input passed to OS command execution",
        "attack_vector": "Inject shell commands via input parameters",
        "poc_suggestion": "Append ; whoami or $(whoami) to test RCE",
    },
    "path_traversal": {
        "patterns": [
            r"open\s*\(\s*[^)]*\+",
            r"readFile\s*\(\s*[^)]*\+",
            r"fs\.(readFileSync|readFile|writeFileSync|writeFile)\s*\(\s*[^)]*\+",
            r"sendFile\s*\(\s*[^)]*\+",
            r"File\s*\(\s*[^)]*\+",
            r"Path\.join\s*\(\s*[^)]*req\.",
            r"path\.join\s*\(\s*[^)]*req\.",
            r"file_get_contents\s*\(\s*\$",
        ],
        "cwe": "CWE-22",
        "priority": BountyPriority.HIGH,
        "title": "Path Traversal",
        "description": "User input used in file path without sanitization",
        "attack_vector": "Use ../../../etc/passwd or similar traversal sequences",
        "poc_suggestion": "../../../../etc/passwd or ..\\..\\..\\windows\\system32\\config\\sam",
    },
    "xss": {
        "patterns": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"document\.writeln\s*\(",
            r"\.html\s*\(\s*[^)]*\+",
            r"dangerouslySetInnerHTML",
            r"v-html\s*=",
            r"eval\s*\(\s*[^)]*document\.",
            r"\$\([^)]*\)\.html\s*\(",
            r"out\.print\s*\(\s*[^)]*request\.",
            r"Response\.Write\s*\(\s*[^)]*Request\.",
        ],
        "cwe": "CWE-79",
        "priority": BountyPriority.HIGH,
        "title": "Cross-Site Scripting (XSS)",
        "description": "User-controlled data rendered in HTML without encoding",
        "attack_vector": "Inject JavaScript that executes in victim's browser",
        "poc_suggestion": "<script>alert(document.domain)</script> or event handlers",
    },
    "deserialization": {
        "patterns": [
            r"pickle\.loads?\s*\(",
            r"cPickle\.loads?\s*\(",
            r"yaml\.load\s*\(\s*[^)]*(?!Loader)",
            r"yaml\.unsafe_load\s*\(",
            r"marshal\.loads?\s*\(",
            r"shelve\.open\s*\(",
            r"ObjectInputStream\s*\(\s*new\s+ByteArrayInputStream",
            r"readObject\s*\(",
            r"JSON\.parse\s*\(\s*[^)]*req\.",
            r"XmlSerializer.*Deserialize\s*\(",
        ],
        "cwe": "CWE-502",
        "priority": BountyPriority.CRITICAL,
        "title": "Insecure Deserialization",
        "description": "Untrusted data deserialized without validation",
        "attack_vector": "Craft malicious serialized object for RCE",
        "poc_suggestion": "ysoserial payload or pickle RCE gadget chain",
    },
    "auth_bypass": {
        "patterns": [
            r"if\s+.*==\s*[\"']admin[\"']",
            r"password\s*==\s*[\"']",
            r"token\s*==\s*[\"']",
            r"jwt\.verify\s*\(\s*[^)]*algorithms\s*:\s*\[\s*[\"']none[\"']",
            r"verify\s*=\s*False",
            r"CERT_NONE",
            r"check_hostname\s*=\s*False",
            r"SSL_VERIFY\s*=\s*(false|0|no)",
        ],
        "cwe": "CWE-287",
        "priority": BountyPriority.HIGH,
        "title": "Authentication Bypass",
        "description": "Weak or bypassable authentication mechanism",
        "attack_vector": "Bypass auth via hardcoded creds, weak JWT, or missing validation",
        "poc_suggestion": "Try default creds, JWT none algorithm, or token manipulation",
    },
    "idor": {
        "patterns": [
            r"(GET|POST|PUT|DELETE)\s+.*/(\{id\}|:id|\$\{id\}|\$id)",
            r"findById\s*\(\s*req\.(params|query|body)\.",
            r"getOne\s*\(\s*req\.(params|query|body)\.",
            r"WHERE\s+id\s*=\s*\$",
            r"\.where\s*\(\s*[\"']id[\"']\s*,\s*req\.",
        ],
        "cwe": "CWE-639",
        "priority": BountyPriority.MEDIUM,
        "title": "Insecure Direct Object Reference (IDOR)",
        "description": "Access control not enforced on object-level operations",
        "attack_vector": "Change ID parameter to access other users' resources",
        "poc_suggestion": "Change /api/user/123 to /api/user/456 and check if data leaks",
    },
}

# Patterns to SKIP (not bounty-worthy)
SKIP_PATTERNS = [
    r"pickle\.loads?\s*\(\s*open\s*\(\s*[\"'][^\"']+[\"']\s*\)",  # Local file only
    r"eval\s*\(\s*input\s*\(\s*\)\s*\)",  # CLI-only
    r"exec\s*\(\s*input\s*\(\s*\)\s*\)",  # CLI-only
    r"shell=True.*subprocess.*\[.*[\"']",  # Hardcoded command
    r"X-Frame-Options",  # Missing header alone
    r"X-Content-Type-Options",  # Missing header alone
]


class BountyHunter:
    """
    Scans source code for bounty-worthy vulnerabilities.

    Inspired by ECC's security-bounty-hunter skill:
    - Focus on remotely reachable, user-controlled attack paths
    - Skip patterns that bounty platforms reject
    - Provide actionable PoC suggestions
    - Rate findings by bounty-worthiness
    """

    def __init__(self):
        self.patterns = BOUNTY_PATTERNS
        self.skip_patterns = SKIP_PATTERNS

    def scan_file(self, file_path: str) -> list[BountyFinding]:
        """Scan a single file for bounty-worthy vulnerabilities."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
        except (OSError, UnicodeDecodeError):
            return []

        findings = []
        for vuln_type, config in self.patterns.items():
            for pattern in config["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if it's a skip pattern
                        if self._should_skip(line, file_path):
                            continue

                        # Check for sanitization nearby
                        sanitized = self._check_sanitization(lines, i - 1, vuln_type)

                        finding = BountyFinding(
                            title=config["title"],
                            cwe_id=config["cwe"],
                            severity="high" if config["priority"] in (
                                BountyPriority.CRITICAL, BountyPriority.HIGH
                            ) else "medium",
                            priority=config["priority"],
                            description=config["description"],
                            file_path=file_path,
                            line_start=i,
                            evidence=line.strip()[:200],
                            exploitability="high" if not sanitized else "medium",
                            impact=self._get_impact(vuln_type),
                            attack_vector=config["attack_vector"],
                            poc_suggestion=config["poc_suggestion"],
                            owasp_category=self._get_owasp(vuln_type),
                            false_positive_likelihood="low" if not sanitized else "high",
                            tags=[vuln_type, "bounty"],
                        )
                        findings.append(finding)
                        break  # One finding per pattern per file

        return findings

    def scan_directory(self, directory: str, extensions: list[str] = None) -> list[BountyFinding]:
        """Scan a directory for bounty-worthy vulnerabilities."""
        if extensions is None:
            extensions = [
                ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
                ".php", ".rb", ".cs", ".swift", ".kt",
            ]

        findings = []
        from pathlib import Path

        for path in Path(directory).rglob("*"):
            if path.is_file() and path.suffix in extensions:
                # Skip test files, node_modules, vendor, etc.
                skip_dirs = {"node_modules", "vendor", ".git", "__pycache__", "test", "tests"}
                if any(part in skip_dirs for part in path.parts):
                    continue

                file_findings = self.scan_file(str(path))
                findings.extend(file_findings)

        # Sort by priority
        priority_order = {
            BountyPriority.CRITICAL: 0,
            BountyPriority.HIGH: 1,
            BountyPriority.MEDIUM: 2,
            BountyPriority.LOW: 3,
            BountyPriority.SKIP: 4,
        }
        findings.sort(key=lambda f: priority_order.get(f.priority, 5))

        return findings

    def generate_report(self, findings: list[BountyFinding]) -> str:
        """Generate a bounty-focused report."""
        if not findings:
            return "# Bounty Scan Report\n\n✅ No bounty-worthy vulnerabilities found.\n"

        lines = [
            "# 🎯 Bounty Scan Report",
            "",
            f"**Total Findings:** {len(findings)}",
            f"**Critical:** {sum(1 for f in findings if f.priority == BountyPriority.CRITICAL)}",
            f"**High:** {sum(1 for f in findings if f.priority == BountyPriority.HIGH)}",
            f"**Medium:** {sum(1 for f in findings if f.priority == BountyPriority.MEDIUM)}",
            "",
            "## Findings",
            "",
        ]

        for i, f in enumerate(findings, 1):
            emoji = {
                BountyPriority.CRITICAL: "🔴",
                BountyPriority.HIGH: "🟠",
                BountyPriority.MEDIUM: "🟡",
                BountyPriority.LOW: "🟢",
            }.get(f.priority, "⚪")

            lines.extend([
                f"### {i}. {emoji} {f.title}",
                "",
                f"- **CWE:** {f.cwe_id}",
                f"- **Priority:** {f.priority.value}",
                f"- **Location:** `{f.file_path}:{f.line_start}`",
                f"- **Exploitability:** {f.exploitability}",
                "",
                f"**Description:** {f.description}",
                "",
                f"**Evidence:**",
                f"```",
                f"{f.evidence}",
                f"```",
                "",
                f"**Attack Vector:** {f.attack_vector}",
                "",
                f"**PoC Suggestion:** {f.poc_suggestion}",
                "",
                f"**Impact:** {f.impact}",
                "",
                "---",
                "",
            ])

        return "\n".join(lines)

    def _should_skip(self, line: str, file_path: str) -> bool:
        """Check if a finding should be skipped (not bounty-worthy)."""
        for pattern in self.skip_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # Skip test files
        if "/test" in file_path or "_test." in file_path or "test_" in file_path:
            return True

        return False

    def _check_sanitization(self, lines: list[str], line_idx: int, vuln_type: str) -> bool:
        """Check if there's sanitization near the vulnerable line."""
        window = 5
        start = max(0, line_idx - window)
        end = min(len(lines), line_idx + window)
        context = "\n".join(lines[start:end]).lower()

        sanitizers = {
            "ssrf": ["allowlist", "whitelist", "urlparse", "validate_url", "safe_url"],
            "sqli": ["parameterized", "prepared", "placeholder", "bind_param", "escape"],
            "command_injection": ["shlex", "quote", "escape", "sanitize", "allowlist"],
            "path_traversal": ["realpath", "abspath", "sanitize_path", "secure_filename"],
            "xss": ["escape", "sanitize", "bleach", "markupsafe", "encode"],
            "deserialization": ["safe_load", "Loader=SafeLoader", "validate"],
            "auth_bypass": ["verify", "validate", "check_auth", "authenticate"],
            "idor": ["check_ownership", "authorize", "permission", "belongs_to"],
        }

        for keyword in sanitizers.get(vuln_type, []):
            if keyword in context:
                return True
        return False

    def _get_impact(self, vuln_type: str) -> str:
        impacts = {
            "ssrf": "Internal network access, cloud metadata theft, service enumeration",
            "sqli": "Data exfiltration, authentication bypass, data modification/deletion",
            "command_injection": "Remote code execution, server compromise, data theft",
            "path_traversal": "Arbitrary file read/write, credential theft, code injection",
            "xss": "Session hijacking, credential theft, admin account compromise",
            "deserialization": "Remote code execution, full server compromise",
            "auth_bypass": "Unauthorized access to any account, admin access",
            "idor": "Access to other users' data, privacy violation",
        }
        return impacts.get(vuln_type, "Unknown impact")

    def _get_owasp(self, vuln_type: str) -> str:
        owasp = {
            "ssrf": "A10:2021",
            "sqli": "A03:2021",
            "command_injection": "A03:2021",
            "path_traversal": "A01:2021",
            "xss": "A03:2021",
            "deserialization": "A08:2021",
            "auth_bypass": "A07:2021",
            "idor": "A01:2021",
        }
        return owasp.get(vuln_type, "")
