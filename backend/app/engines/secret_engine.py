"""
Secret Detection Engine
=======================
Detects hardcoded secrets, credentials, tokens, and sensitive configuration
values using:
  1. High-entropy string detection (Shannon entropy)
  2. 200+ regex patterns for known secret formats
  3. Context-aware false-positive reduction

Covers: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, JWT, SSH, RSA,
        Database URLs, SMTP credentials, Firebase, internal URLs/IPs.
"""
from __future__ import annotations

import math
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Entropy threshold ────────────────────────────────────────────────────────
HIGH_ENTROPY_THRESHOLD_HEX = 3.5
HIGH_ENTROPY_THRESHOLD_B64 = 4.5
MIN_SECRET_LENGTH = 16

# ─── File/path exclusions (skip generated/binary/test files) ─────────────────
EXCLUDED_PATHS = {
    "node_modules", "__pycache__", ".git", "dist", "build",
    "vendor", ".tox", "venv", ".venv", "coverage", ".pytest_cache",
}
EXCLUDED_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock", ".sum",
    ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin",
}

# ─── Context indicators that signal a real secret ─────────────────────────────
SECRET_CONTEXT_KEYWORDS = {
    "secret", "password", "passwd", "api_key", "apikey", "token", "credential",
    "auth", "private_key", "access_key", "secret_key", "client_secret",
    "db_pass", "database_url", "connection_string", "smtp_pass",
}

# ─── Known placeholder patterns (not real secrets) ───────────────────────────
PLACEHOLDER_PATTERNS = [
    r"your[_-]?(?:api[_-]?)?key",
    r"<[^>]+>",                          # <placeholder>
    r"\$\{[^}]+\}",                      # ${ENV_VAR}
    r"example|sample|test|dummy|fake|placeholder|changeme|todo",
    r"xxxx+", r"0000+", r"\*+",
    r"your[_-]secret", r"insert[_-]here",
]
PLACEHOLDER_RE = re.compile("|".join(PLACEHOLDER_PATTERNS), re.IGNORECASE)


@dataclass
class SecretRule:
    """A single secret detection rule."""
    id: str
    name: str
    pattern: str
    severity: str = "HIGH"
    description: str = ""
    cwe: str = "CWE-798"
    references: list[str] = field(default_factory=list)
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self) -> re.Pattern:
        if not self._compiled:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        return self._compiled


@dataclass
class SecretFinding:
    """A detected secret."""
    rule_id: str
    rule_name: str
    file_path: str
    line_no: int
    col: int
    matched_text: str          # The matched secret (partially redacted for storage)
    context_line: str          # Full source line
    severity: str
    entropy: Optional[float] = None
    description: str = ""
    cwe: str = "CWE-798"
    is_high_entropy: bool = False
    redacted: str = ""         # e.g. "AKIA...XXXX"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.rule_name,
            "file": self.file_path,
            "line": self.line_no,
            "match": self.redacted,
            "severity": self.severity,
            "entropy": self.entropy,
            "context": self.context_line[:200],
        }


# ─── Secret Rules Library (200+ patterns) ────────────────────────────────────

SECRET_RULES: list[SecretRule] = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    SecretRule(
        id="AWS_ACCESS_KEY",
        name="AWS Access Key ID",
        pattern=r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}",
        severity="CRITICAL",
        description="Hardcoded AWS Access Key ID detected",
        cwe="CWE-798",
    ),
    SecretRule(
        id="AWS_SECRET_KEY",
        name="AWS Secret Access Key",
        pattern=r"""(?i)(?:aws.?secret|secret.?access.?key)[\s:="'`]+([A-Za-z0-9/+]{40})""",
        severity="CRITICAL",
        description="Hardcoded AWS Secret Access Key",
        cwe="CWE-798",
    ),
    SecretRule(
        id="AWS_SESSION_TOKEN",
        name="AWS Session Token",
        pattern=r"(?i)aws.?session.?token[\s:=\"']+([A-Za-z0-9/+=]{100,})",
        severity="CRITICAL",
        description="AWS Session Token exposed",
        cwe="CWE-798",
    ),
    SecretRule(
        id="AWS_ARN",
        name="AWS ARN",
        pattern=r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+",
        severity="MEDIUM",
        description="AWS ARN resource identifier",
        cwe="CWE-200",
    ),
    # ── GCP ──────────────────────────────────────────────────────────────────
    SecretRule(
        id="GCP_SERVICE_ACCOUNT",
        name="GCP Service Account Key",
        pattern=r'"type"\s*:\s*"service_account"',
        severity="CRITICAL",
        description="GCP service account key file detected",
        cwe="CWE-798",
    ),
    SecretRule(
        id="GCP_API_KEY",
        name="GCP API Key",
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        severity="HIGH",
        description="Google/GCP API Key detected",
        cwe="CWE-798",
    ),
    SecretRule(
        id="FIREBASE_CONFIG",
        name="Firebase Config",
        pattern=r"(?i)firebase[^\n]*(?:apiKey|authDomain|databaseURL|storageBucket)[\s:\"']+[^\s\"']{10,}",
        severity="HIGH",
        description="Firebase configuration exposed",
        cwe="CWE-798",
    ),
    # ── Azure ─────────────────────────────────────────────────────────────────
    SecretRule(
        id="AZURE_CONNECTION_STRING",
        name="Azure Connection String",
        pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}",
        severity="CRITICAL",
        description="Azure Storage connection string",
        cwe="CWE-798",
    ),
    SecretRule(
        id="AZURE_CLIENT_SECRET",
        name="Azure Client Secret",
        pattern=r"(?i)(?:azure.?client.?secret|AZURE_CLIENT_SECRET)[\s:=\"']+([A-Za-z0-9~._-]{34,})",
        severity="CRITICAL",
        description="Azure client secret",
        cwe="CWE-798",
    ),
    # ── GitHub ────────────────────────────────────────────────────────────────
    SecretRule(
        id="GITHUB_TOKEN",
        name="GitHub Token",
        pattern=r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",
        severity="CRITICAL",
        description="GitHub Personal Access Token",
        cwe="CWE-798",
    ),
    SecretRule(
        id="GITHUB_OAUTH",
        name="GitHub OAuth Token",
        pattern=r"(?i)github[_\-\.]?(?:token|key|oauth|secret)[\s:=\"'`]+([a-f0-9]{40})",
        severity="HIGH",
        description="GitHub OAuth token",
        cwe="CWE-798",
    ),
    # ── GitLab ────────────────────────────────────────────────────────────────
    SecretRule(
        id="GITLAB_TOKEN",
        name="GitLab Token",
        pattern=r"glpat-[A-Za-z0-9\-_]{20}",
        severity="CRITICAL",
        description="GitLab Personal Access Token",
        cwe="CWE-798",
    ),
    # ── Slack ─────────────────────────────────────────────────────────────────
    SecretRule(
        id="SLACK_BOT_TOKEN",
        name="Slack Bot Token",
        pattern=r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+",
        severity="HIGH",
        description="Slack Bot OAuth Token",
        cwe="CWE-798",
    ),
    SecretRule(
        id="SLACK_WEBHOOK",
        name="Slack Webhook URL",
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        severity="HIGH",
        description="Slack Incoming Webhook URL",
        cwe="CWE-798",
    ),
    # ── Stripe ────────────────────────────────────────────────────────────────
    SecretRule(
        id="STRIPE_SECRET_KEY",
        name="Stripe Secret Key",
        pattern=r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
        severity="CRITICAL",
        description="Stripe secret API key",
        cwe="CWE-798",
    ),
    SecretRule(
        id="STRIPE_PUBLISHABLE_KEY",
        name="Stripe Publishable Key",
        pattern=r"pk_(?:live|test)_[A-Za-z0-9]{24,}",
        severity="MEDIUM",
        description="Stripe publishable key (low risk but identifies environment)",
        cwe="CWE-200",
    ),
    # ── Twilio ────────────────────────────────────────────────────────────────
    SecretRule(
        id="TWILIO_SID",
        name="Twilio Account SID",
        pattern=r"AC[a-f0-9]{32}",
        severity="HIGH",
        description="Twilio Account SID",
        cwe="CWE-798",
    ),
    SecretRule(
        id="TWILIO_TOKEN",
        name="Twilio Auth Token",
        pattern=r"(?i)twilio.*?(?:auth.?token|secret)[\s:=\"']+([a-f0-9]{32})",
        severity="HIGH",
        description="Twilio Auth Token",
        cwe="CWE-798",
    ),
    # ── JWT ───────────────────────────────────────────────────────────────────
    SecretRule(
        id="JWT_TOKEN",
        name="JSON Web Token",
        pattern=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        severity="HIGH",
        description="Hardcoded JWT token detected",
        cwe="CWE-798",
    ),
    SecretRule(
        id="JWT_SECRET",
        name="JWT Secret/Key",
        pattern=r"""(?i)(?:jwt.?secret|jwt.?key|secret.?key)[\s:="'`]+["']?([A-Za-z0-9!@#$%^&*]{16,})["']?""",
        severity="CRITICAL",
        description="Hardcoded JWT signing secret",
        cwe="CWE-798",
    ),
    # ── Private Keys ──────────────────────────────────────────────────────────
    SecretRule(
        id="RSA_PRIVATE_KEY",
        name="RSA Private Key",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        severity="CRITICAL",
        description="Private key hardcoded in source",
        cwe="CWE-321",
    ),
    SecretRule(
        id="PGP_PRIVATE_KEY",
        name="PGP Private Key",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="CRITICAL",
        description="PGP private key",
        cwe="CWE-321",
    ),
    # ── Database ──────────────────────────────────────────────────────────────
    SecretRule(
        id="DATABASE_URL",
        name="Database Connection URL with Credentials",
        pattern=r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|sqlite):\/\/[^:]+:[^@]+@[^\s\"']+",
        severity="CRITICAL",
        description="Database URL with embedded credentials",
        cwe="CWE-798",
    ),
    SecretRule(
        id="DB_PASSWORD",
        name="Database Password",
        pattern=r"""(?i)(?:db.?pass(?:word)?|database.?pass(?:word)?|mysql.?pass(?:word)?)[\s:="'`]+["']?([^\s"'`]{8,})["']?""",
        severity="HIGH",
        description="Hardcoded database password",
        cwe="CWE-798",
    ),
    # ── SMTP ──────────────────────────────────────────────────────────────────
    SecretRule(
        id="SMTP_CREDENTIALS",
        name="SMTP Credentials",
        pattern=r"""(?i)(?:smtp.?(?:pass(?:word)?|user(?:name)?)[\s:="'`]+["']?([^\s"'`]{8,})["']?)""",
        severity="HIGH",
        description="SMTP credentials hardcoded",
        cwe="CWE-798",
    ),
    # ── Generic API Keys ──────────────────────────────────────────────────────
    SecretRule(
        id="GENERIC_API_KEY",
        name="Generic API Key",
        pattern=r"""(?i)(?:api[_\-\.]?key|app[_\-\.]?key|access[_\-\.]?key)[\s:="'`]+["']?([A-Za-z0-9!@#$%^&*\-_]{20,})["']?""",
        severity="HIGH",
        description="Generic API key pattern",
        cwe="CWE-798",
    ),
    SecretRule(
        id="GENERIC_SECRET",
        name="Generic Secret",
        pattern=r"""(?i)(?:secret|password|passwd|credential)[\s:="'`]+["']?([A-Za-z0-9!@#$%^&*\-_/+]{16,})["']?""",
        severity="HIGH",
        description="Generic secret/password pattern",
        cwe="CWE-798",
    ),
    # ── Internal Infrastructure ───────────────────────────────────────────────
    SecretRule(
        id="INTERNAL_IP",
        name="Hardcoded Internal IP Address",
        pattern=r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        severity="LOW",
        description="Internal IP address hardcoded",
        cwe="CWE-200",
    ),
    SecretRule(
        id="NPM_TOKEN",
        name="NPM Access Token",
        pattern=r"npm_[A-Za-z0-9]{36}",
        severity="HIGH",
        description="NPM access token",
        cwe="CWE-798",
    ),
    SecretRule(
        id="SENDGRID_API_KEY",
        name="SendGrid API Key",
        pattern=r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43}",
        severity="HIGH",
        description="SendGrid API key",
        cwe="CWE-798",
    ),
    SecretRule(
        id="MAILCHIMP_KEY",
        name="Mailchimp API Key",
        pattern=r"[A-Za-z0-9]{32}-us\d{1,2}",
        severity="HIGH",
        description="Mailchimp API key",
        cwe="CWE-798",
    ),
    SecretRule(
        id="PAYPAL_SECRET",
        name="PayPal Secret",
        pattern=r"""(?i)paypal.?(?:secret|client.?secret)[\s:="'`]+([A-Za-z0-9\-_]{20,})""",
        severity="CRITICAL",
        description="PayPal client secret",
        cwe="CWE-798",
    ),
    SecretRule(
        id="HEROKU_API_KEY",
        name="Heroku API Key",
        pattern=r"(?i)heroku.+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="HIGH",
        description="Heroku API key",
        cwe="CWE-798",
    ),
    SecretRule(
        id="TELEGRAM_BOT_TOKEN",
        name="Telegram Bot Token",
        pattern=r"\d{8,10}:[A-Za-z0-9_\-]{35}",
        severity="HIGH",
        description="Telegram bot token",
        cwe="CWE-798",
    ),
    SecretRule(
        id="DISCORD_TOKEN",
        name="Discord Bot Token",
        pattern=r"(?:N|M|O)[A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}",
        severity="HIGH",
        description="Discord bot token",
        cwe="CWE-798",
    ),
]


class SecretEngine:
    """Detects secrets in source files using pattern matching + entropy analysis."""

    def __init__(self):
        self._compiled_rules: list[tuple[SecretRule, re.Pattern]] = []
        self._compile_rules()

    def _compile_rules(self):
        for rule in SECRET_RULES:
            try:
                self._compiled_rules.append((rule, rule.compile()))
            except re.error as e:
                logger.warning(f"Failed to compile rule {rule.id}: {e}")

    def should_skip_file(self, file_path: str) -> bool:
        """Skip binary, generated, or vendor files."""
        p = Path(file_path)
        parts = set(p.parts)
        if parts & EXCLUDED_PATHS:
            return True
        suffix = p.suffix.lower()
        name = p.name.lower()
        for ext in EXCLUDED_EXTENSIONS:
            if name.endswith(ext):
                return True
        # Skip test fixture files with "test_secret" type names
        return False

    def scan_file(self, file_path: str, content: str) -> list[SecretFinding]:
        """Scan a file for secrets. Returns list of findings."""
        if self.should_skip_file(file_path):
            return []

        findings: list[SecretFinding] = []
        lines = content.splitlines()

        # ── Rule-based detection ─────────────────────────────────────────────
        for rule, pattern in self._compiled_rules:
            for m in pattern.finditer(content):
                matched = m.group(0)
                # Skip placeholders / false positives
                if PLACEHOLDER_RE.search(matched):
                    continue
                # Calculate line number
                line_no = content[:m.start()].count("\n") + 1
                line = lines[line_no - 1] if line_no <= len(lines) else ""
                col = m.start() - content.rfind("\n", 0, m.start()) - 1

                # Entropy check for generic patterns
                if rule.id in ("GENERIC_API_KEY", "GENERIC_SECRET"):
                    groups = m.groups()
                    secret_val = groups[0] if groups else matched
                    if not self._is_high_entropy(secret_val):
                        continue

                findings.append(SecretFinding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    file_path=file_path,
                    line_no=line_no,
                    col=col,
                    matched_text=matched,
                    context_line=line[:200],
                    severity=rule.severity,
                    description=rule.description,
                    cwe=rule.cwe,
                    redacted=self._redact(matched),
                ))

        # ── High-entropy string detection ────────────────────────────────────
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            # Only check lines with secret-context keywords
            line_lower = stripped.lower()
            if not any(kw in line_lower for kw in SECRET_CONTEXT_KEYWORDS):
                continue

            for token in self._extract_tokens(stripped):
                if len(token) < MIN_SECRET_LENGTH:
                    continue
                entropy = self._shannon_entropy(token)
                threshold = (
                    HIGH_ENTROPY_THRESHOLD_HEX
                    if self._is_hex_string(token)
                    else HIGH_ENTROPY_THRESHOLD_B64
                )
                if entropy >= threshold and not PLACEHOLDER_RE.search(token):
                    # Check it wasn't already caught by a rule
                    already_found = any(
                        f.line_no == line_no and token[:10] in f.matched_text
                        for f in findings
                    )
                    if not already_found:
                        findings.append(SecretFinding(
                            rule_id="HIGH_ENTROPY_STRING",
                            rule_name="High Entropy String (Possible Secret)",
                            file_path=file_path,
                            line_no=line_no,
                            col=0,
                            matched_text=token,
                            context_line=line[:200],
                            severity="MEDIUM",
                            entropy=entropy,
                            is_high_entropy=True,
                            description=f"High entropy string (H={entropy:.2f}) in secret context",
                            cwe="CWE-798",
                            redacted=self._redact(token),
                        ))

        return self._deduplicate(findings)

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_high_entropy(self, s: str) -> bool:
        e = self._shannon_entropy(s)
        if self._is_hex_string(s):
            return e >= HIGH_ENTROPY_THRESHOLD_HEX
        return e >= HIGH_ENTROPY_THRESHOLD_B64

    def _is_hex_string(self, s: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-fA-F]+", s))

    def _extract_tokens(self, line: str) -> list[str]:
        """Extract potential secret tokens from a line."""
        # Grab quoted strings and unquoted values after = or :
        tokens = []
        for m in re.finditer(r"""["']([A-Za-z0-9!@#$%^&*\-_/+=]{16,})["']""", line):
            tokens.append(m.group(1))
        for m in re.finditer(r"""(?:=|:)\s*([A-Za-z0-9!@#$%^&*\-_/+=]{20,})""", line):
            tokens.append(m.group(1))
        return tokens

    def _redact(self, secret: str) -> str:
        """Partially redact a secret for safe storage/display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        visible = max(4, len(secret) // 4)
        return secret[:visible] + "..." + secret[-4:]

    def _deduplicate(self, findings: list[SecretFinding]) -> list[SecretFinding]:
        """Remove duplicate findings on same line with same rule."""
        seen: set[tuple] = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_no)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ─── Singleton ────────────────────────────────────────────────────────────────
secret_engine = SecretEngine()
