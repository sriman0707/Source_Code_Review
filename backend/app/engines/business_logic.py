"""
Business Logic Security Engine
================================
Detects complex business logic vulnerabilities that pattern matchers miss:

- IDOR / BOLA / BFLA
- Privilege Escalation (horizontal + vertical)
- Payment / Coupon / Referral abuse
- Race Conditions
- Account Takeover flows
- Mass Assignment
- OTP / MFA bypass
- Password Reset weaknesses
- Workflow bypass
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from app.engines.ast_engine import ParsedFile

logger = logging.getLogger(__name__)


@dataclass
class BusinessLogicFinding:
    """A business logic vulnerability finding."""
    rule_id: str
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    severity: str
    confidence: float
    category: str
    cwe: str
    owasp: str
    attack_scenario: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "file": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "attack_scenario": self.attack_scenario,
        }


# ─── Business Logic Rules ─────────────────────────────────────────────────────

class BusinessLogicEngine:

    def analyze(self, parsed_file: ParsedFile) -> list[BusinessLogicFinding]:
        """Run all business logic checks on a parsed file."""
        findings: list[BusinessLogicFinding] = []
        findings.extend(self._check_idor(parsed_file))
        findings.extend(self._check_mass_assignment(parsed_file))
        findings.extend(self._check_payment_logic(parsed_file))
        findings.extend(self._check_auth_bypass(parsed_file))
        findings.extend(self._check_race_conditions(parsed_file))
        findings.extend(self._check_password_reset(parsed_file))
        findings.extend(self._check_otp_bypass(parsed_file))
        findings.extend(self._check_privilege_escalation(parsed_file))
        findings.extend(self._check_account_takeover(parsed_file))
        findings.extend(self._check_graphql(parsed_file))
        return findings

    # ── IDOR / BOLA ───────────────────────────────────────────────────────────
    def _check_idor(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # Pattern: Using user-supplied ID directly to fetch object without ownership check
        # e.g., `obj = Model.objects.get(id=request.data['id'])`
        # without subsequent `if obj.owner != request.user`
        id_fetch_patterns = [
            r"(?:get|find|fetch|query)\s*\(\s*(?:id|pk|user_id|account_id)\s*=",
            r"(?:Model|objects)\.get\(id\s*=",
            r"findById\s*\(",
            r"\.find_by_id\s*\(",
            r"getById\s*\(",
            r"findOne\s*\(\s*\{?\s*_?id\s*:",
            r"WHERE\s+id\s*=",
            r"db\.get\s*\(",
        ]
        ownership_check_patterns = [
            r"owner", r"user_id\s*=\s*(?:request|current_user|session)",
            r"\.user\s*==", r"belongs_to", r"is_owner",
            r"permission", r"authorize", r"can_access",
            r"assert.*owner", r"if.*\.user_id\s*!=",
        ]

        window_size = 20  # Lines after fetch to look for ownership check

        for i, line in enumerate(lines, 1):
            matched_fetch = False
            for pat in id_fetch_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    matched_fetch = True
                    break

            if not matched_fetch:
                continue

            # Look for user-controlled input on same or adjacent lines
            has_user_input = False
            context_start = max(0, i - 3)
            context_end = min(len(lines), i + 3)
            context = "\n".join(lines[context_start:context_end])
            user_input_patterns = [
                "request", "req.", "params", "query", "body",
                "ctx.", "c.Param", "r.URL",
            ]
            if any(p in context for p in user_input_patterns):
                has_user_input = True

            if not has_user_input:
                continue

            # Look for ownership validation in next N lines
            check_window = "\n".join(lines[i:min(len(lines), i + window_size)])
            has_ownership_check = any(
                re.search(p, check_window, re.IGNORECASE)
                for p in ownership_check_patterns
            )

            if not has_ownership_check:
                snippet = pf.get_snippet(max(1, i-1), min(len(lines), i+5))
                findings.append(BusinessLogicFinding(
                    rule_id="BL_IDOR_001",
                    title="Potential IDOR — Object Fetched by User-Controlled ID Without Ownership Check",
                    description=(
                        "An object is fetched using a user-supplied identifier (id, pk, etc.) "
                        "without validating that the requesting user owns or has access to it. "
                        "This is a classic Broken Object Level Authorization (BOLA/IDOR) pattern."
                    ),
                    file_path=pf.path,
                    line_start=i,
                    line_end=min(len(lines), i + 5),
                    code_snippet=snippet,
                    severity="HIGH",
                    confidence=0.7,
                    category="idor",
                    cwe="CWE-639",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    attack_scenario=(
                        "Attacker changes the `id` parameter from their own resource ID "
                        "to another user's ID. Since no ownership check exists, the server "
                        "returns the other user's data — IDOR confirmed."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/639.html",
                    ],
                ))

        return findings

    # ── Mass Assignment ────────────────────────────────────────────────────────
    def _check_mass_assignment(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        patterns = {
            "python": [
                r"\.update\s*\(\s*\*\*\s*request\.",
                r"setattr\s*\(\s*\w+\s*,\s*key\s*,\s*value\s*\)",
                r"Model\s*\(\s*\*\*\s*(?:request|data|body)",
                r"\.update_or_create\s*\(\s*\*\*",
                r"from_dict\s*\(\s*request",
                r"schema\.load\s*\(\s*request",  # May not validate role/is_admin
            ],
            "javascript": [
                r"Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)",
                r"\.\s*set\s*\(\s*req\.body\s*\)",
                r"Model\.create\s*\(\s*req\.body\s*\)",
                r"\.updateOne\s*\(\s*\{[^}]*\}\s*,\s*\{.*\$set.*req\.body",
                r"new\s+Model\s*\(\s*req\.body\s*\)",
                r"\.update\s*\(\s*req\.body\s*\)",
            ],
            "php": [
                r"\$model->fill\s*\(\s*\$request->all\(\)\s*\)",
                r"Model::create\s*\(\s*\$request->all\(\)\s*\)",
                r"\$model->update\s*\(\s*\$request->all\(\)\s*\)",
            ],
            "java": [
                r"BeanUtils\.copyProperties\s*\(",
                r"@RequestBody\s+Map",
            ],
            "go": [
                r"json\.NewDecoder.*\.Decode\s*\(&\w+\)",
                r"c\.ShouldBindJSON\s*\(",
                r"c\.BindJSON\s*\(",
            ],
        }

        lang_patterns = patterns.get(pf.language, patterns.get("javascript", []))

        for i, line in enumerate(lines, 1):
            for pat in lang_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    # Check for allowlist/denylist in context
                    context = "\n".join(lines[max(0, i-5):min(len(lines), i+5)])
                    has_filter = any(kw in context for kw in [
                        "allowlist", "whitelist", "permitted", "only(",
                        "permit!", "fillable", "mass_assignable", "exclude(",
                        "pick(", "omit(", "validated_data", "cleaned_data",
                    ])
                    if not has_filter:
                        snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+3))
                        findings.append(BusinessLogicFinding(
                            rule_id="BL_MASS_ASSIGN_001",
                            title="Mass Assignment — Unfiltered Request Body Bound to Model",
                            description=(
                                "The entire request body is directly assigned to a model object "
                                "without field allowlisting. An attacker can set sensitive fields "
                                "like `is_admin`, `role`, `balance`, or `verified` directly."
                            ),
                            file_path=pf.path,
                            line_start=i,
                            line_end=i,
                            code_snippet=snippet,
                            severity="HIGH",
                            confidence=0.8,
                            category="business_logic",
                            cwe="CWE-915",
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            attack_scenario=(
                                'POST /api/register with body {"username":"hacker","is_admin":true} '
                                "— attacker becomes admin by injecting the is_admin field."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                                "https://cwe.mitre.org/data/definitions/915.html",
                            ],
                        ))
                    break

        return findings

    # ── Payment Logic Flaws ───────────────────────────────────────────────────
    def _check_payment_logic(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # Negative price / zero-value payment bypass
        neg_price_patterns = [
            r"price\s*[><=!]+\s*0",
            r"amount\s*[><=!]+\s*0",
            r"total\s*[><=!]+\s*0",
        ]
        # Missing validation: amount not validated before charging
        payment_sinks = [
            "stripe.charge", "stripe.create", "paypal", "charge(", "create_charge",
            "process_payment", "debit(", "transfer(", "pay(", "checkout(",
        ]
        payment_validation = [
            "if.*amount.*>.*0", "if.*price.*>", "validate.*amount",
            "assert.*amount", "amount.*positive",
        ]

        in_payment_block = False
        payment_start = 0

        for i, line in enumerate(lines, 1):
            line_l = line.lower()

            # Detect payment operations
            has_payment_sink = any(s in line_l for s in payment_sinks)
            if has_payment_sink:
                # Check if amount is validated in nearby context
                context_start = max(0, i - 15)
                context = "\n".join(lines[context_start:i])
                has_validation = any(
                    re.search(v, context, re.IGNORECASE) for v in payment_validation
                )
                if not has_validation:
                    snippet = pf.get_snippet(max(1, i-5), min(len(lines), i+3))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_PAYMENT_001",
                        title="Payment Processing Without Amount Validation",
                        description=(
                            "A payment is processed without validating that the amount is positive. "
                            "An attacker may submit a negative or zero amount to receive refunds, "
                            "bypass payment, or manipulate account balances."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="CRITICAL",
                        confidence=0.65,
                        category="business_logic",
                        cwe="CWE-840",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        attack_scenario=(
                            'POST /api/checkout with {"amount": -100} — attacker receives '
                            "$100 credit instead of being charged. Negative pricing attack."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                        ],
                    ))

        # Coupon abuse detection
        coupon_patterns = [
            r"coupon|discount|promo|voucher",
        ]
        coupon_limit_check = [
            "already_used", "one_per_user", "coupon_used", "is_valid",
            "user.*coupon", "max_uses", "usage_count",
        ]

        for i, line in enumerate(lines, 1):
            if any(re.search(p, line, re.IGNORECASE) for p in coupon_patterns):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 15)
                context = "\n".join(lines[context_start:context_end])
                has_limit_check = any(kw in context.lower() for kw in coupon_limit_check)
                if not has_limit_check:
                    snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+5))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_COUPON_001",
                        title="Coupon/Promo Code Without Usage Limit Check",
                        description=(
                            "Coupon/discount code processing detected without verifying usage limits. "
                            "An attacker can stack or reuse the same coupon multiple times."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="MEDIUM",
                        confidence=0.55,
                        category="business_logic",
                        cwe="CWE-840",
                        owasp="API6:2023",
                        attack_scenario=(
                            "Apply the same coupon code 100 times in parallel (race condition). "
                            "Each request passes the unused check before any can mark it used."
                        ),
                        references=[],
                    ))
                    break  # One per file for this rule

        return findings

    # ── Auth Bypass ───────────────────────────────────────────────────────────
    def _check_auth_bypass(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # JWT alg:none vulnerability
        jwt_none_patterns = [
            r"""alg(?:orithm)?\s*[=:]\s*["']none["']""",
            r"""algorithms\s*=\s*\[\s*["']none["']""",
            r"""verify\s*=\s*False""",
            r"""options\s*=\s*\{[^}]*verify_signature[^}]*False""",
        ]

        for i, line in enumerate(lines, 1):
            for pat in jwt_none_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+3))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_JWT_NONE_001",
                        title="JWT 'none' Algorithm Accepted — Authentication Bypass",
                        description=(
                            "The application appears to accept JWTs with the 'none' algorithm "
                            "or has signature verification disabled. An attacker can forge any JWT "
                            "and impersonate any user, including administrators."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="CRITICAL",
                        confidence=0.9,
                        category="authentication",
                        cwe="CWE-347",
                        owasp="A02:2021 Cryptographic Failures",
                        attack_scenario=(
                            "Decode any JWT, change the algorithm to 'none', set sub to admin user ID, "
                            "remove the signature. Server accepts the forged token and grants admin access."
                        ),
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            "https://cwe.mitre.org/data/definitions/347.html",
                        ],
                    ))

        # Hardcoded admin bypass
        admin_bypass = [
            r"""(?:admin|superuser|is_admin)\s*=\s*(?:True|true|1|"true")""",
            r"""role\s*=\s*["']admin["']""",
            r"""if\s+username\s*==\s*["']admin["']""",
        ]
        for i, line in enumerate(lines, 1):
            for pat in admin_bypass:
                if re.search(pat, line, re.IGNORECASE):
                    # Check if this is in test code
                    path_lower = pf.path.lower()
                    is_test = any(t in path_lower for t in ["test", "spec", "mock", "fixture"])
                    if not is_test:
                        snippet = pf.get_snippet(max(1, i-1), min(len(lines), i+3))
                        findings.append(BusinessLogicFinding(
                            rule_id="BL_HARDCODED_ADMIN_001",
                            title="Hardcoded Admin/Privileged Role Assignment",
                            description=(
                                "Admin privileges or role assignment appears hardcoded. "
                                "This could create a backdoor account or bypass authorization."
                            ),
                            file_path=pf.path,
                            line_start=i,
                            line_end=i,
                            code_snippet=snippet,
                            severity="HIGH",
                            confidence=0.7,
                            category="authorization",
                            cwe="CWE-798",
                            owasp="A07:2021 Identification and Authentication Failures",
                            attack_scenario="Hardcoded admin credentials allow backdoor access.",
                            references=[],
                        ))

        return findings

    # ── Race Conditions ───────────────────────────────────────────────────────
    def _check_race_conditions(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # Check → Act patterns without locking (TOCTOU)
        check_act_patterns = [
            # Check balance, then deduct
            (r"(?:balance|wallet|credit|funds).*[><=]", r"(?:deduct|withdraw|subtract|reduce).*(?:balance|wallet)"),
            # Check coupon validity, then mark used
            (r"(?:is_valid|not.*used|unused).*(?:coupon|code)", r"(?:mark|set|update).*(?:used|redeemed)"),
            # Check stock, then decrement
            (r"(?:stock|quantity|inventory).*[><=].*0", r"(?:decrement|reduce|update).*(?:stock|quantity)"),
        ]

        for i, line in enumerate(lines, 1):
            for check_pat, act_pat in check_act_patterns:
                if re.search(check_pat, line, re.IGNORECASE):
                    # Look for the "act" within 20 lines
                    window = lines[i:min(len(lines), i + 20)]
                    for j, wline in enumerate(window):
                        if re.search(act_pat, wline, re.IGNORECASE):
                            # Check for transaction/locking primitives
                            context = "\n".join(lines[i-1:i+j+1])
                            has_lock = any(kw in context.lower() for kw in [
                                "transaction", "atomic", "lock", "mutex", "with_lock",
                                "select_for_update", "pessimistic", "serializable",
                                "for update", "@atomic",
                            ])
                            if not has_lock:
                                snippet = pf.get_snippet(i, min(len(lines), i+j+1))
                                findings.append(BusinessLogicFinding(
                                    rule_id="BL_RACE_001",
                                    title="TOCTOU Race Condition — Check-Then-Act Without Atomic Lock",
                                    description=(
                                        "A check (balance, coupon validity, stock) followed by an action "
                                        "(debit, mark-used, decrement) occurs without a database transaction "
                                        "or lock. Parallel requests can pass the check simultaneously and "
                                        "both execute the action — classic race condition."
                                    ),
                                    file_path=pf.path,
                                    line_start=i,
                                    line_end=min(len(lines), i+j+1),
                                    code_snippet=snippet,
                                    severity="HIGH",
                                    confidence=0.75,
                                    category="business_logic",
                                    cwe="CWE-362",
                                    owasp="API6:2023",
                                    attack_scenario=(
                                        "Send 50 concurrent requests to redeem coupon. All pass the "
                                        "'is_valid' check simultaneously before any can mark it used. "
                                        "Result: coupon redeemed 50 times."
                                    ),
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/362.html",
                                    ],
                                ))
                            break

        return findings

    # ── Password Reset Weaknesses ─────────────────────────────────────────────
    def _check_password_reset(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        for i, line in enumerate(lines, 1):
            line_l = line.lower()

            # Weak token generation
            weak_token_patterns = [
                r"random\.random\s*\(",          # Python: not crypto-secure
                r"Math\.random\s*\(",            # JS: not crypto-secure
                r"rand\s*\(",                    # PHP rand()
                r"str\(time\(",                  # Timestamp-based token
                r"uuid1\s*\(",                   # UUID1 is time-based, guessable
            ]
            if "reset" in line_l or "token" in line_l or "password" in line_l:
                for pat in weak_token_patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+3))
                        findings.append(BusinessLogicFinding(
                            rule_id="BL_PWRESET_001",
                            title="Weak Password Reset Token Generation",
                            description=(
                                "Password reset token is generated using a non-cryptographically-secure "
                                "random function. Tokens may be predictable, allowing account takeover."
                            ),
                            file_path=pf.path,
                            line_start=i,
                            line_end=i,
                            code_snippet=snippet,
                            severity="HIGH",
                            confidence=0.8,
                            category="authentication",
                            cwe="CWE-340",
                            owasp="A07:2021",
                            attack_scenario=(
                                "Attacker uses known seed or brute-forces the token space to "
                                "predict a valid password reset token and takes over the account."
                            ),
                            references=["https://cwe.mitre.org/data/definitions/340.html"],
                        ))
                        break

            # Token not expiring
            if "reset_token" in line_l or "password_reset" in line_l:
                context = "\n".join(lines[i:min(len(lines), i+15)])
                has_expiry = any(kw in context.lower() for kw in [
                    "expires", "expiry", "ttl", "timeout", "timedelta", "max_age",
                    "created_at", "expired",
                ])
                if not has_expiry:
                    snippet = pf.get_snippet(i, min(len(lines), i+5))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_PWRESET_002",
                        title="Password Reset Token May Not Have Expiry",
                        description=(
                            "Password reset token is created without an explicit expiry check nearby. "
                            "Non-expiring tokens allow an attacker who intercepts an old token to "
                            "reset the password at any time."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="MEDIUM",
                        confidence=0.55,
                        category="authentication",
                        cwe="CWE-613",
                        owasp="A07:2021",
                        attack_scenario="Expired tokens are accepted indefinitely, allowing delayed ATO.",
                        references=["https://cwe.mitre.org/data/definitions/613.html"],
                    ))

        return findings

    # ── OTP Bypass ────────────────────────────────────────────────────────────
    def _check_otp_bypass(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        for i, line in enumerate(lines, 1):
            line_l = line.lower()

            if not any(kw in line_l for kw in ["otp", "mfa", "totp", "2fa", "one_time"]):
                continue

            # Check for rate limiting on OTP verification
            context = "\n".join(lines[max(0, i-3):min(len(lines), i+15)])
            has_rate_limit = any(kw in context.lower() for kw in [
                "rate_limit", "throttle", "max_attempts", "attempt_count",
                "lockout", "cooldown", "delay", "sleep",
            ])

            if not has_rate_limit and ("verify" in line_l or "check" in line_l or "validate" in line_l):
                snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+5))
                findings.append(BusinessLogicFinding(
                    rule_id="BL_OTP_001",
                    title="OTP/MFA Verification Without Rate Limiting — Brute Force Risk",
                    description=(
                        "OTP or MFA verification does not appear to have rate limiting or attempt lockout. "
                        "An attacker can brute-force a 6-digit OTP (1,000,000 combinations) without restriction."
                    ),
                    file_path=pf.path,
                    line_start=i,
                    line_end=i,
                    code_snippet=snippet,
                    severity="HIGH",
                    confidence=0.7,
                    category="authentication",
                    cwe="CWE-307",
                    owasp="A07:2021",
                    attack_scenario=(
                        "Attacker sends 1,000,000 requests with incrementing OTP values. "
                        "With no rate limiting, the correct OTP is found within minutes — MFA bypassed."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/307.html"],
                ))

        return findings

    # ── Privilege Escalation ──────────────────────────────────────────────────
    def _check_privilege_escalation(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # Role update without authorization check
        role_update_patterns = [
            r"\.role\s*=",
            r"user\.is_admin\s*=",
            r"setRole\s*\(",
            r"update.*role",
            r"user\[.role.\]\s*=",
            r"promote\s*\(",
            r"elevate\s*\(",
        ]
        auth_check_patterns = [
            "is_admin", "require_admin", "admin_required", "has_permission",
            "check_permission", "current_user.*admin", "role.*admin",
            "@admin", "authorize", "can(:manage",
        ]

        for i, line in enumerate(lines, 1):
            for pat in role_update_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    # Check for auth guard in surrounding context
                    context_start = max(0, i - 20)
                    context = "\n".join(lines[context_start:i])
                    has_auth = any(kw in context.lower() for kw in auth_check_patterns)
                    if not has_auth:
                        path_lower = pf.path.lower()
                        is_test = any(t in path_lower for t in ["test", "spec", "seed", "migration"])
                        if not is_test:
                            snippet = pf.get_snippet(max(1, i-3), min(len(lines), i+3))
                            findings.append(BusinessLogicFinding(
                                rule_id="BL_PRIVESC_001",
                                title="Privilege Escalation — Role Update Without Authorization Check",
                                description=(
                                    "User role or admin flag is being updated without an apparent "
                                    "authorization guard. A regular user might be able to elevate "
                                    "their own privileges to admin."
                                ),
                                file_path=pf.path,
                                line_start=i,
                                line_end=i,
                                code_snippet=snippet,
                                severity="CRITICAL",
                                confidence=0.65,
                                category="authorization",
                                cwe="CWE-269",
                                owasp="A01:2021 Broken Access Control",
                                attack_scenario=(
                                    "Attacker sends PUT /api/profile with body {\"role\":\"admin\"} "
                                    "or {\"is_admin\":true}. Without authorization check, role is updated."
                                ),
                                references=["https://cwe.mitre.org/data/definitions/269.html"],
                            ))
                    break

        return findings

    # ── Account Takeover ──────────────────────────────────────────────────────
    def _check_account_takeover(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines

        # Email change without password re-auth
        for i, line in enumerate(lines, 1):
            line_l = line.lower()
            if any(kw in line_l for kw in ["email", "username", "phone"]) and \
               any(kw in line_l for kw in ["update", "change", "set", "="]):
                context_start = max(0, i - 15)
                context = "\n".join(lines[context_start:i+5])
                has_reauth = any(kw in context.lower() for kw in [
                    "password", "current_password", "confirm_password",
                    "re_enter", "verify_password", "check_password",
                ])
                if not has_reauth:
                    snippet = pf.get_snippet(max(1, i-2), min(len(lines), i+4))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_ATO_001",
                        title="Account Email/Username Change Without Password Confirmation",
                        description=(
                            "Email or username update does not require current password confirmation. "
                            "If an attacker gains temporary session access (e.g., via XSS), they can "
                            "permanently change the email and lock the real owner out."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="HIGH",
                        confidence=0.5,
                        category="authentication",
                        cwe="CWE-620",
                        owasp="A07:2021",
                        attack_scenario=(
                            "Attacker with stolen session cookie changes the email to attacker@evil.com. "
                            "Account is now fully controlled by attacker."
                        ),
                        references=["https://cwe.mitre.org/data/definitions/620.html"],
                    ))
                    break  # One per file for this rule

        return findings

    # ── GraphQL Security ──────────────────────────────────────────────────────
    def _check_graphql(self, pf: ParsedFile) -> list[BusinessLogicFinding]:
        findings = []
        lines = pf.lines
        content = pf.content

        # Introspection enabled in production
        if "introspection" in content.lower():
            for i, line in enumerate(lines, 1):
                if re.search(r"introspection\s*[=:]\s*(?:True|true|1|enabled)", line, re.IGNORECASE):
                    snippet = pf.get_snippet(max(1, i-1), min(len(lines), i+3))
                    findings.append(BusinessLogicFinding(
                        rule_id="BL_GRAPHQL_001",
                        title="GraphQL Introspection Enabled",
                        description=(
                            "GraphQL introspection is enabled. This allows attackers to enumerate "
                            "the entire schema, discover hidden fields, mutations, and admin endpoints."
                        ),
                        file_path=pf.path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        severity="MEDIUM",
                        confidence=0.85,
                        category="graphql",
                        cwe="CWE-200",
                        owasp="API8:2023 Security Misconfiguration",
                        attack_scenario=(
                            "Send {__schema{types{name}}} query to discover all types, "
                            "then enumerate admin mutations like deleteUser, promoteToAdmin."
                        ),
                        references=["https://owasp.org/www-project-api-security/"],
                    ))

        # Missing query depth/complexity limits
        if "graphql" in pf.path.lower() or "schema" in pf.path.lower():
            has_depth_limit = any(
                kw in content.lower()
                for kw in ["depth_limit", "max_depth", "query_complexity", "max_complexity"]
            )
            if not has_depth_limit:
                findings.append(BusinessLogicFinding(
                    rule_id="BL_GRAPHQL_002",
                    title="GraphQL — No Query Depth or Complexity Limit",
                    description=(
                        "No query depth or complexity limits detected. An attacker can send deeply "
                        "nested queries to cause denial of service or extract large data sets."
                    ),
                    file_path=pf.path,
                    line_start=1,
                    line_end=1,
                    code_snippet="",
                    severity="MEDIUM",
                    confidence=0.6,
                    category="graphql",
                    cwe="CWE-400",
                    owasp="API8:2023",
                    attack_scenario=(
                        "Query: {users{friends{friends{friends{name}}}}} — exponential data fetch "
                        "causes server timeout or OOM."
                    ),
                    references=[],
                ))

        return findings


# ─── Singleton ────────────────────────────────────────────────────────────────
business_logic_engine = BusinessLogicEngine()
