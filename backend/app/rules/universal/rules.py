"""Universal rules applying to all languages"""
from app.rules.base import Rule

RULES = [
    Rule(id="UNIV_TODO_001", title="Security TODO/FIXME Comment",
         description="Security-related TODO comment indicates known unresolved security issue.",
         category="misconfiguration", severity="INFO",
         pattern=r"""(?:#|//|\*)\s*(?:TODO|FIXME|HACK|XXX).*(?:security|auth|vuln|inject|xss|sql|csrf)""",
         cwe="CWE-1188", owasp="A05:2021", confidence=0.8),
    Rule(id="UNIV_DISABLED_SECURITY_001", title="Security Check Disabled in Comment",
         description="Code appears to disable a security check.",
         category="misconfiguration", severity="HIGH",
         pattern=r"""(?:#|//)\s*(?:disabled?|bypass|skip|remove)\s+(?:auth|security|check|validation)""",
         cwe="CWE-1188", owasp="A05:2021", confidence=0.6),
    Rule(id="UNIV_DEBUG_001", title="Debug/Verbose Logging in Production Path",
         description="Debug output in production code may leak sensitive data.",
         category="data_exposure", severity="LOW",
         pattern=r"""(?:console\.log|print|var_dump|dd\(|debug\()\s*\([^)]*(?:password|token|secret|key)""",
         cwe="CWE-532", owasp="A09:2021", confidence=0.6),
]
