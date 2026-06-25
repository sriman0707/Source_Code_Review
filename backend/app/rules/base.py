"""
Security Rules Base Classes
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Pattern
from app.engines.ast_engine import ParsedFile


@dataclass
class RuleMatch:
    """A single rule match result."""
    rule_id: str
    title: str
    description: str
    category: str
    severity: str
    line_start: int
    line_end: int
    col_start: int = 0
    matched_text: str = ""
    cwe: str = ""
    owasp: str = ""
    confidence: float = 0.8
    references: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class Rule:
    """
    A single SAST rule with regex pattern matching.
    Rules can target specific languages or be universal.
    """
    id: str
    title: str
    description: str
    category: str
    severity: str                          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    pattern: str                           # Regex pattern
    languages: list[str] = field(default_factory=list)  # Empty = all languages
    cwe: str = ""
    owasp: str = ""
    confidence: float = 0.8
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    negative_patterns: list[str] = field(default_factory=list)  # FP reduction patterns
    _compiled: Optional[Pattern] = field(default=None, repr=False)
    _neg_compiled: list[Pattern] = field(default_factory=list, repr=False)

    def compile(self):
        """Compile the regex pattern."""
        if not self._compiled:
            self._compiled = re.compile(self.pattern, re.MULTILINE | re.IGNORECASE)
        if not self._neg_compiled:
            self._neg_compiled = [
                re.compile(p, re.IGNORECASE) for p in self.negative_patterns
            ]
        return self

    def match(self, parsed_file: ParsedFile) -> list[RuleMatch]:
        """Run this rule against a parsed file. Returns list of matches."""
        # Language filter
        if self.languages and parsed_file.language not in self.languages:
            return []

        self.compile()
        matches = []
        content = parsed_file.content
        lines = parsed_file.lines

        for m in self._compiled.finditer(content):
            matched_text = m.group(0)

            # Apply negative patterns (FP reduction)
            # Check context window (±3 lines) for FP indicators
            line_no = content[:m.start()].count("\n") + 1
            ctx_start = max(0, line_no - 4)
            ctx_end = min(len(lines), line_no + 3)
            context = "\n".join(lines[ctx_start:ctx_end])

            fp_detected = any(
                neg.search(context) for neg in self._neg_compiled
            )
            if fp_detected:
                continue

            # Skip comments
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*", "/*", "<!--", "'", '"')):
                # Check if it's actually a comment
                comment_starters = ("#", "//", "/*", "*", "<!--", "'''", '"""')
                if any(stripped.startswith(cs) for cs in comment_starters):
                    continue

            end_line_no = content[:m.end()].count("\n") + 1

            matches.append(RuleMatch(
                rule_id=self.id,
                title=self.title,
                description=self.description,
                category=self.category,
                severity=self.severity,
                line_start=line_no,
                line_end=end_line_no,
                col_start=m.start() - content.rfind("\n", 0, m.start()) - 1,
                matched_text=matched_text[:200],
                cwe=self.cwe,
                owasp=self.owasp,
                confidence=self.confidence,
                references=self.references,
                remediation=self.remediation,
            ))

        return matches
