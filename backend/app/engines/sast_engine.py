"""
SAST Engine — Main Orchestrator
=================================
Coordinates all analysis engines for a complete security scan:

1. File discovery and language detection
2. AST parsing
3. Taint analysis
4. Rule-based SAST
5. Secret detection
6. Business logic analysis
7. Dependency scanning
8. IaC scanning
9. AI reasoning (Deep/Bug Bounty profiles)
10. Finding deduplication and scoring
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from app.engines.ast_engine import ast_engine, ParsedFile
from app.engines.taint_engine import taint_engine, TaintFlow
from app.engines.secret_engine import secret_engine, SecretFinding
from app.engines.dependency_engine import dependency_engine
from app.engines.business_logic import business_logic_engine
from app.engines.ai_engine import ai_engine
from app.rules.loader import rule_loader
from app.config import settings

logger = logging.getLogger(__name__)

# ─── Files to skip ───────────────────────────────────────────────────────────
SKIP_DIRS = {
    "node_modules", "__pycache__", ".git", ".svn", ".hg",
    "dist", "build", ".next", ".nuxt", "vendor", "venv",
    ".venv", ".tox", "coverage", ".pytest_cache", "target",
    ".gradle", ".m2", "bin", "obj",
}
SKIP_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock", ".sum",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".mp4", ".mp3", ".avi", ".mov",
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file

# Severity → numeric score for sorting
SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10,
}


@dataclass
class ScanFinding:
    """Unified finding structure from any engine."""
    rule_id: str
    title: str
    description: str
    category: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 0
    code_snippet: str = ""
    affected_function: Optional[str] = None
    affected_class: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    detection_method: str = "sast"
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None
    taint_path: Optional[list] = None
    ai_confidence: float = 0.8
    is_false_positive: bool = False
    false_positive_reason: str = ""
    # AI-enriched fields
    ai_analyzed: bool = False
    exploitability: Optional[str] = None
    attack_scenario: str = ""
    proof_of_concept: str = ""
    business_impact: str = ""
    ai_remediation: str = ""
    secure_code_example: str = ""
    references: list[str] = field(default_factory=list)
    bug_bounty_title: str = ""
    bug_bounty_report: str = ""
    estimated_bounty: str = ""

    @property
    def fingerprint(self) -> str:
        """Unique fingerprint for deduplication."""
        key = f"{self.rule_id}:{self.file_path}:{self.line_start}"
        return hashlib.md5(key.encode()).hexdigest()


@dataclass
class ScanResult:
    """Complete result of a scan run."""
    scan_id: str
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: list[ScanFinding] = field(default_factory=list)
    detected_languages: dict = field(default_factory=dict)
    frameworks_detected: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def risk_score(self) -> int:
        """0-100 risk score based on finding severity distribution."""
        counts = self.by_severity
        score = (
            counts["CRITICAL"] * 25 +
            counts["HIGH"] * 10 +
            counts["MEDIUM"] * 3 +
            counts["LOW"] * 1
        )
        return min(100, score)


class SASTEngine:
    """
    Main SAST orchestrator.
    Coordinates all sub-engines and produces a unified ScanResult.
    """

    async def scan_directory(
        self,
        scan_id: str,
        directory: str,
        profile: str = "standard",
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> ScanResult:
        """
        Scan a directory of source code files.

        Profiles:
          quick        — secret + pattern rules only
          standard     — full SAST + taint + secrets + business logic
          deep         — standard + AI analysis for HIGH+ findings
          bug_bounty   — deep + PoC generation + full bug bounty reports
        """
        result = ScanResult(scan_id=scan_id)

        # ── Phase 1: File Discovery ──────────────────────────────────────────
        if progress_callback:
            progress_callback(5, "file_discovery")

        files = list(self._discover_files(directory))
        result.files_scanned = len(files)
        logger.info(f"[{scan_id}] Discovered {len(files)} files")

        if not files:
            return result

        # Detect languages
        for fp in files:
            lang = ast_engine.detect_language(fp)
            if lang:
                result.detected_languages[lang] = result.detected_languages.get(lang, 0) + 1

        # ── Phase 2: Parse Files ─────────────────────────────────────────────
        if progress_callback:
            progress_callback(15, "parsing")

        parsed_files: list[ParsedFile] = []
        for fp in files:
            try:
                content = self._read_file(fp)
                if content is None:
                    continue
                result.lines_scanned += content.count("\n") + 1
                pf = ast_engine.parse_file(fp, content)
                parsed_files.append(pf)
            except Exception as e:
                logger.warning(f"Parse error {fp}: {e}")

        # ── Phase 3: Secret Detection ─────────────────────────────────────────
        if progress_callback:
            progress_callback(25, "secret_detection")

        secret_findings = await self._run_secret_detection(parsed_files)
        result.findings.extend(secret_findings)

        # ── Phase 4: Dependency Scanning ──────────────────────────────────────
        if progress_callback:
            progress_callback(35, "dependency_scanning")

        dep_findings = await self._run_dependency_scanning(parsed_files)
        result.findings.extend(dep_findings)

        # Quick profile stops here
        if profile == "quick":
            result.findings = self._deduplicate(result.findings)
            return result

        # ── Phase 5: SAST Rules ───────────────────────────────────────────────
        if progress_callback:
            progress_callback(45, "sast_rules")

        rule_findings = await self._run_rules(parsed_files)
        result.findings.extend(rule_findings)

        # ── Phase 6: Taint Analysis ───────────────────────────────────────────
        if progress_callback:
            progress_callback(60, "taint_analysis")

        taint_findings = await self._run_taint_analysis(parsed_files)
        result.findings.extend(taint_findings)

        # ── Phase 7: Business Logic ───────────────────────────────────────────
        if progress_callback:
            progress_callback(70, "business_logic")

        bl_findings = await self._run_business_logic(parsed_files)
        result.findings.extend(bl_findings)

        # Dedup before AI analysis
        result.findings = self._deduplicate(result.findings)

        # ── Phase 8: AI Analysis (Deep/Bug Bounty profiles) ───────────────────
        if profile in ("deep", "bug_bounty") and settings.ai_provider != "none":
            if progress_callback:
                progress_callback(80, "ai_analysis")

            result.findings = await self._run_ai_analysis(
                result.findings,
                parsed_files,
                profile,
            )

        # ── Phase 9: Detect Frameworks ────────────────────────────────────────
        result.frameworks_detected = self._detect_frameworks(parsed_files)

        # ── Final Sort ────────────────────────────────────────────────────────
        result.findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity, 0),
            reverse=True,
        )

        if progress_callback:
            progress_callback(100, "complete")

        logger.info(
            f"[{scan_id}] Scan complete: {result.total_findings} findings "
            f"({result.by_severity})"
        )
        return result

    async def scan_file_content(
        self,
        scan_id: str,
        file_path: str,
        content: str,
        profile: str = "standard",
    ) -> ScanResult:
        """Scan a single file's content."""
        result = ScanResult(scan_id=scan_id, files_scanned=1)
        result.lines_scanned = content.count("\n") + 1

        pf = ast_engine.parse_file(file_path, content)
        parsed_files = [pf]

        # Secret detection
        result.findings.extend(await self._run_secret_detection(parsed_files))
        # Rules
        result.findings.extend(await self._run_rules(parsed_files))
        # Taint
        result.findings.extend(await self._run_taint_analysis(parsed_files))
        # Business logic
        result.findings.extend(await self._run_business_logic(parsed_files))
        # Dependency check if manifest
        result.findings.extend(await self._run_dependency_scanning(parsed_files))

        if profile in ("deep", "bug_bounty") and settings.ai_provider != "none":
            result.findings = await self._run_ai_analysis(result.findings, parsed_files, profile)

        result.findings = self._deduplicate(result.findings)
        result.findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity, 0), reverse=True
        )
        return result

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _discover_files(self, directory: str):
        """Walk directory and yield scannable file paths."""
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories (in-place modification)
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not d.startswith(".")
            ]
            for filename in files:
                fp = os.path.join(root, filename)
                p = Path(fp)
                # Skip by extension
                if any(p.name.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue
                # Skip large files
                try:
                    if p.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield fp

    def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content, handling encoding gracefully."""
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                with open(file_path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return None

    async def _run_secret_detection(self, parsed_files: list[ParsedFile]) -> list[ScanFinding]:
        findings = []
        for pf in parsed_files:
            for sf in secret_engine.scan_file(pf.path, pf.content):
                findings.append(ScanFinding(
                    rule_id=sf.rule_id,
                    title=sf.rule_name,
                    description=sf.description,
                    category="secret",
                    severity=sf.severity,
                    file_path=sf.file_path,
                    line_start=sf.line_no,
                    line_end=sf.line_no,
                    code_snippet=sf.context_line,
                    cwe_id=sf.cwe,
                    detection_method="secret_detection",
                    ai_confidence=0.9,
                ))
        return findings

    async def _run_dependency_scanning(self, parsed_files: list[ParsedFile]) -> list[ScanFinding]:
        findings = []
        dep_filenames = set(dependency_engine.MANIFEST_FILES.keys())
        for pf in parsed_files:
            if Path(pf.path).name in dep_filenames:
                for df in await dependency_engine.scan_file(pf.path, pf.content):
                    severity_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                                    "MEDIUM": "MEDIUM", "LOW": "LOW"}
                    findings.append(ScanFinding(
                        rule_id=f"DEP_{df.finding_type.upper()}",
                        title=df.title,
                        description=df.description,
                        category="dependency",
                        severity=severity_map.get(df.severity, "MEDIUM"),
                        file_path=df.file_path,
                        line_start=df.line_no,
                        line_end=df.line_no,
                        cwe_id="CWE-1035",
                        detection_method="dependency_scanning",
                        ai_confidence=0.95,
                        references=df.references,
                    ))
        return findings

    async def _run_rules(self, parsed_files: list[ParsedFile]) -> list[ScanFinding]:
        """Run loaded SAST rules against parsed files."""
        findings = []
        for pf in parsed_files:
            for match in rule_loader.match(pf):
                findings.append(ScanFinding(
                    rule_id=match.rule_id,
                    title=match.title,
                    description=match.description,
                    category=match.category,
                    severity=match.severity,
                    file_path=pf.path,
                    line_start=match.line_start,
                    line_end=match.line_end,
                    col_start=match.col_start,
                    code_snippet=pf.get_snippet(match.line_start, match.line_end),
                    cwe_id=match.cwe,
                    owasp_category=match.owasp,
                    detection_method="sast_rule",
                    ai_confidence=match.confidence,
                    references=match.references,
                ))
        return findings

    async def _run_taint_analysis(self, parsed_files: list[ParsedFile]) -> list[ScanFinding]:
        """Run taint tracking engine."""
        findings = []
        for pf in parsed_files:
            for flow in taint_engine.analyze(pf):
                vuln_map = {
                    "sql_injection": ("injection", "CWE-89", "A03:2021"),
                    "command_injection": ("injection", "CWE-78", "A03:2021"),
                    "xss": ("xss", "CWE-79", "A03:2021"),
                    "ssrf": ("ssrf", "CWE-918", "A10:2021"),
                    "path_traversal": ("path_traversal", "CWE-22", "A01:2021"),
                    "ssti": ("ssti", "CWE-94", "A03:2021"),
                    "deserialization": ("injection", "CWE-502", "A08:2021"),
                    "ldap_injection": ("injection", "CWE-90", "A03:2021"),
                    "xxe": ("xxe", "CWE-611", "A05:2021"),
                    "nosql_injection": ("injection", "CWE-943", "A03:2021"),
                    "prototype_pollution": ("injection", "CWE-1321", "A03:2021"),
                }
                cat, cwe, owasp = vuln_map.get(
                    flow.vulnerability_type,
                    ("injection", "CWE-20", "A03:2021"),
                )
                title_map = {
                    "sql_injection": "SQL Injection — Tainted User Input Reaches Database Query",
                    "command_injection": "Command Injection — User Input Reaches Shell Execution",
                    "xss": "Cross-Site Scripting (XSS) — Unsanitized Input in Response",
                    "ssrf": "SSRF — User-Controlled URL in Server-Side Request",
                    "path_traversal": "Path Traversal — User Input in File System Operation",
                    "ssti": "Server-Side Template Injection — User Input in Template",
                    "deserialization": "Insecure Deserialization — Untrusted Data Deserialized",
                    "nosql_injection": "NoSQL Injection — Unsanitized Input in NoSQL Query",
                    "prototype_pollution": "Prototype Pollution — User Input Merged into Object",
                }
                severity_map = {
                    "sql_injection": "HIGH",
                    "command_injection": "CRITICAL",
                    "xss": "HIGH",
                    "ssrf": "HIGH",
                    "path_traversal": "HIGH",
                    "ssti": "CRITICAL",
                    "deserialization": "CRITICAL",
                    "nosql_injection": "HIGH",
                    "prototype_pollution": "MEDIUM",
                }
                findings.append(ScanFinding(
                    rule_id=f"TAINT_{flow.vulnerability_type.upper()}",
                    title=title_map.get(flow.vulnerability_type, f"Taint: {flow.vulnerability_type}"),
                    description=(
                        f"User-controlled data flows from {flow.source.code[:100]} "
                        f"to dangerous sink {flow.sink.code[:100]} without sanitization."
                    ),
                    category=cat,
                    severity=severity_map.get(flow.vulnerability_type, "HIGH"),
                    file_path=pf.path,
                    line_start=flow.source.line,
                    line_end=flow.sink.line,
                    code_snippet=pf.get_snippet(flow.source.line, flow.sink.line),
                    cwe_id=cwe,
                    owasp_category=owasp,
                    detection_method="taint_analysis",
                    taint_source=flow.source.code,
                    taint_sink=flow.sink.code,
                    ai_confidence=flow.confidence,
                ))
        return findings

    async def _run_business_logic(self, parsed_files: list[ParsedFile]) -> list[ScanFinding]:
        """Run business logic engine."""
        findings = []
        for pf in parsed_files:
            for blf in business_logic_engine.analyze(pf):
                findings.append(ScanFinding(
                    rule_id=blf.rule_id,
                    title=blf.title,
                    description=blf.description,
                    category=blf.category,
                    severity=blf.severity,
                    file_path=blf.file_path,
                    line_start=blf.line_start,
                    line_end=blf.line_end,
                    code_snippet=blf.code_snippet,
                    cwe_id=blf.cwe,
                    owasp_category=blf.owasp,
                    detection_method="business_logic",
                    ai_confidence=blf.confidence,
                    attack_scenario=blf.attack_scenario,
                    references=blf.references,
                ))
        return findings

    async def _run_ai_analysis(
        self,
        findings: list[ScanFinding],
        parsed_files: list[ParsedFile],
        profile: str,
    ) -> list[ScanFinding]:
        """Enrich high-severity findings with AI analysis."""
        # Only analyze HIGH+ findings (or all for bug_bounty)
        min_severity = "HIGH" if profile == "deep" else "MEDIUM"
        threshold = SEVERITY_SCORES.get(min_severity, 0)

        # Build file content lookup
        file_contents: dict[str, ParsedFile] = {pf.path: pf for pf in parsed_files}

        enriched = []
        # Limit AI calls to avoid token/cost explosion
        ai_count = 0
        MAX_AI_CALLS = 20 if profile == "bug_bounty" else 10

        for finding in findings:
            if (
                SEVERITY_SCORES.get(finding.severity, 0) >= threshold
                and ai_count < MAX_AI_CALLS
                and not finding.ai_analyzed
            ):
                pf = file_contents.get(finding.file_path)
                code_snippet = finding.code_snippet
                if pf and not code_snippet:
                    code_snippet = pf.get_snippet(finding.line_start, finding.line_end)

                try:
                    result = await ai_engine.analyze_finding(
                        title=finding.title,
                        description=finding.description,
                        file_path=finding.file_path,
                        code_snippet=code_snippet,
                        vulnerability_type=finding.category,
                        language=pf.language if pf else "unknown",
                        taint_source=finding.taint_source,
                        taint_sink=finding.taint_sink,
                    )

                    if not result.is_valid:
                        finding.is_false_positive = True
                        finding.false_positive_reason = result.false_positive_reason
                    else:
                        finding.ai_analyzed = True
                        finding.ai_confidence = result.confidence
                        finding.exploitability = result.exploitability
                        finding.cvss_score = result.cvss_score
                        finding.cvss_vector = result.cvss_vector
                        finding.attack_scenario = result.attack_scenario
                        finding.proof_of_concept = result.proof_of_concept
                        finding.business_impact = result.business_impact
                        finding.ai_remediation = result.remediation
                        finding.secure_code_example = result.secure_code_example
                        finding.references = result.references
                        if profile == "bug_bounty":
                            finding.bug_bounty_title = result.bug_bounty_title
                            finding.estimated_bounty = result.estimated_bounty

                    ai_count += 1
                except Exception as e:
                    logger.warning(f"AI analysis failed for {finding.rule_id}: {e}")

            enriched.append(finding)

        # Filter confirmed FPs
        return [f for f in enriched if not f.is_false_positive]

    def _deduplicate(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove duplicate findings by fingerprint."""
        seen: set[str] = set()
        unique = []
        for f in findings:
            fp = f.fingerprint
            if fp not in seen:
                seen.add(fp)
                unique.append(f)
        return unique

    def _detect_frameworks(self, parsed_files: list[ParsedFile]) -> list[str]:
        """Detect frameworks from import statements and file patterns."""
        frameworks = set()
        all_imports = []
        for pf in parsed_files:
            all_imports.extend([n.text for n in pf.imports])

        import_text = "\n".join(all_imports).lower()

        framework_signals = {
            "Flask": ["from flask", "import flask"],
            "Django": ["from django", "import django"],
            "FastAPI": ["from fastapi", "import fastapi"],
            "Express": ["require('express')", "from 'express'"],
            "NestJS": ["@nestjs/", "@Injectable"],
            "React": ["from 'react'", "import react"],
            "NextJS": ["from 'next'", "next/app"],
            "Vue": ["from 'vue'", "import vue"],
            "Angular": ["@angular/", "NgModule"],
            "Spring Boot": ["springframework", "spring-boot"],
            "Laravel": ["laravel\\", "illuminate\\"],
            "Rails": ["require 'rails'", "ActionController"],
            "Gin": ['"github.com/gin-gonic/gin"'],
            "Echo": ['"github.com/labstack/echo"'],
        }
        for fw, signals in framework_signals.items():
            if any(s in import_text for s in signals):
                frameworks.add(fw)

        # Also check file names
        for pf in parsed_files:
            name = Path(pf.path).name.lower()
            if name in ("manage.py", "wsgi.py", "asgi.py"):
                frameworks.add("Django")
            elif name == "app.py":
                if "flask" in pf.content.lower():
                    frameworks.add("Flask")
            elif name == "next.config.js":
                frameworks.add("NextJS")

        return list(frameworks)


# ─── Singleton ────────────────────────────────────────────────────────────────
sast_engine = SASTEngine()
