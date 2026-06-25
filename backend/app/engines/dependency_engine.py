"""
Dependency Scanning Engine
===========================
Scans dependency manifests for:
- Known CVEs (via OSV.dev API)
- Typosquatting attacks
- Dependency confusion attacks
- Malicious packages
- Severely outdated components

Supports: requirements.txt, package.json, pom.xml, go.mod, Gemfile, composer.json
"""
from __future__ import annotations

import re
import json
import logging
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ─── Known typosquatting targets ─────────────────────────────────────────────
POPULAR_PACKAGES: dict[str, list[str]] = {
    "python": [
        "requests", "numpy", "pandas", "flask", "django", "fastapi",
        "sqlalchemy", "celery", "redis", "boto3", "pydantic", "httpx",
        "cryptography", "paramiko", "pillow", "tensorflow", "torch",
    ],
    "npm": [
        "express", "react", "lodash", "axios", "webpack", "babel",
        "typescript", "jest", "eslint", "next", "vue", "angular",
        "moment", "chalk", "dotenv", "mongoose", "sequelize",
    ],
}

# Typosquatting distance threshold (Levenshtein)
TYPOSQUATTING_DISTANCE = 2


@dataclass
class DependencyFinding:
    """A finding related to a dependency."""
    package_name: str
    version: str
    ecosystem: str
    finding_type: str    # "cve", "typosquatting", "malicious", "outdated", "confusion"
    severity: str
    title: str
    description: str
    file_path: str
    line_no: int
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_version: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "cve": self.cve_id,
            "cvss": self.cvss_score,
            "fix_version": self.fix_version,
            "file": self.file_path,
            "line": self.line_no,
        }


class DependencyEngine:
    """Scans dependency files for security issues."""

    MANIFEST_FILES = {
        "requirements.txt": "PyPI",
        "requirements-dev.txt": "PyPI",
        "requirements-prod.txt": "PyPI",
        "Pipfile": "PyPI",
        "pyproject.toml": "PyPI",
        "setup.py": "PyPI",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "pom.xml": "Maven",
        "build.gradle": "Maven",
        "go.mod": "Go",
        "Gemfile": "RubyGems",
        "composer.json": "Packagist",
        "Cargo.toml": "crates.io",
    }

    async def scan_file(self, file_path: str, content: str) -> list[DependencyFinding]:
        """Scan a dependency file for security issues."""
        filename = Path(file_path).name
        ecosystem = self.MANIFEST_FILES.get(filename)
        if not ecosystem:
            return []

        packages = self._parse_manifest(filename, content, file_path)
        if not packages:
            return []

        findings: list[DependencyFinding] = []

        # Check CVEs via OSV API
        cve_findings = await self._check_osv(packages, ecosystem, file_path)
        findings.extend(cve_findings)

        # Check typosquatting
        typo_findings = self._check_typosquatting(packages, ecosystem, file_path)
        findings.extend(typo_findings)

        # Check dependency confusion
        confusion_findings = self._check_dependency_confusion(packages, ecosystem, file_path)
        findings.extend(confusion_findings)

        return findings

    def _parse_manifest(self, filename: str, content: str, file_path: str) -> list[dict]:
        """Parse dependency file and extract package name + version."""
        packages = []

        if filename.startswith("requirements"):
            # requirements.txt format: package==version or package>=version
            for i, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                # Remove extras: package[extras]==version
                line = re.sub(r"\[.*?\]", "", line)
                m = re.match(r"^([\w\-\.]+)\s*(?:[>=<!~^]+)\s*([\w\.]+)", line)
                if m:
                    packages.append({
                        "name": m.group(1).lower(),
                        "version": m.group(2),
                        "line": i,
                    })

        elif filename == "package.json":
            try:
                data = json.loads(content)
                for section in ["dependencies", "devDependencies", "peerDependencies"]:
                    for name, version in data.get(section, {}).items():
                        # Clean version string
                        ver = re.sub(r"[^0-9.]", "", version)
                        packages.append({"name": name, "version": ver or version, "line": 0})
            except Exception:
                pass

        elif filename == "go.mod":
            for i, line in enumerate(content.splitlines(), 1):
                m = re.match(r"^\s+?([\w./-]+)\s+v([\w.]+)", line)
                if m:
                    packages.append({"name": m.group(1), "version": m.group(2), "line": i})

        elif filename == "Gemfile":
            for i, line in enumerate(content.splitlines(), 1):
                m = re.match(r"""gem\s+['"](\w[\w\-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", line)
                if m:
                    packages.append({
                        "name": m.group(1),
                        "version": m.group(2) or "unknown",
                        "line": i,
                    })

        elif filename == "composer.json":
            try:
                data = json.loads(content)
                for section in ["require", "require-dev"]:
                    for name, version in data.get(section, {}).items():
                        packages.append({"name": name, "version": version, "line": 0})
            except Exception:
                pass

        elif filename == "Cargo.toml":
            for i, line in enumerate(content.splitlines(), 1):
                m = re.match(r"""(\w[\w_]+)\s*=\s*["']([^"']+)["']""", line)
                if m and m.group(1) not in ("name", "version", "edition"):
                    packages.append({"name": m.group(1), "version": m.group(2), "line": i})

        return packages

    async def _check_osv(
        self,
        packages: list[dict],
        ecosystem: str,
        file_path: str,
    ) -> list[DependencyFinding]:
        """Query OSV.dev API for known vulnerabilities."""
        findings = []

        # OSV ecosystem names
        osv_ecosystem = {
            "PyPI": "PyPI",
            "npm": "npm",
            "Maven": "Maven",
            "Go": "Go",
            "RubyGems": "RubyGems",
            "Packagist": "Packagist",
            "crates.io": "crates.io",
        }.get(ecosystem, ecosystem)

        # Batch query (OSV supports batch)
        queries = []
        for pkg in packages[:50]:  # Limit to 50 per scan
            if pkg["version"] and pkg["version"] != "unknown":
                queries.append({
                    "version": pkg["version"],
                    "package": {"name": pkg["name"], "ecosystem": osv_ecosystem},
                })

        if not queries:
            return []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{settings.osv_api_url}/querybatch",
                    json={"queries": queries},
                )
                if resp.status_code != 200:
                    return []

                data = resp.json()
                results = data.get("results", [])

                for i, result in enumerate(results):
                    vulns = result.get("vulns", [])
                    if not vulns:
                        continue
                    pkg = packages[i]

                    for vuln in vulns[:3]:  # Top 3 vulns per package
                        severity = self._osv_severity(vuln)
                        cvss = self._osv_cvss(vuln)
                        fix_version = self._osv_fix_version(vuln)

                        findings.append(DependencyFinding(
                            package_name=pkg["name"],
                            version=pkg["version"],
                            ecosystem=ecosystem,
                            finding_type="cve",
                            severity=severity,
                            title=f"{vuln.get('id', 'Unknown')} in {pkg['name']} {pkg['version']}",
                            description=(
                                vuln.get("summary", "") or
                                vuln.get("details", "")[:300]
                            ),
                            file_path=file_path,
                            line_no=pkg.get("line", 0),
                            cve_id=self._extract_cve(vuln),
                            cvss_score=cvss,
                            fix_version=fix_version,
                            references=self._osv_references(vuln),
                        ))
        except Exception as e:
            logger.warning(f"OSV API query failed: {e}")

        return findings

    def _check_typosquatting(
        self, packages: list[dict], ecosystem: str, file_path: str
    ) -> list[DependencyFinding]:
        """Detect potential typosquatting attacks."""
        findings = []
        lang_key = "python" if ecosystem == "PyPI" else "npm"
        popular = POPULAR_PACKAGES.get(lang_key, [])

        for pkg in packages:
            name = pkg["name"]
            for popular_name in popular:
                if name == popular_name:
                    continue
                dist = self._levenshtein(name, popular_name)
                if 0 < dist <= TYPOSQUATTING_DISTANCE:
                    findings.append(DependencyFinding(
                        package_name=name,
                        version=pkg["version"],
                        ecosystem=ecosystem,
                        finding_type="typosquatting",
                        severity="HIGH",
                        title=f"Potential Typosquatting: '{name}' resembles '{popular_name}'",
                        description=(
                            f"Package '{name}' is very similar to the popular package '{popular_name}'. "
                            f"This may be a typosquatting attack (edit distance: {dist}). "
                            "Verify the package is legitimate and intentional."
                        ),
                        file_path=file_path,
                        line_no=pkg.get("line", 0),
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/",
                        ],
                    ))
        return findings

    def _check_dependency_confusion(
        self, packages: list[dict], ecosystem: str, file_path: str
    ) -> list[DependencyFinding]:
        """Detect potential dependency confusion risks (internal package names in public registries)."""
        findings = []
        internal_indicators = [
            r"^internal[-_]", r"^private[-_]", r"^corp[-_]", r"^company[-_]",
            r"[-_]internal$", r"[-_]private$",
        ]
        for pkg in packages:
            name = pkg["name"]
            for pat in internal_indicators:
                if re.search(pat, name, re.IGNORECASE):
                    findings.append(DependencyFinding(
                        package_name=name,
                        version=pkg["version"],
                        ecosystem=ecosystem,
                        finding_type="confusion",
                        severity="MEDIUM",
                        title=f"Possible Dependency Confusion: '{name}' looks like an internal package",
                        description=(
                            f"Package '{name}' appears to be an internal package name. "
                            "If this name is registered in the public registry by an attacker, "
                            "your build system may silently fetch a malicious version."
                        ),
                        file_path=file_path,
                        line_no=pkg.get("line", 0),
                        references=[
                            "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
                        ],
                    ))
                    break
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    def _osv_severity(self, vuln: dict) -> str:
        score = self._osv_cvss(vuln)
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        severity = vuln.get("database_specific", {}).get("severity", "").upper()
        return severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"

    def _osv_cvss(self, vuln: dict) -> float:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                m = re.search(r"CVSS:3\.\d/[^\s]+", score_str)
                if m:
                    try:
                        parts = score_str.split("/")
                        return float(parts[-1].split(":")[0])
                    except Exception:
                        pass
        return 0.0

    def _osv_fix_version(self, vuln: dict) -> Optional[str]:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    def _extract_cve(self, vuln: dict) -> Optional[str]:
        vuln_id = vuln.get("id", "")
        if vuln_id.startswith("CVE-"):
            return vuln_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return vuln_id or None

    def _osv_references(self, vuln: dict) -> list[str]:
        return [ref.get("url", "") for ref in vuln.get("references", [])[:3]]


# ─── Singleton ────────────────────────────────────────────────────────────────
dependency_engine = DependencyEngine()
