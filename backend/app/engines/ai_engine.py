"""
AI Reasoning Engine
===================
Uses Google Gemini (or Ollama fallback) to perform expert-level security analysis:

1. Exploit feasibility assessment
2. False positive filtering
3. Attack scenario generation
4. Proof-of-Concept crafting
5. CVSS v3.1 scoring
6. Bug bounty report generation (HackerOne / Bugcrowd format)
7. Remediation advice with secure code examples
"""
from __future__ import annotations

import json
import logging
import re
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class AIAnalysisResult:
    """Result from AI analysis of a security finding."""
    is_valid: bool = True                   # False = likely FP
    confidence: float = 0.8
    exploitability: str = "MEDIUM"          # HIGH, MEDIUM, LOW, NONE
    cvss_score: float = 0.0
    cvss_vector: str = ""
    attack_scenario: str = ""
    proof_of_concept: str = ""
    business_impact: str = ""
    remediation: str = ""
    secure_code_example: str = ""
    references: list[str] = field(default_factory=list)
    bug_bounty_title: str = ""
    bug_bounty_report: str = ""
    estimated_bounty: str = ""
    false_positive_reason: str = ""
    ai_model_used: str = ""
    tokens_used: int = 0


class AIEngine:
    """
    AI-powered security reasoning engine.
    Supports Google Gemini (cloud) and Ollama (local/offline).
    """

    def __init__(self):
        self.provider = settings.ai_provider
        self._gemini_model = None
        self._init_provider()

    def _init_provider(self):
        if self.provider == "gemini" and settings.gemini_api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=settings.gemini_api_key)
                self._gemini_model = genai.GenerativeModel(
                    model_name=settings.gemini_model,
                    generation_config={
                        "temperature": settings.ai_temperature,
                        "max_output_tokens": settings.ai_max_tokens,
                    },
                    system_instruction=self._system_prompt(),
                )
                logger.info(f"AI Engine: Gemini ({settings.gemini_model}) initialized")
            except Exception as e:
                logger.warning(f"Gemini init failed: {e}. Falling back to Ollama.")
                self.provider = "ollama"
        elif self.provider == "ollama":
            logger.info(f"AI Engine: Ollama ({settings.ollama_model}) configured")

    def _system_prompt(self) -> str:
        return """You are an elite Application Security Researcher, Principal Security Engineer, 
and Bug Bounty Hunter. You have 15+ years of experience in:
- Finding and exploiting web vulnerabilities
- Source code security review
- Bug bounty hunting (top 1% on HackerOne, Bugcrowd)
- Secure code development

Your job is to analyze security findings from static analysis tools and:
1. Determine if the finding is a TRUE positive or false positive
2. Assess real-world exploitability
3. Generate realistic attack scenarios and PoC
4. Calculate accurate CVSS v3.1 scores
5. Write professional bug bounty reports

ALWAYS think like an attacker. Never be conservative about severity if exploitation is realistic.
NEVER report false positives — thoroughly analyze the code context.
Always respond with valid JSON only."""

    async def analyze_finding(
        self,
        title: str,
        description: str,
        file_path: str,
        code_snippet: str,
        vulnerability_type: str,
        language: str,
        taint_source: Optional[str] = None,
        taint_sink: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> AIAnalysisResult:
        """
        Perform AI analysis on a security finding.
        Returns enriched analysis with exploitability, PoC, CVSS, etc.
        """
        if self.provider == "none":
            return AIAnalysisResult(ai_model_used="none")

        prompt = self._build_analysis_prompt(
            title=title,
            description=description,
            file_path=file_path,
            code_snippet=code_snippet,
            vulnerability_type=vulnerability_type,
            language=language,
            taint_source=taint_source,
            taint_sink=taint_sink,
            framework=framework,
        )

        try:
            raw_response = await self._call_ai(prompt)
            return self._parse_analysis_response(raw_response)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return AIAnalysisResult(confidence=0.5, ai_model_used=self.provider)

    async def generate_bug_bounty_report(
        self,
        findings: list[dict],
        project_name: str,
        target_url: Optional[str] = None,
    ) -> str:
        """Generate a professional HackerOne-style bug bounty report."""
        if self.provider == "none":
            return ""

        prompt = f"""Generate a professional bug bounty report in HackerOne format for the following findings.

Project: {project_name}
Target: {target_url or "N/A"}

Findings:
{json.dumps(findings[:5], indent=2)}  

Output format (Markdown):
# [Vulnerability Title]

## Summary
[Clear, concise description of the vulnerability]

## Severity
[Critical/High/Medium/Low] — CVSS: [score] ([vector])

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
...

## Proof of Concept
```
[PoC code or request/response]
```

## Impact
[Business impact explanation]

## Affected Component
- File: [path]
- Function: [name]
- Line: [number]

## Root Cause
[Technical explanation]

## Remediation
[Fix recommendation with secure code example]

## References
- [CVE/CWE/OWASP links]
"""
        try:
            return await self._call_ai(prompt)
        except Exception as e:
            logger.error(f"Bug bounty report generation failed: {e}")
            return ""

    async def reduce_false_positives(
        self,
        findings: list[dict],
        code_context: str,
        language: str,
    ) -> list[dict]:
        """
        Batch false positive reduction.
        Returns the same list with 'ai_is_fp' and 'ai_fp_reason' fields added.
        """
        if self.provider == "none" or not findings:
            return findings

        prompt = f"""You are reviewing static analysis findings for false positive reduction.
Language: {language}

Code Context:
```{language}
{code_context[:3000]}
```

Findings to evaluate:
{json.dumps([{{"id": i, "title": f.get("title"), "type": f.get("category"), "line": f.get("line_start")}} for i, f in enumerate(findings[:20])], indent=2)}

For each finding, determine if it is a TRUE positive or FALSE positive.
Consider: framework behavior, sanitization, execution context, business logic.

Respond with JSON array:
[{{"id": 0, "is_fp": false, "confidence": 0.9, "reason": "..."}}]
"""
        try:
            raw = await self._call_ai(prompt)
            evaluations = self._extract_json(raw)
            if isinstance(evaluations, list):
                for evaluation in evaluations:
                    idx = evaluation.get("id", -1)
                    if 0 <= idx < len(findings):
                        findings[idx]["ai_is_fp"] = evaluation.get("is_fp", False)
                        findings[idx]["ai_confidence"] = evaluation.get("confidence", 0.5)
                        findings[idx]["ai_fp_reason"] = evaluation.get("reason", "")
        except Exception as e:
            logger.error(f"FP reduction failed: {e}")

        return findings

    def _build_analysis_prompt(self, **kwargs) -> str:
        return f"""Analyze this security finding as an elite bug bounty hunter and AppSec engineer.

## Finding Details
Title: {kwargs['title']}
Type: {kwargs['vulnerability_type']}
Language: {kwargs['language']}
Framework: {kwargs.get('framework', 'Unknown')}
File: {kwargs['file_path']}

## Description
{kwargs['description']}

## Vulnerable Code
```{kwargs['language']}
{kwargs['code_snippet'][:2000]}
```

## Taint Flow
Source: {kwargs.get('taint_source', 'N/A')}
Sink: {kwargs.get('taint_sink', 'N/A')}

## Your Task
1. Determine if this is a TRUE vulnerability (not a false positive)
2. Assess real-world exploitability
3. Create a realistic attack scenario
4. Write a working proof of concept
5. Calculate CVSS v3.1 score
6. Write a HackerOne-quality bug bounty title
7. Estimate bounty range based on severity and exploitability
8. Provide remediation with secure code example

Respond ONLY with valid JSON (no markdown):
{{
  "is_valid": true,
  "confidence": 0.95,
  "exploitability": "HIGH",
  "false_positive_reason": "",
  "cvss_score": 8.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "attack_scenario": "An unauthenticated attacker...",
  "proof_of_concept": "POST /api/users HTTP/1.1\\nHost: example.com\\n...",
  "business_impact": "Complete database compromise...",
  "remediation": "Use parameterized queries...",
  "secure_code_example": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."],
  "bug_bounty_title": "SQL Injection in /api/search allows full database extraction",
  "estimated_bounty": "$1,000 - $10,000"
}}"""

    async def _call_ai(self, prompt: str) -> str:
        """Route to the configured AI provider."""
        if self.provider == "gemini":
            return await self._call_gemini(prompt)
        elif self.provider == "ollama":
            return await self._call_ollama(prompt)
        return ""

    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API."""
        if not self._gemini_model:
            return ""
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._gemini_model.generate_content(prompt),
        )
        return response.text

    async def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama API."""
        import aiohttp
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": settings.ai_temperature,
                "num_predict": settings.ai_max_tokens,
            },
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{settings.ollama_base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                data = await resp.json()
                return data.get("response", "")

    def _parse_analysis_response(self, raw: str) -> AIAnalysisResult:
        """Parse AI JSON response into AIAnalysisResult."""
        data = self._extract_json(raw)
        if not data or not isinstance(data, dict):
            return AIAnalysisResult(confidence=0.4, ai_model_used=self.provider)

        return AIAnalysisResult(
            is_valid=data.get("is_valid", True),
            confidence=float(data.get("confidence", 0.7)),
            exploitability=data.get("exploitability", "MEDIUM"),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cvss_vector=data.get("cvss_vector", ""),
            attack_scenario=data.get("attack_scenario", ""),
            proof_of_concept=data.get("proof_of_concept", ""),
            business_impact=data.get("business_impact", ""),
            remediation=data.get("remediation", ""),
            secure_code_example=data.get("secure_code_example", ""),
            references=data.get("references", []),
            bug_bounty_title=data.get("bug_bounty_title", ""),
            estimated_bounty=data.get("estimated_bounty", ""),
            false_positive_reason=data.get("false_positive_reason", ""),
            ai_model_used=self.provider,
        )

    def _extract_json(self, text: str):
        """Extract JSON from AI response text."""
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try extracting from markdown code block
        m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        # Try finding first { } or [ ] block
        for pattern in [r"\{[\s\S]+\}", r"\[[\s\S]+\]"]:
            m = re.search(pattern, text)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
        return None


# ─── Singleton ────────────────────────────────────────────────────────────────
ai_engine = AIEngine()
