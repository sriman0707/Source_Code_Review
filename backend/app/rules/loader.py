"""
Rule Loader — Discovers and aggregates rules from all language modules.
"""
from __future__ import annotations

import logging
from typing import Iterator

from app.rules.base import Rule, RuleMatch
from app.engines.ast_engine import ParsedFile

logger = logging.getLogger(__name__)


class RuleLoader:
    """
    Loads all rules from language-specific modules and
    provides a unified match() interface.
    """

    def __init__(self):
        self._rules: list[Rule] = []
        self._load_all_rules()

    def _load_all_rules(self):
        """Import all rule modules and collect their RULES lists."""
        rule_modules = [
            ("python", "app.rules.python.rules"),
            ("javascript", "app.rules.javascript.rules"),
            ("java", "app.rules.java.rules"),
            ("php", "app.rules.php.rules"),
            ("go", "app.rules.go.rules"),
            ("graphql", "app.rules.graphql.rules"),
            ("universal", "app.rules.universal.rules"),
            ("iac", "app.rules.iac.rules"),
        ]
        for lang, module_path in rule_modules:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                rules = getattr(mod, "RULES", [])
                self._rules.extend(rules)
                logger.info(f"Loaded {len(rules)} rules from {module_path}")
            except ImportError:
                logger.debug(f"Rule module not found: {module_path}")
            except Exception as e:
                logger.warning(f"Error loading rules from {module_path}: {e}")

        logger.info(f"Total rules loaded: {len(self._rules)}")

    def match(self, parsed_file: ParsedFile) -> Iterator[RuleMatch]:
        """Run all applicable rules against a parsed file."""
        for rule in self._rules:
            try:
                for match in rule.match(parsed_file):
                    yield match
            except Exception as e:
                logger.debug(f"Rule {rule.id} failed on {parsed_file.path}: {e}")

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rules_by_language(self, language: str) -> list[Rule]:
        return [r for r in self._rules if not r.languages or language in r.languages]

    def get_rules_by_category(self, category: str) -> list[Rule]:
        return [r for r in self._rules if r.category == category]


# ─── Singleton ────────────────────────────────────────────────────────────────
rule_loader = RuleLoader()
