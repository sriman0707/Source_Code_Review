"""
AST Engine — Multi-language source code parsing using Tree-sitter.

Parses source files into a normalized Abstract Syntax Tree representation.
Supports: Python, JavaScript, TypeScript, Java, PHP, Go, Rust, Ruby, C#, Dart.

The engine produces normalized node objects that downstream engines
(taint, CFG, SAST rule matching) consume without caring about language specifics.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Language → file extension mapping ───────────────────────────────────────
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python":     [".py"],
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java":       [".java"],
    "php":        [".php"],
    "go":         [".go"],
    "rust":       [".rs"],
    "ruby":       [".rb"],
    "csharp":     [".cs"],
    "kotlin":     [".kt", ".kts"],
    "swift":      [".swift"],
    "dart":       [".dart"],
    "solidity":   [".sol"],
    "yaml":       [".yml", ".yaml"],
    "json":       [".json"],
    "terraform":  [".tf"],
    "dockerfile": ["Dockerfile", ".dockerfile"],
}

EXT_TO_LANGUAGE: dict[str, str] = {}
for lang, exts in LANGUAGE_EXTENSIONS.items():
    for ext in exts:
        EXT_TO_LANGUAGE[ext] = lang


@dataclass
class ASTNode:
    """Normalized AST node usable across all language parsers."""
    node_type: str                          # e.g. "function_definition", "call_expression"
    text: str                               # Raw source text of this node
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    language: str
    children: list["ASTNode"] = field(default_factory=list)
    parent: Optional["ASTNode"] = None
    metadata: dict = field(default_factory=dict)  # Language-specific extras

    @property
    def location(self) -> str:
        return f"{self.start_line}:{self.start_col}"


@dataclass
class ParsedFile:
    """Result of parsing a single source file."""
    path: str
    language: str
    content: str
    lines: list[str]
    root: Optional[ASTNode]
    functions: list[ASTNode] = field(default_factory=list)
    classes: list[ASTNode] = field(default_factory=list)
    imports: list[ASTNode] = field(default_factory=list)
    calls: list[ASTNode] = field(default_factory=list)
    assignments: list[ASTNode] = field(default_factory=list)
    string_literals: list[ASTNode] = field(default_factory=list)
    comments: list[ASTNode] = field(default_factory=list)
    parse_error: Optional[str] = None

    def get_line(self, line_no: int) -> str:
        """Get source line (1-indexed)."""
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1]
        return ""

    def get_snippet(self, start: int, end: int, context: int = 2) -> str:
        """Get code snippet with surrounding context lines."""
        s = max(1, start - context)
        e = min(len(self.lines), end + context)
        snippet_lines = []
        for i in range(s, e + 1):
            marker = ">>> " if start <= i <= end else "    "
            snippet_lines.append(f"{marker}{i:4d} | {self.lines[i-1]}")
        return "\n".join(snippet_lines)


class ASTEngine:
    """
    Multi-language AST parser.
    Uses tree-sitter when available, falls back to regex-based extraction.
    """

    def __init__(self):
        self._parsers: dict[str, object] = {}
        self._init_parsers()

    def _init_parsers(self):
        """Try to initialize tree-sitter parsers for each supported language."""
        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language, Parser
            PY_LANGUAGE = Language(tspython.language())
            parser = Parser(PY_LANGUAGE)
            self._parsers["python"] = parser
            logger.info("tree-sitter: Python parser loaded")
        except Exception as e:
            logger.warning(f"tree-sitter Python parser unavailable: {e}")

        try:
            import tree_sitter_javascript as tsjs
            from tree_sitter import Language, Parser
            JS_LANGUAGE = Language(tsjs.language())
            parser = Parser(JS_LANGUAGE)
            self._parsers["javascript"] = parser
            logger.info("tree-sitter: JavaScript parser loaded")
        except Exception as e:
            logger.warning(f"tree-sitter JS parser unavailable: {e}")

        try:
            import tree_sitter_java as tsjava
            from tree_sitter import Language, Parser
            JAVA_LANGUAGE = Language(tsjava.language())
            parser = Parser(JAVA_LANGUAGE)
            self._parsers["java"] = parser
            logger.info("tree-sitter: Java parser loaded")
        except Exception as e:
            logger.warning(f"tree-sitter Java parser unavailable: {e}")

        try:
            import tree_sitter_go as tsgo
            from tree_sitter import Language, Parser
            GO_LANGUAGE = Language(tsgo.language())
            parser = Parser(GO_LANGUAGE)
            self._parsers["go"] = parser
            logger.info("tree-sitter: Go parser loaded")
        except Exception as e:
            logger.warning(f"tree-sitter Go parser unavailable: {e}")

    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect language from file extension or filename."""
        p = Path(file_path)
        # Check by extension
        ext = p.suffix.lower()
        if ext in EXT_TO_LANGUAGE:
            return EXT_TO_LANGUAGE[ext]
        # Check by filename (e.g. Dockerfile)
        name = p.name
        if name in EXT_TO_LANGUAGE:
            return EXT_TO_LANGUAGE[name]
        return None

    def parse_file(self, file_path: str, content: str) -> ParsedFile:
        """Parse a source file and return a ParsedFile with extracted nodes."""
        language = self.detect_language(file_path)
        lines = content.splitlines()

        parsed = ParsedFile(
            path=file_path,
            language=language or "unknown",
            content=content,
            lines=lines,
            root=None,
        )

        if not language:
            return parsed

        parser = self._parsers.get(language)
        if parser:
            try:
                self._parse_with_treesitter(parser, parsed, language)
            except Exception as e:
                logger.warning(f"tree-sitter parse failed for {file_path}: {e}")
                self._parse_with_regex(parsed, language)
        else:
            self._parse_with_regex(parsed, language)

        return parsed

    def _parse_with_treesitter(self, parser, parsed: ParsedFile, language: str):
        """Use tree-sitter for precise AST parsing."""
        tree = parser.parse(parsed.content.encode("utf-8"))
        root_node = tree.root_node

        # Convert tree-sitter node to our normalized ASTNode
        parsed.root = self._convert_node(root_node, parsed.content, language)

        # Extract top-level constructs
        self._extract_constructs(parsed, root_node, language)

    def _convert_node(self, ts_node, source: str, language: str) -> ASTNode:
        """Recursively convert tree-sitter node to ASTNode."""
        try:
            text = source[ts_node.start_byte:ts_node.end_byte]
        except Exception:
            text = ""

        node = ASTNode(
            node_type=ts_node.type,
            text=text[:500],  # Cap size
            start_line=ts_node.start_point[0] + 1,
            end_line=ts_node.end_point[0] + 1,
            start_col=ts_node.start_point[1],
            end_col=ts_node.end_point[1],
            language=language,
        )
        for child in ts_node.children:
            child_node = self._convert_node(child, source, language)
            child_node.parent = node
            node.children.append(child_node)
        return node

    def _extract_constructs(self, parsed: ParsedFile, root_node, language: str):
        """Walk tree and extract functions, classes, calls, etc."""
        source = parsed.content.encode("utf-8")

        FUNCTION_TYPES = {
            "python": ["function_definition", "async_function_definition"],
            "javascript": ["function_declaration", "arrow_function", "method_definition"],
            "java": ["method_declaration", "constructor_declaration"],
            "go": ["function_declaration", "method_declaration"],
        }
        CLASS_TYPES = {
            "python": ["class_definition"],
            "javascript": ["class_declaration"],
            "java": ["class_declaration", "interface_declaration"],
            "go": ["type_declaration"],
        }
        IMPORT_TYPES = {
            "python": ["import_statement", "import_from_statement"],
            "javascript": ["import_statement", "require"],
            "java": ["import_declaration"],
            "go": ["import_declaration"],
        }
        CALL_TYPES = {
            "python": ["call"],
            "javascript": ["call_expression"],
            "java": ["method_invocation"],
            "go": ["call_expression"],
        }
        STRING_TYPES = {
            "python": ["string"],
            "javascript": ["string", "template_string"],
            "java": ["string_literal"],
            "go": ["interpreted_string_literal", "raw_string_literal"],
        }

        fn_types = set(FUNCTION_TYPES.get(language, []))
        cls_types = set(CLASS_TYPES.get(language, []))
        imp_types = set(IMPORT_TYPES.get(language, []))
        call_types = set(CALL_TYPES.get(language, []))
        str_types = set(STRING_TYPES.get(language, []))

        def walk(node):
            ntype = node.type
            try:
                text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            except Exception:
                text = ""

            ast_node = ASTNode(
                node_type=ntype,
                text=text[:300],
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                start_col=node.start_point[1],
                end_col=node.end_point[1],
                language=language,
            )

            if ntype in fn_types:
                parsed.functions.append(ast_node)
            elif ntype in cls_types:
                parsed.classes.append(ast_node)
            elif ntype in imp_types:
                parsed.imports.append(ast_node)
            elif ntype in call_types:
                parsed.calls.append(ast_node)
            elif ntype in str_types:
                parsed.string_literals.append(ast_node)

            for child in node.children:
                walk(child)

        walk(root_node)

    def _parse_with_regex(self, parsed: ParsedFile, language: str):
        """
        Fallback regex-based extraction when tree-sitter is unavailable.
        Less precise but covers all languages.
        """
        import re
        content = parsed.content
        lines = parsed.lines

        PATTERNS = {
            "python": {
                "function": r"^\s*(?:async\s+)?def\s+(\w+)\s*\(",
                "class": r"^\s*class\s+(\w+)[\s:(]",
                "import": r"^\s*(?:import|from)\s+\S+",
                "call": r"(\w+)\s*\(",
                "string": r'(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\\]*"|\'[^\'\\]*\')',
            },
            "javascript": {
                "function": r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())",
                "class": r"\bclass\s+(\w+)",
                "import": r"(?:import\s|require\()",
                "call": r"(\w+)\s*\(",
                "string": r'(?:`[^`]*`|"[^"\\]*"|\'[^\'\\]*\')',
            },
            "java": {
                "function": r"(?:public|private|protected|static|\s)+[\w<>[\]]+\s+(\w+)\s*\(",
                "class": r"\bclass\s+(\w+)",
                "import": r"^\s*import\s+[\w.]+;",
                "call": r"(\w+)\s*\(",
                "string": r'"[^"\\]*"',
            },
            "php": {
                "function": r"\bfunction\s+(\w+)\s*\(",
                "class": r"\bclass\s+(\w+)",
                "import": r"(?:require|include|use)\s",
                "call": r"(\w+)\s*\(",
                "string": r'(?:"[^"\\]*"|\'[^\'\\]*\')',
            },
            "go": {
                "function": r"\bfunc\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(",
                "class": r"\btype\s+(\w+)\s+struct",
                "import": r'"[\w/.]+"',
                "call": r"(\w+)\s*\(",
                "string": r'(?:`[^`]*`|"[^"\\]*")',
            },
        }

        lang_patterns = PATTERNS.get(language, PATTERNS.get("javascript", {}))

        for i, line in enumerate(lines, 1):
            if "function" in lang_patterns:
                m = re.search(lang_patterns["function"], line)
                if m:
                    name = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else "unknown")
                    parsed.functions.append(ASTNode(
                        node_type="function_definition",
                        text=line.strip()[:200],
                        start_line=i, end_line=i,
                        start_col=0, end_col=len(line),
                        language=language,
                        metadata={"name": name},
                    ))
            if "class" in lang_patterns:
                m = re.search(lang_patterns["class"], line)
                if m:
                    parsed.classes.append(ASTNode(
                        node_type="class_definition",
                        text=line.strip()[:200],
                        start_line=i, end_line=i,
                        start_col=0, end_col=len(line),
                        language=language,
                        metadata={"name": m.group(1)},
                    ))
            if "import" in lang_patterns:
                if re.search(lang_patterns["import"], line):
                    parsed.imports.append(ASTNode(
                        node_type="import",
                        text=line.strip()[:200],
                        start_line=i, end_line=i,
                        start_col=0, end_col=len(line),
                        language=language,
                    ))

        # Extract string literals
        if "string" in lang_patterns:
            for m in re.finditer(lang_patterns["string"], content):
                line_no = content[:m.start()].count("\n") + 1
                parsed.string_literals.append(ASTNode(
                    node_type="string_literal",
                    text=m.group(0)[:200],
                    start_line=line_no, end_line=line_no,
                    start_col=0, end_col=0,
                    language=language,
                ))


# ─── Singleton ────────────────────────────────────────────────────────────────
ast_engine = ASTEngine()
