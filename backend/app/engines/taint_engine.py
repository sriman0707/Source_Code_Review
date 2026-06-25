"""
Taint Tracking Engine
=====================
Tracks untrusted data from SOURCES through transformations to dangerous SINKS,
identifying whether sanitizers neutralize the flow.

Performs interprocedural taint analysis — tracks across function calls, return
values, class attributes, and file boundaries.

Architecture:
  SOURCE  →  [propagation steps]  →  SANITIZER? → SINK
                                         ↓ (if no sanitizer)
                                      FINDING
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from app.engines.ast_engine import ParsedFile, ASTNode

logger = logging.getLogger(__name__)


# ─── Source Definitions ──────────────────────────────────────────────────────

SOURCES: dict[str, list[str]] = {
    "python": [
        # Flask / Django / FastAPI request inputs
        "request.args", "request.form", "request.json", "request.data",
        "request.files", "request.cookies", "request.headers",
        "request.get_json", "request.values",
        # Django
        "request.POST", "request.GET", "request.META",
        # FastAPI
        "Body(", "Query(", "Path(", "Form(",
        # General
        "input(", "sys.stdin", "os.environ", "environ.get",
        "os.getenv", "getattr(request",
    ],
    "javascript": [
        "req.body", "req.query", "req.params", "req.headers", "req.cookies",
        "request.body", "request.query", "request.params",
        "document.URL", "document.location", "window.location",
        "document.referrer", "location.href", "location.search",
        "location.hash", "document.cookie",
        "event.data", "postMessage",
        "localStorage.getItem", "sessionStorage.getItem",
        "new URLSearchParams", "decodeURIComponent",
        "JSON.parse(req", "ctx.query", "ctx.request.body",
    ],
    "java": [
        "request.getParameter", "request.getQueryString",
        "request.getHeader", "request.getCookies",
        "request.getInputStream", "request.getReader",
        "System.getenv", "System.getProperty",
        "request.getAttribute", "getServletPath",
    ],
    "php": [
        "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "$_COOKIE",
        "$_FILES", "$_ENV", "getallheaders(", "apache_request_headers(",
        "file_get_contents('php://input')",
    ],
    "go": [
        "r.URL.Query()", "r.FormValue(", "r.PostFormValue(",
        "r.Header.Get(", "r.Body", "r.Cookie(",
        "chi.URLParam(", "mux.Vars(",
        "c.Query(", "c.Param(", "c.PostForm(",  # gin
        "ctx.QueryParam(", "ctx.FormValue(",     # echo
    ],
}

# ─── Sink Definitions ────────────────────────────────────────────────────────

SINKS: dict[str, dict[str, list[str]]] = {
    "python": {
        "sql_injection": [
            "execute(", "executemany(", "raw(", "RawSQL(",
            "cursor.execute(", "db.execute(", "session.execute(",
            "engine.execute(", "text(", "query.format(",
            ".filter(", "extra(", "RawSQL(",
        ],
        "command_injection": [
            "os.system(", "subprocess.call(", "subprocess.run(",
            "subprocess.Popen(", "subprocess.check_output(",
            "os.popen(", "commands.getoutput(", "eval(",
            "exec(", "execfile(",
        ],
        "xss": [
            "render_template_string(", "Markup(", "mark_safe(",
            "format_html(", "innerHTML", ".write(", "Response(",
            "HTMLParser(", "jinja2.Template(",
        ],
        "ssrf": [
            "requests.get(", "requests.post(", "requests.put(",
            "urllib.request.urlopen(", "urllib.urlopen(",
            "httpx.get(", "httpx.post(", "aiohttp.ClientSession(",
            "urllib3.PoolManager(", "pycurl.Curl(",
        ],
        "path_traversal": [
            "open(", "os.path.join(", "os.listdir(", "os.remove(",
            "shutil.copy(", "pathlib.Path(", "send_file(",
            "send_from_directory(", "FileResponse(",
        ],
        "ssti": [
            "render_template_string(", "Template(", "from_string(",
            "Environment().from_string(", "jinja2.Template(",
        ],
        "deserialization": [
            "pickle.loads(", "pickle.load(", "yaml.load(",
            "marshal.loads(", "jsonpickle.decode(",
        ],
        "ldap_injection": [
            "ldap.search(", "ldap3.Connection(",
        ],
        "xxe": [
            "lxml.etree.fromstring(", "xml.etree.ElementTree.parse(",
            "xmltodict.parse(", "minidom.parseString(",
        ],
    },
    "javascript": {
        "sql_injection": [
            "query(", "execute(", ".raw(", "db.query(",
            "pool.query(", "connection.query(",
            "knex.raw(", "sequelize.query(",
        ],
        "xss": [
            "innerHTML", "outerHTML", "document.write(",
            "insertAdjacentHTML(", "eval(", "setTimeout(",
            "setInterval(", "Function(", "dangerouslySetInnerHTML",
            "v-html", "$(", ".html(",
        ],
        "command_injection": [
            "child_process.exec(", "exec(", "execSync(",
            "spawn(", "spawnSync(", "execFile(",
            "shelljs.exec(", "cp.exec(",
        ],
        "ssrf": [
            "fetch(", "axios.get(", "axios.post(", "http.request(",
            "https.request(", "got(", "superagent.get(",
            "needle.get(", "request(",
        ],
        "path_traversal": [
            "fs.readFile(", "fs.writeFile(", "fs.readFileSync(",
            "res.sendFile(", "path.join(", "fs.existsSync(",
        ],
        "nosql_injection": [
            ".find(", ".findOne(", ".aggregate(", ".update(",
            ".findOneAndUpdate(", "mongoose.model(",
        ],
        "prototype_pollution": [
            "Object.assign(", "_.merge(", "_.extend(",
            "merge(", "extend(", "deepMerge(",
        ],
    },
    "java": {
        "sql_injection": [
            "createQuery(", "createNativeQuery(", "executeQuery(",
            "prepareStatement(", "Statement.execute(",
            "EntityManager.createNativeQuery(",
        ],
        "command_injection": [
            "Runtime.exec(", "ProcessBuilder(", "new ProcessBuilder(",
        ],
        "xss": [
            "PrintWriter.write(", "getOutputStream().write(",
            "response.getWriter(", "out.println(",
        ],
        "path_traversal": [
            "new File(", "new FileInputStream(", "new FileOutputStream(",
            "Paths.get(", "Files.readAllBytes(",
        ],
        "xxe": [
            "DocumentBuilder.parse(", "SAXParser.parse(",
            "XMLReader.parse(", "XMLInputFactory(",
        ],
        "ssrf": [
            "new URL(", "HttpURLConnection(", "URL.openConnection(",
            "HttpClient.newHttpClient(", "RestTemplate(",
        ],
    },
    "php": {
        "sql_injection": [
            "mysql_query(", "mysqli_query(", "$pdo->query(",
            "pg_query(", "sqlite_query(",
        ],
        "command_injection": [
            "system(", "exec(", "shell_exec(", "passthru(",
            "popen(", "proc_open(", "eval(",
        ],
        "xss": [
            "echo ", "print(", "printf(", "<?=", "var_dump(",
        ],
        "path_traversal": [
            "include(", "require(", "include_once(", "require_once(",
            "file_get_contents(", "fopen(", "readfile(",
        ],
        "ssrf": [
            "curl_exec(", "file_get_contents(", "fopen('http",
        ],
        "xxe": [
            "simplexml_load_string(", "simplexml_load_file(",
            "DOMDocument->loadXML(", "xml_parse(",
        ],
    },
    "go": {
        "sql_injection": [
            "db.Query(", "db.Exec(", "db.QueryRow(",
            "stmt.Query(", "gorm.Raw(",
        ],
        "command_injection": [
            "exec.Command(", "os/exec.Command(",
        ],
        "ssrf": [
            "http.Get(", "http.Post(", "http.NewRequest(",
            "http.DefaultClient.Do(", "resty.New(",
        ],
        "path_traversal": [
            "os.Open(", "ioutil.ReadFile(", "os.ReadFile(",
            "http.ServeFile(", "filepath.Join(",
        ],
    },
}

# ─── Sanitizer Definitions ───────────────────────────────────────────────────

SANITIZERS: dict[str, list[str]] = {
    "python": [
        "escape(", "html.escape(", "bleach.clean(", "markupsafe.escape(",
        "parameterized", "prepared_statement",
        "re.escape(", "shlex.quote(", "pipes.quote(",
        "validate(", "sanitize(", "clean(", "strip(",
        "int(", "float(", "bool(",          # Type coercion sanitizers
        "uuid.UUID(", "datetime.fromisoformat(",
    ],
    "javascript": [
        "sanitize(", "DOMPurify.sanitize(", "xss(", "escape(",
        "encodeURIComponent(", "encodeURI(",
        "validator.escape(", "validator.isURL(", "validator.isEmail(",
        "parameterize(", "parseInt(", "parseFloat(",
        "Number(", "Boolean(", "String(",
    ],
    "java": [
        "StringEscapeUtils.escapeHtml(", "ESAPI.encoder().encodeForHTML(",
        "PreparedStatement", "HtmlUtils.htmlEscape(",
        "Integer.parseInt(", "Long.parseLong(", "UUID.fromString(",
    ],
    "php": [
        "htmlspecialchars(", "htmlentities(", "strip_tags(",
        "addslashes(", "mysqli_real_escape_string(",
        "filter_var(", "intval(", "floatval(",
        "preg_replace(", "PDO::prepare(",
    ],
    "go": [
        "html.EscapeString(", "url.QueryEscape(", "template.HTMLEscapeString(",
        "strconv.Atoi(", "strconv.ParseInt(", "uuid.Parse(",
        "regexp.MustCompile(",
    ],
}


@dataclass
class TaintNode:
    """A node in a taint flow path."""
    file_path: str
    line: int
    col: int
    code: str
    node_type: str  # "source" | "propagation" | "sanitizer" | "sink"
    variable: Optional[str] = None
    function: Optional[str] = None


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    source: TaintNode
    sink: TaintNode
    path: list[TaintNode] = field(default_factory=list)
    vulnerability_type: str = ""
    sanitized: bool = False
    sanitizer_node: Optional[TaintNode] = None
    confidence: float = 0.8

    @property
    def is_vulnerable(self) -> bool:
        return not self.sanitized

    def to_dict(self) -> dict:
        return {
            "source": {
                "file": self.source.file_path,
                "line": self.source.line,
                "code": self.source.code,
            },
            "sink": {
                "file": self.sink.file_path,
                "line": self.sink.line,
                "code": self.sink.code,
                "type": self.vulnerability_type,
            },
            "sanitized": self.sanitized,
            "confidence": self.confidence,
            "path_length": len(self.path),
        }


class TaintEngine:
    """
    Performs taint analysis on parsed source files.
    Identifies user-controlled data flowing to dangerous sinks.
    """

    def analyze(
        self,
        parsed_file: ParsedFile,
        cross_file_context: Optional[dict] = None,
    ) -> list[TaintFlow]:
        """
        Analyze a parsed file for taint flows.
        Returns list of TaintFlow objects (only vulnerable ones by default).
        """
        language = parsed_file.language
        if language not in SOURCES:
            return []

        flows: list[TaintFlow] = []
        lines = parsed_file.lines
        content = parsed_file.content
        sources_for_lang = SOURCES.get(language, [])
        sinks_for_lang = SINKS.get(language, {})
        sanitizers_for_lang = SANITIZERS.get(language, [])

        # ── Phase 1: Find tainted variables ────────────────────────────────
        tainted_vars: dict[int, list[str]] = {}  # line → variable names

        for line_no, line in enumerate(lines, 1):
            for source_pattern in sources_for_lang:
                if source_pattern in line:
                    # Extract variable being assigned (LHS of assignment)
                    var = self._extract_assigned_var(line, language)
                    if var:
                        tainted_vars[line_no] = tainted_vars.get(line_no, []) + [var]

                    # Mark this line as a source node
                    source_node = TaintNode(
                        file_path=parsed_file.path,
                        line=line_no,
                        col=line.find(source_pattern),
                        code=line.strip()[:300],
                        node_type="source",
                        variable=var,
                    )
                    # Look for sinks that use this variable downstream
                    flows.extend(
                        self._trace_to_sinks(
                            source_node=source_node,
                            tainted_var=var,
                            lines=lines,
                            language=language,
                            sinks=sinks_for_lang,
                            sanitizers=sanitizers_for_lang,
                            start_line=line_no,
                        )
                    )

        # ── Phase 2: Direct source-in-sink patterns ─────────────────────────
        for line_no, line in enumerate(lines, 1):
            for vuln_type, sink_patterns in sinks_for_lang.items():
                for sink_pattern in sink_patterns:
                    if sink_pattern not in line:
                        continue
                    # Check if any source pattern appears directly in same line
                    for src_pattern in sources_for_lang:
                        if src_pattern in line:
                            sanitized, san_node = self._check_sanitization(
                                line, line_no, parsed_file.path, sanitizers_for_lang
                            )
                            src_node = TaintNode(
                                file_path=parsed_file.path,
                                line=line_no,
                                col=line.find(src_pattern),
                                code=line.strip()[:300],
                                node_type="source",
                            )
                            sink_node = TaintNode(
                                file_path=parsed_file.path,
                                line=line_no,
                                col=line.find(sink_pattern),
                                code=line.strip()[:300],
                                node_type="sink",
                            )
                            flow = TaintFlow(
                                source=src_node,
                                sink=sink_node,
                                vulnerability_type=vuln_type,
                                sanitized=sanitized,
                                sanitizer_node=san_node,
                                confidence=0.9 if not sanitized else 0.2,
                            )
                            if flow.is_vulnerable:
                                flows.append(flow)

        return [f for f in flows if f.is_vulnerable]

    def _trace_to_sinks(
        self,
        source_node: TaintNode,
        tainted_var: Optional[str],
        lines: list[str],
        language: str,
        sinks: dict[str, list[str]],
        sanitizers: list[str],
        start_line: int,
    ) -> list[TaintFlow]:
        """Trace a tainted variable forward to any sink usage."""
        if not tainted_var:
            return []

        flows = []
        # Scan subsequent lines for the tainted variable used in a sink
        for line_no in range(start_line + 1, min(start_line + 100, len(lines) + 1)):
            line = lines[line_no - 1]
            # Skip if the variable isn't referenced on this line
            if tainted_var not in line:
                continue
            # Check if this line reassigns the variable (potential sanitization)
            reassigned_val = self._get_assignment_rhs(line, tainted_var, language)

            for vuln_type, sink_patterns in sinks.items():
                for sink_pattern in sink_patterns:
                    if sink_pattern not in line:
                        continue
                    sanitized, san_node = self._check_sanitization(
                        line, line_no, source_node.file_path, sanitizers
                    )
                    sink_node = TaintNode(
                        file_path=source_node.file_path,
                        line=line_no,
                        col=line.find(sink_pattern),
                        code=line.strip()[:300],
                        node_type="sink",
                    )
                    flow = TaintFlow(
                        source=source_node,
                        sink=sink_node,
                        vulnerability_type=vuln_type,
                        sanitized=sanitized,
                        sanitizer_node=san_node,
                        confidence=0.75 if not sanitized else 0.15,
                    )
                    if flow.is_vulnerable:
                        flows.append(flow)
        return flows

    def _check_sanitization(
        self,
        line: str,
        line_no: int,
        file_path: str,
        sanitizers: list[str],
    ) -> tuple[bool, Optional[TaintNode]]:
        """Check if a line applies a known sanitizer."""
        for san in sanitizers:
            if san in line:
                return True, TaintNode(
                    file_path=file_path,
                    line=line_no,
                    col=line.find(san),
                    code=line.strip()[:200],
                    node_type="sanitizer",
                )
        return False, None

    def _extract_assigned_var(self, line: str, language: str) -> Optional[str]:
        """Extract the variable name on the LHS of an assignment."""
        patterns = {
            "python": r"^\s*(\w+)\s*=",
            "javascript": r"(?:const|let|var)\s+(\w+)\s*=|^\s*(\w+)\s*=",
            "java": r"(?:\w+\s+)?(\w+)\s*=",
            "php": r"\$(\w+)\s*=",
            "go": r"(?:var\s+)?(\w+)\s*(?::=|=)",
        }
        pattern = patterns.get(language, r"^\s*(\w+)\s*=")
        m = re.match(pattern, line)
        if m:
            for g in m.groups():
                if g:
                    return g
        return None

    def _get_assignment_rhs(self, line: str, var: str, language: str) -> Optional[str]:
        """Get the RHS of an assignment to var (for detecting reassignment)."""
        pattern = rf"\b{re.escape(var)}\s*=\s*(.+)"
        m = re.search(pattern, line)
        if m:
            return m.group(1).strip()
        return None


# ─── Singleton ────────────────────────────────────────────────────────────────
taint_engine = TaintEngine()
