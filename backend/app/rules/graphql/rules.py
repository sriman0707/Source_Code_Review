"""GraphQL-specific security rules"""
from app.rules.base import Rule

RULES = [
    Rule(id="GQL_INTRO_001", title="GraphQL Introspection Enabled",
         description="Introspection exposes full schema to attackers.",
         category="graphql", severity="MEDIUM",
         pattern=r"""introspection\s*[=:]\s*(?:True|true|1|enabled)""",
         cwe="CWE-200", owasp="API8:2023", confidence=0.85),
    Rule(id="GQL_DEPTH_001", title="GraphQL — No Query Depth Limit",
         description="Deep nested queries can cause DoS.",
         category="graphql", severity="MEDIUM",
         pattern=r"""(?:graphql|schema|typeDefs)[^{]*\{""",
         negative_patterns=[r"depth_limit|max_depth|depthLimit|maxDepth"],
         cwe="CWE-400", owasp="API8:2023", confidence=0.5),
    Rule(id="GQL_AUTH_001", title="GraphQL Mutation Without Auth Middleware",
         description="GraphQL mutation missing authentication decorator/middleware.",
         category="authorization", severity="HIGH",
         pattern=r"""(?:type\s+Mutation|@Mutation)\s*\{[^}]+resolve\s*:""",
         negative_patterns=[r"@auth|@login_required|@IsAuthenticated|isAuthenticated"],
         cwe="CWE-862", owasp="API1:2023", confidence=0.6),
    Rule(id="GQL_ALIAS_001", title="GraphQL Alias Attack Vector",
         description="No alias/batching protection detected.",
         category="graphql", severity="LOW",
         pattern=r"""(?:graphql|schema)""",
         negative_patterns=[r"alias|batch_limit|max_aliases"],
         cwe="CWE-400", owasp="API8:2023", confidence=0.3),
]
