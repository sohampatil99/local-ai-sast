"""Java analysis with tree-sitter: dangerous calls plus taint tracking from servlet/Spring input.

Sources are HttpServletRequest getters (getParameter, getHeader, ...) and parameters annotated
@RequestParam/@PathVariable/@RequestBody. Taint follows local variables and crosses calls to
other methods of the same file. static final String constants, primitive-typed values and
numeric conversions (Integer.parseInt) are treated as safe, so SQL built only from them is
not reported.
"""
from .models import Finding
from .taxonomy import default_severity

try:
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Parser

    _PARSER = Parser(Language(_tsjava.language()))
    AVAILABLE = True
except Exception:  # tree-sitter-java missing: engine falls back to regex rules
    _PARSER = None
    AVAILABLE = False

SOURCE_METHODS = {"getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders",
                  "getQueryString", "getCookies", "getInputStream", "getReader", "getPathInfo",
                  "getRequestURI", "getRequestURL", "getPart", "getParts"}
INPUT_ANNOTATIONS = {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue",
                     "ModelAttribute", "QueryParam", "PathParam", "FormParam", "HeaderParam"}
SQL_METHODS = {"executeQuery", "executeUpdate", "execute", "addBatch", "prepareStatement", "prepareCall",
               "createQuery", "createNativeQuery", "createSQLQuery", "queryForList", "queryForObject",
               "queryForMap", "query", "update", "batchUpdate"}
SAFE_CONVERSIONS = {"parseInt", "parseLong", "parseDouble", "parseFloat", "parseShort", "parseBoolean",
                    "size", "length", "hashCode", "randomUUID"}
BOXES = {"Integer", "Long", "Double", "Float", "Short", "Boolean", "UUID"}  # Integer.valueOf, UUID.fromString
SANITIZERS = {"escapeHtml4": {"xss"}, "escapeHtml": {"xss"}, "htmlEscape": {"xss"}, "forHtml": {"xss"},
              "forHtmlContent": {"xss"}, "encodeForHTML": {"xss"},
              "getName": {"path_traversal"}, "getFileName": {"path_traversal"}}
FILE_TYPES = {"File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter", "RandomAccessFile"}
PRIMITIVES = {"integral_type", "floating_point_type", "boolean_type"}
LITERALS = {"string_literal", "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
            "true", "false", "null_literal", "character_literal", "text_block"}
TAINT_CATEGORIES = {"sqli", "cmdi", "code_injection", "xss", "deserialization", "path_traversal"}
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low"}
WEAK_ALGOS = ("MD5", "SHA1", "SHA-1", "DES", "RC4", "/ECB/")
NO_TAINT = None


class _State:
    def __init__(self):
        self.tainted = {}  # name -> frozenset of sink categories it is sanitized for
        self.values = {}  # name -> list of assigned expression nodes
        self.prim = set()  # names declared with a primitive type (int, long, boolean, ...)
        self.safe = set()


class _JavaAnalyzer:
    def __init__(self, tree, src, source_file, lines):
        self.root = tree.root_node
        self.src = src
        self.sf = source_file
        self.lines = lines
        self.findings = []
        self.consts = set()
        self.methods = {}
        self.param_taint = {}
        self.returns_source = set()
        self.passthrough = set()
        self.states = {}

    # ---- helpers -----------------------------------------------------------
    def text(self, node):
        return self.src[node.start_byte:node.end_byte].decode("utf-8", "ignore")

    def walk(self, node=None):
        stack = [node or self.root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    def field(self, node, name):
        f = node.child_by_field_name(name)
        return f

    def args(self, node):
        a = node.child_by_field_name("arguments")
        return [c for c in a.named_children if c.type not in {"comment", "line_comment", "block_comment"}] if a else []

    def call_name(self, node):
        n = node.child_by_field_name("name")
        return self.text(n) if n is not None else ""

    def enclosing_method(self, node):
        cur = node.parent
        while cur is not None and cur.type not in {"method_declaration", "constructor_declaration"}:
            cur = cur.parent
        return cur

    def method_name(self, m):
        n = m.child_by_field_name("name")
        return self.text(n) if n is not None else "<init>"

    def params(self, m):
        """[(name, type node, annotation names)] for a method."""
        out = []
        plist = m.child_by_field_name("parameters")
        for p in plist.named_children if plist else []:
            if p.type not in {"formal_parameter", "spread_parameter"}:
                continue
            name, typ = p.child_by_field_name("name"), p.child_by_field_name("type")
            if name is None:
                name = next((c for c in p.named_children if c.type == "variable_declarator"), None)
                name = name.child_by_field_name("name") if name is not None else None
            if name is None:
                continue
            notes = {self.text(a.child_by_field_name("name")) for c in p.children if c.type == "modifiers"
                     for a in c.named_children if a.type in {"marker_annotation", "annotation"}
                     and a.child_by_field_name("name") is not None}
            out.append((self.text(name), typ, notes))
        return out

    # ---- collection ----------------------------------------------------------
    def collect(self):
        seen = {}
        for n in self.walk():
            if n.type in {"method_declaration", "constructor_declaration"}:
                seen.setdefault(self.method_name(n), []).append(n)
            elif n.type == "field_declaration":
                mods = next((c for c in n.children if c.type == "modifiers"), None)
                if mods is None or "final" not in self.text(mods).split():
                    continue
                for d in n.named_children:
                    if d.type == "variable_declarator":
                        name, value = d.child_by_field_name("name"), d.child_by_field_name("value")
                        if name is not None and value is not None and self.is_safe_value(value, _State()):
                            self.consts.add(self.text(name))
        self.methods = {k: v[0] for k, v in seen.items() if len(v) == 1}
        self.param_taint = {m: {} for m in self.methods.values()}

    def resolve(self, call):
        if call.type != "method_invocation":
            return None
        obj = call.child_by_field_name("object")
        if obj is None or obj.type == "this":
            return self.methods.get(self.call_name(call))
        return None

    def bind(self, call, m):
        names = [p[0] for p in self.params(m)]
        return [(names[i], a) for i, a in enumerate(self.args(call)) if i < len(names)]

    # ---- taint ---------------------------------------------------------------
    def taint_info(self, node, st):
        t = node.type
        if t == "identifier":
            return st.tainted.get(self.text(node))
        if t in LITERALS:
            return NO_TAINT
        if t == "method_invocation":
            name = self.call_name(node)
            obj = node.child_by_field_name("object")
            obj_t = self.text(obj) if obj is not None else ""
            if name in SOURCE_METHODS:
                return frozenset()
            if name in SAFE_CONVERSIONS or (name in {"valueOf", "fromString"} and obj_t in BOXES):
                return NO_TAINT
            if name in SQL_METHODS:
                return NO_TAINT  # query results are database data, not request input
            parts = ([obj] if obj is not None else []) + self.args(node)
            if name in SANITIZERS:
                inner = self._merge(parts, st)
                return NO_TAINT if inner is None else inner | SANITIZERS[name]
            callee = self.resolve(node)
            if callee is not None:
                if callee in self.returns_source:
                    return frozenset()
                return self._merge(self.args(node), st) if callee in self.passthrough else NO_TAINT
            return self._merge(parts, st)
        if t == "object_creation_expression":
            return self._merge(self.args(node), st)
        return self._merge(node.named_children, st)

    def _merge(self, nodes, st):
        infos = [i for i in (self.taint_info(n, st) for n in nodes) if i is not None]
        if not infos:
            return NO_TAINT
        out = infos[0]
        for i in infos[1:]:
            out = out & i
        return out

    def is_tainted(self, node, st, category=None):
        info = self.taint_info(node, st)
        return info is not None and (category is None or category not in info)

    # ---- constants and string building ----------------------------------------
    def is_safe_value(self, node, st):
        t = node.type
        if t in LITERALS:
            return True
        if t == "identifier":
            name = self.text(node)
            if name in st.prim:
                return True
            if name in st.values:
                return name in st.safe
            return name in self.consts
        if t == "field_access":
            f = node.child_by_field_name("field")
            return f is not None and self.text(f) in self.consts
        if t in {"parenthesized_expression", "unary_expression", "cast_expression"}:
            return all(self.is_safe_value(c, st) for c in node.named_children if c.type not in PRIMITIVES
                       and c.type != "type_identifier")
        if t == "binary_expression":
            return self.is_safe_value(node.child_by_field_name("left"), st) and \
                self.is_safe_value(node.child_by_field_name("right"), st)
        if t == "ternary_expression":
            return self.is_safe_value(node.child_by_field_name("consequence"), st) and \
                self.is_safe_value(node.child_by_field_name("alternative"), st)
        if t == "method_invocation":
            name = self.call_name(node)
            obj = node.child_by_field_name("object")
            return name in SAFE_CONVERSIONS or (name in {"valueOf", "fromString"} and obj is not None
                                                and self.text(obj) in BOXES)
        return False

    def pieces(self, node):
        if node.type == "binary_expression" and node.child_by_field_name("operator") is not None \
                and self.text(node.child_by_field_name("operator")) == "+":
            out = []
            for side in (node.child_by_field_name("left"), node.child_by_field_name("right")):
                sub = self.pieces(side)
                out += sub if sub is not None else [side]
            return out
        if node.type == "parenthesized_expression" and node.named_children:
            return self.pieces(node.named_children[0])
        if node.type == "method_invocation" and self.call_name(node) == "format":
            obj = node.child_by_field_name("object")
            if obj is not None and self.text(obj) == "String":
                args = self.args(node)
                return [a for i, a in enumerate(args) if i > 0 or a.type != "string_literal"]
        if node.type == "array_creation_expression":
            init = next((c for c in node.named_children if c.type == "array_initializer"), None)
            return list(init.named_children) if init is not None else None
        return None

    def is_unsafe(self, node, st, category, depth=0):
        if self.is_safe_value(node, st):
            return False
        info = self.taint_info(node, st)
        if info is not None and category in info:
            return False
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, st, category, depth) for p in parts)
        if node.type == "identifier" and depth < 4 and st.values.get(self.text(node)):
            return any(self.is_unsafe(v, st, category, depth + 1) for v in st.values[self.text(node)])
        return True

    def is_dynamic(self, node, st, category, depth=0):
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, st, category) for p in parts)
        if node.type == "identifier" and depth < 4:
            return any(self.is_dynamic(v, st, category, depth + 1) for v in st.values.get(self.text(node), []))
        return False

    def scope_state(self, m, seed=()):
        st = _State()
        is_main = self.method_name(m) == "main"
        for name, typ, notes in self.params(m):
            if typ is not None and typ.type in PRIMITIVES:
                st.prim.add(name)
            elif notes & INPUT_ANNOTATIONS or (is_main and typ is not None and self.text(typ) == "String[]"):
                st.tainted[name] = frozenset()
        st.tainted.update({p: frozenset() for p in seed if p not in st.prim})
        assigns = []
        body = m.child_by_field_name("body")
        for n in self.walk(body) if body is not None else []:
            if n.type == "local_variable_declaration":
                typ = n.child_by_field_name("type")
                for d in n.named_children:
                    if d.type != "variable_declarator":
                        continue
                    name, value = d.child_by_field_name("name"), d.child_by_field_name("value")
                    if name is None:
                        continue
                    if typ is not None and typ.type in PRIMITIVES:
                        st.prim.add(self.text(name))
                    if value is not None:
                        assigns.append((self.text(name), value))
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and right is not None and left.type == "identifier":
                    assigns.append((self.text(left), right))
            elif n.type == "enhanced_for_statement":
                name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                if name is not None and value is not None:
                    assigns.append((self.text(name), value))
        for name, value in assigns:
            st.values.setdefault(name, []).append(value)
        for _ in range(3):
            st.safe = {n for n, vals in st.values.items() if all(self.is_safe_value(v, st) for v in vals)}
        for _ in range(2):
            for name, value in assigns:
                if name in st.prim:
                    continue
                info = self.taint_info(value, st)
                if info is not None:
                    prev = st.tainted.get(name)
                    st.tainted[name] = info if prev is None else prev & info
        return st

    def state(self, m):
        if m not in self.states:
            self.states[m] = self.scope_state(m, self.param_taint.get(m, {}))
        return self.states[m]

    def propagate(self, calls):
        changed = False
        self.states = {}
        for m in self.methods.values():
            body = m.child_by_field_name("body")
            returns = [r.named_children[0] for r in self.walk(body) if r.type == "return_statement"
                       and r.named_children] if body is not None else []
            if not returns:
                continue
            if m not in self.returns_source:
                base = self.scope_state(m)
                if any(self.is_tainted(r, base) for r in returns):
                    self.returns_source.add(m)
                    changed = True
            if m not in self.passthrough:
                seeded = self.scope_state(m, [p[0] for p in self.params(m)])
                if any(self.is_tainted(r, seeded) for r in returns):
                    self.passthrough.add(m)
                    changed = True
        for call, caller in calls:
            callee = self.resolve(call)
            if callee is None:
                continue
            st = self.state(caller)
            for param, arg in self.bind(call, callee):
                if param not in self.param_taint[callee] and self.is_tainted(arg, st):
                    self.param_taint[callee][param] = \
                        f"{self.method_name(caller)}() -> {self.method_name(callee)}({param})"
                    changed = True
        if changed:
            self.states = {}
        return changed

    # ---- reporting -------------------------------------------------------------
    def report(self, node, rule_id, category, title, message, tainted_hit, via=""):
        line = node.start_point[0] + 1
        snippet = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        if "nosast" in snippet:
            return
        severity = default_severity(category)
        if not tainted_hit and category in TAINT_CATEGORIES:
            severity = DOWNGRADE.get(severity, severity)
        if tainted_hit:
            message += " User-controlled input reaches this call"
            message += f" through a method argument ({via})." if via else "."
        self.findings.append(Finding(
            rule_id=rule_id, title=title, category=category, severity=severity,
            file=self.sf.rel, line=line, snippet=snippet[:300], message=message,
            detector="ast-java", confidence="high" if tainted_hit else "medium", language="java"))

    def via(self, m, nodes, category):
        origins = self.param_taint.get(m)
        if not origins:
            return ""
        base = self.scope_state(m)
        if any(self.is_tainted(n, base, category) for n in nodes):
            return ""
        names = {self.text(i) for n in nodes for i in self.walk(n) if i.type == "identifier"}
        hits = [o for p, o in origins.items() if p in names]
        return "; ".join(hits or origins.values())

    # ---- checks ----------------------------------------------------------------
    def run(self):
        self.collect()
        calls = [(n, self.enclosing_method(n)) for n in self.walk()
                 if n.type in {"method_invocation", "object_creation_expression"}]
        calls = [(n, m) for n, m in calls if m is not None]
        for _ in range(5):
            if not self.propagate(calls):
                break
        for n, m in calls:
            self.check(n, m, self.state(m))
        return self.findings

    def check(self, n, m, st):
        args = self.args(n)
        arg0 = args[0] if args else None

        def hit(category, nodes=None):
            return any(self.is_tainted(a, st, category) for a in (nodes if nodes is not None else args[:1]))

        def via(category, nodes=None):
            return self.via(m, nodes if nodes is not None else args[:1], category)

        if n.type == "object_creation_expression":
            typ = n.child_by_field_name("type")
            tname = self.text(typ).split("<")[0].split(".")[-1] if typ is not None else ""
            if tname in {"ObjectInputStream", "XMLDecoder"}:
                self.report(n, "JAVA-DESER", "deserialization", "Insecure Deserialization",
                            f"new {tname}() deserializes objects and can run attacker-chosen code.",
                            hit("deserialization", args), via("deserialization", args))
            elif tname in FILE_TYPES and hit("path_traversal", args):
                self.report(n, "JAVA-PATH", "path_traversal", "Path Traversal",
                            f"File path passed to new {tname}() is derived from user input.", True,
                            via("path_traversal", args))
            elif tname == "ProcessBuilder" and hit("cmdi", args):
                self.report(n, "JAVA-CMDI", "cmdi", "OS Command Injection",
                            "ProcessBuilder command contains user input.", True, via("cmdi", args))
            elif tname == "URL" and hit("ssrf"):
                self.report(n, "JAVA-SSRF", "ssrf", "Server-Side Request Forgery",
                            "Outbound URL is built from user input.", True, via("ssrf"))
            return

        name = self.call_name(n)
        obj = n.child_by_field_name("object")
        obj_t = self.text(obj) if obj is not None else ""
        if name in SQL_METHODS and arg0 is not None and obj is not None and self.is_dynamic(arg0, st, "sqli"):
            self.report(n, "JAVA-SQLI", "sqli", "SQL Injection",
                        f"SQL passed to {name}() is built by string concatenation.", hit("sqli"), via("sqli"))
        if name == "exec" and obj_t.endswith("getRuntime()") and arg0 is not None \
                and self.is_unsafe(arg0, st, "cmdi"):
            self.report(n, "JAVA-CMDI", "cmdi", "OS Command Injection",
                        "Runtime.exec() runs a dynamically built command.", hit("cmdi"), via("cmdi"))
        if name == "getInstance" and obj_t in {"MessageDigest", "Cipher", "KeyGenerator", "Mac",
                                               "SecretKeyFactory"} \
                and arg0 is not None and arg0.type == "string_literal":
            algo = self.text(arg0).strip('"').upper()
            if any(w in algo for w in WEAK_ALGOS) or (obj_t == "Cipher" and algo in {"AES", "DESEDE"}):
                self.report(n, "JAVA-WEAKHASH", "weak_crypto", "Weak Cryptography",
                            f"{obj_t}.getInstance(\"{algo}\") uses a broken algorithm or ECB mode.", False)
        if name in {"print", "println", "write", "append", "printf", "format"} and arg0 is not None \
                and self.is_writer(obj, st) and hit("xss"):
            self.report(n, "JAVA-XSS", "xss", "Cross-Site Scripting",
                        "User input is written to the HTTP response without HTML escaping.", True, via("xss"))
        if (obj_t in {"Paths", "Path"} and name in {"get", "of"}) and hit("path_traversal", args):
            self.report(n, "JAVA-PATH", "path_traversal", "Path Traversal",
                        f"{obj_t}.{name}() builds a file path from user input.", True, via("path_traversal", args))

    def is_writer(self, obj, st):
        if obj is None:
            return False
        t = self.text(obj)
        if t.endswith("getWriter()") or t.endswith("getOutputStream()"):
            return True
        return obj.type == "identifier" and any("getWriter()" in self.text(v) for v in st.values.get(t, []))


def scan_java(source_file, text, lines):
    if _PARSER is None:
        return []
    src = text.encode("utf-8")
    return _JavaAnalyzer(_PARSER.parse(src), src, source_file, lines).run()
