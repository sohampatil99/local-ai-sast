"""Go analysis with tree-sitter: dangerous calls plus taint tracking from net/http (and gin/mux) input.

Sources are request getters (r.FormValue, r.URL.Query().Get, r.Header.Get, mux.Vars, gin's c.Query /
c.Param) and os.Args. Taint follows local variables and crosses calls to other functions of the same
file. Constants, integer-typed values and strconv conversions are safe, so SQL built only from them is
not reported; filepath.Base and html.EscapeString are sanitizers for paths and HTML.
"""
import re

from .models import Finding
from .taxonomy import default_severity

try:
    import tree_sitter_go as _tsgo
    from tree_sitter import Language, Parser

    _PARSER = Parser(Language(_tsgo.language()))
    AVAILABLE = True
except Exception:  # tree-sitter-go missing: engine falls back to regex rules
    _PARSER = None
    AVAILABLE = False

SOURCE_CALL = re.compile(r"\.(FormValue|PostFormValue|PostForm|DefaultQuery|DefaultPostForm|Param|Cookie|"
                         r"GetHeader|FormFile)$|\.Query\(\)\.Get$|\.Header\.Get$|^mux\.Vars$|\.URL\.Query$")
SOURCE_FIELD = re.compile(r"\.URL\.(Path|RawQuery|RawPath)$|^\w+\.Body$|^\w+\.Form$|^os\.Args$")
SAFE_CONVERSIONS = {"strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat",
                    "strconv.ParseBool", "len", "uuid.New", "uuid.NewString", "strconv.Itoa"}
SANITIZERS = {"filepath.Base": {"path_traversal"}, "path.Base": {"path_traversal"},
              "html.EscapeString": {"xss"}, "template.HTMLEscapeString": {"xss"}, "url.QueryEscape": {"xss"}}
SQL_METHODS = {"Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext", "Prepare",
               "PrepareContext", "Raw", "Select", "Get"}
SQL_RECEIVERS_HINT = re.compile(r"(?i)\b(db|tx|conn|sqlx?|stmt|gorm|pool)\b")
FILE_FUNCS = {"os.Open", "os.OpenFile", "os.ReadFile", "os.Create", "os.WriteFile", "os.Remove", "os.RemoveAll",
              "ioutil.ReadFile", "ioutil.WriteFile"}
HTTP_CLIENT = {"http.Get": 0, "http.Post": 0, "http.Head": 0, "http.NewRequest": 1, "http.NewRequestWithContext": 2}
WEAK_CRYPTO = {"md5.New", "md5.Sum", "sha1.New", "sha1.Sum", "des.NewCipher", "des.NewTripleDESCipher",
               "rc4.NewCipher"}
SHELLS = {"sh", "bash", "cmd", "/bin/sh", "/bin/bash", "powershell", "zsh"}
INT_TYPES = {"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32",
             "float64", "bool"}
LITERALS = {"interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal", "rune_literal",
            "true", "false", "nil", "imaginary_literal"}
TAINT_CATEGORIES = {"sqli", "cmdi", "code_injection", "xss", "deserialization", "path_traversal"}
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low"}
NO_TAINT = None


class _State:
    def __init__(self):
        self.tainted = {}  # name -> frozenset of sink categories it is sanitized for
        self.values = {}
        self.prim = set()  # declared with an integer/bool type
        self.safe = set()
        self.writers = set()  # http.ResponseWriter parameters


class _GoAnalyzer:
    def __init__(self, tree, src, source_file, lines):
        self.root = tree.root_node
        self.src = src
        self.sf = source_file
        self.lines = lines
        self.findings = []
        self.consts = set()
        self.funcs = {}
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

    def field_all(self, node, name):
        return [c for i, c in enumerate(node.children) if node.field_name_for_child(i) == name]

    def args(self, call):
        a = call.child_by_field_name("arguments")
        return [c for c in a.named_children if c.type != "comment"] if a is not None else []

    def call_name(self, call):
        f = call.child_by_field_name("function")
        return self.text(f) if f is not None else ""

    def enclosing(self, node):
        cur = node.parent
        while cur is not None and cur.type not in {"function_declaration", "method_declaration", "func_literal"}:
            cur = cur.parent
        while cur is not None and cur.type == "func_literal":  # closures share their function's scope
            outer = cur.parent
            while outer is not None and outer.type not in {"function_declaration", "method_declaration", "func_literal"}:
                outer = outer.parent
            if outer is None:
                break
            cur = outer
        return cur

    def fname(self, fn):
        n = fn.child_by_field_name("name")
        return self.text(n) if n is not None else "func"

    def params(self, fn):
        """[(name, type text)] for a function, one entry per name (a, b string -> two)."""
        out = []
        plist = fn.child_by_field_name("parameters")
        for p in plist.named_children if plist is not None else []:
            if p.type not in {"parameter_declaration", "variadic_parameter_declaration"}:
                continue
            typ = p.child_by_field_name("type")
            for name in self.field_all(p, "name"):
                out.append((self.text(name), self.text(typ) if typ is not None else ""))
        return out

    # ---- collection --------------------------------------------------------
    def collect(self):
        seen = {}
        for n in self.walk():
            if n.type in {"function_declaration", "method_declaration"}:
                seen.setdefault(self.fname(n), []).append(n)
            elif n.type == "const_spec":
                for name in self.field_all(n, "name"):
                    self.consts.add(self.text(name))
        self.funcs = {k: v[0] for k, v in seen.items() if len(v) == 1}
        self.param_taint = {fn: {} for fn in self.funcs.values()}

    def resolve(self, call):
        f = call.child_by_field_name("function")
        return self.funcs.get(self.text(f)) if f is not None and f.type == "identifier" else None

    def bind(self, call, fn):
        names = [p[0] for p in self.params(fn)]
        return [(names[i], a) for i, a in enumerate(self.args(call)) if i < len(names)]

    # ---- taint -------------------------------------------------------------
    def taint_info(self, node, st):
        t = node.type
        if t == "identifier":
            return st.tainted.get(self.text(node))
        if t in LITERALS or t in {"func_literal"}:
            return NO_TAINT
        if t == "selector_expression" and SOURCE_FIELD.search(self.text(node)):
            return frozenset()
        if t == "call_expression":
            name = self.call_name(node)
            if SOURCE_CALL.search(name):
                return frozenset()
            if name in SAFE_CONVERSIONS:
                return NO_TAINT
            args = self.args(node)
            if name in SANITIZERS:
                inner = self._merge(args, st)
                return NO_TAINT if inner is None else inner | SANITIZERS[name]
            callee = self.resolve(node)
            if callee is not None:
                if callee in self.returns_source:
                    return frozenset()
                return self._merge(args, st) if callee in self.passthrough else NO_TAINT
            fn = node.child_by_field_name("function")
            return self._merge(([fn] if fn is not None else []) + args, st)
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

    # ---- constants and string building -------------------------------------
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
        if t in {"parenthesized_expression", "unary_expression"}:
            return all(self.is_safe_value(c, st) for c in node.named_children)
        if t == "binary_expression":
            return self.is_safe_value(node.child_by_field_name("left"), st) and \
                self.is_safe_value(node.child_by_field_name("right"), st)
        if t == "type_conversion_expression":
            op = node.child_by_field_name("operand")
            return op is not None and self.is_safe_value(op, st)
        if t == "call_expression":
            name = self.call_name(node)
            if name in SAFE_CONVERSIONS:
                return True
            if name == "fmt.Sprintf":
                return all(self.is_safe_value(a, st) for a in self.args(node))
        return False

    def pieces(self, node):
        if node.type == "binary_expression" and self.text(node.child_by_field_name("operator")) == "+":
            out = []
            for side in (node.child_by_field_name("left"), node.child_by_field_name("right")):
                sub = self.pieces(side)
                out += sub if sub is not None else [side]
            return out
        if node.type == "parenthesized_expression" and node.named_children:
            return self.pieces(node.named_children[0])
        if node.type == "call_expression" and self.call_name(node) in {"fmt.Sprintf", "strings.Join"}:
            args = self.args(node)
            return [a for i, a in enumerate(args) if i > 0 or a.type not in LITERALS]
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

    def scope_state(self, fn, seed=()):
        st = _State()
        for name, typ in self.params(fn):
            if typ in INT_TYPES:
                st.prim.add(name)
            if typ.endswith("ResponseWriter"):
                st.writers.add(name)
        st.tainted.update({p: frozenset() for p in seed if p not in st.prim})
        assigns = []
        body = fn.child_by_field_name("body")
        for n in self.walk(body) if body is not None else []:
            if n.type in {"short_var_declaration", "assignment_statement"}:
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is None or right is None:
                    continue
                lefts, rights = left.named_children, right.named_children
                for i, l in enumerate(lefts):
                    if l.type != "identifier" or self.text(l) == "_":
                        continue
                    # a, err := f(x): every name on the left takes the single call's value
                    value = rights[i] if len(rights) == len(lefts) else (rights[0] if rights else None)
                    if value is not None:
                        assigns.append((self.text(l), value))
            elif n.type == "var_spec":
                typ = n.child_by_field_name("type")
                value = n.child_by_field_name("value")
                names = self.field_all(n, "name")
                for i, name in enumerate(names):
                    if typ is not None and self.text(typ) in INT_TYPES:
                        st.prim.add(self.text(name))
                    if value is not None and value.named_children:
                        vals = value.named_children
                        assigns.append((self.text(name), vals[i] if i < len(vals) else vals[0]))
            elif n.type == "const_spec":
                for name in self.field_all(n, "name"):
                    st.prim.add(self.text(name))  # a local constant is never attacker-controlled
            elif n.type == "range_clause":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and right is not None:
                    for l in left.named_children:
                        if l.type == "identifier":
                            assigns.append((self.text(l), right))
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

    def state(self, fn):
        if fn not in self.states:
            self.states[fn] = self.scope_state(fn, self.param_taint.get(fn, {}))
        return self.states[fn]

    def propagate(self, calls):
        changed = False
        self.states = {}
        for fn in self.funcs.values():
            body = fn.child_by_field_name("body")
            returns = [c for r in self.walk(body) if r.type == "return_statement"
                       for e in r.named_children for c in (e.named_children if e.type == "expression_list" else [e])] \
                if body is not None else []
            if not returns:
                continue
            if fn not in self.returns_source and any(self.is_tainted(r, self.scope_state(fn)) for r in returns):
                self.returns_source.add(fn)
                changed = True
            if fn not in self.passthrough:
                seeded = self.scope_state(fn, [p[0] for p in self.params(fn)])
                if any(self.is_tainted(r, seeded) for r in returns):
                    self.passthrough.add(fn)
                    changed = True
        for call, caller in calls:
            callee = self.resolve(call)
            if callee is None or caller is None:
                continue
            st = self.state(caller)
            for param, arg in self.bind(call, callee):
                if param not in self.param_taint[callee] and self.is_tainted(arg, st):
                    self.param_taint[callee][param] = f"{self.fname(caller)}() -> {self.fname(callee)}({param})"
                    changed = True
        if changed:
            self.states = {}
        return changed

    # ---- reporting -----------------------------------------------------------
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
            message += f" through a function argument ({via})." if via else "."
        self.findings.append(Finding(
            rule_id=rule_id, title=title, category=category, severity=severity,
            file=self.sf.rel, line=line, snippet=snippet[:300], message=message,
            detector="ast-go", confidence="high" if tainted_hit else "medium", language="go"))

    def via(self, fn, nodes, category):
        origins = self.param_taint.get(fn)
        if not origins:
            return ""
        base = self.scope_state(fn)
        if any(self.is_tainted(n, base, category) for n in nodes):
            return ""
        names = {self.text(i) for n in nodes for i in self.walk(n) if i.type == "identifier"}
        hits = [o for p, o in origins.items() if p in names]
        return "; ".join(hits or origins.values())

    # ---- checks ----------------------------------------------------------------
    def run(self):
        self.collect()
        calls = [(n, self.enclosing(n)) for n in self.walk() if n.type == "call_expression"]
        for _ in range(5):
            if not self.propagate(calls):
                break
        for n, fn in calls:
            if fn is not None:
                self.check(n, fn, self.state(fn))
        for n in self.walk():
            if n.type == "keyed_element":
                key, value = n.child_by_field_name("key"), n.child_by_field_name("value")
                if key is not None and value is not None and self.text(key) == "InsecureSkipVerify" \
                        and self.text(value) == "true":
                    self.report(n, "GO-TLS", "insecure_tls", "Disabled TLS Verification",
                                "InsecureSkipVerify: true turns off certificate checks.", False)
        return self.findings

    def check(self, n, fn, st):
        name = self.call_name(n)
        short = name.rsplit(".", 1)[-1]
        args = self.args(n)

        def hit(category, nodes):
            return any(self.is_tainted(a, st, category) for a in nodes)

        def via(category, nodes):
            return self.via(fn, nodes, category)

        if short in SQL_METHODS and "." in name and args:
            recv = name.rsplit(".", 1)[0]
            q = args[1] if short.endswith("Context") and len(args) > 1 else args[0]
            if (short not in {"Select", "Get"} or SQL_RECEIVERS_HINT.search(recv)) and self.is_dynamic(q, st, "sqli"):
                self.report(n, "GO-SQLI", "sqli", "SQL Injection",
                            f"SQL passed to {name}() is built with concatenation or fmt.Sprintf.",
                            hit("sqli", [q]), via("sqli", [q]))
        if name in {"exec.Command", "exec.CommandContext"} and args:
            rest = args[1:] if name == "exec.Command" else args[2:]
            prog = args[0] if name == "exec.Command" else (args[1] if len(args) > 1 else None)
            prog_t = self.text(prog).strip('"`') if prog is not None else ""
            if prog is not None and prog.type in LITERALS and prog_t in SHELLS:
                if any(self.is_unsafe(a, st, "cmdi") for a in rest):
                    self.report(n, "GO-CMDI", "cmdi", "OS Command Injection",
                                f"{prog_t} -c runs a dynamically built command.", hit("cmdi", rest), via("cmdi", rest))
            elif prog is not None and (self.is_tainted(prog, st, "cmdi") or hit("cmdi", rest)):
                self.report(n, "GO-CMDI", "cmdi", "OS Command Injection",
                            f"{name}() runs a program or arguments taken from user input.", True,
                            via("cmdi", [prog] + rest))
        if name in FILE_FUNCS and args and hit("path_traversal", args[:1]):
            self.report(n, "GO-PATH", "path_traversal", "Path Traversal",
                        f"File path passed to {name}() is derived from user input.", True,
                        via("path_traversal", args[:1]))
        if name == "http.ServeFile" and len(args) > 2 and hit("path_traversal", args[2:3]):
            self.report(n, "GO-PATH", "path_traversal", "Path Traversal",
                        "http.ServeFile() serves a path derived from user input.", True,
                        via("path_traversal", args[2:3]))
        if name in HTTP_CLIENT and len(args) > HTTP_CLIENT[name] and hit("ssrf", [args[HTTP_CLIENT[name]]]):
            self.report(n, "GO-SSRF", "ssrf", "Server-Side Request Forgery",
                        f"Outbound URL in {name}() comes from user input.", True,
                        via("ssrf", [args[HTTP_CLIENT[name]]]))
        if name in WEAK_CRYPTO:
            self.report(n, "GO-WEAKHASH", "weak_crypto", "Weak Cryptography",
                        f"{name}() uses a broken hash or cipher.", False)
        if name in {"fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln", "io.WriteString"} and len(args) > 1:
            w = args[0]
            if w.type == "identifier" and self.text(w) in st.writers and hit("xss", args[1:]):
                self.report(n, "GO-XSS", "xss", "Cross-Site Scripting",
                            "User input is written to the HTTP response without HTML escaping.", True,
                            via("xss", args[1:]))
        if name == "template.HTML" and args and hit("xss", args[:1]):
            self.report(n, "GO-XSS", "xss", "Cross-Site Scripting",
                        "template.HTML() marks user input as safe HTML, disabling escaping.", True,
                        via("xss", args[:1]))


def scan_go(source_file, text, lines):
    if _PARSER is None:
        return []
    src = text.encode("utf-8")
    return _GoAnalyzer(_PARSER.parse(src), src, source_file, lines).run()
