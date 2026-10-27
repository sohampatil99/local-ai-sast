"""JavaScript/TypeScript analysis with tree-sitter: dangerous calls, DOM sinks, taint from req.*.

Taint is tracked by variable name across the file. It also crosses calls to functions
defined in the same file: a tainted argument taints the parameter, and a function that
returns user input taints its callers. Constants, numeric conversions (parseInt, Number)
and sanitizers (path.basename, escapeHtml, DOMPurify.sanitize) stop it.
"""
import re

from .models import Finding
from .taxonomy import default_severity

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    _PARSERS = {
        "javascript": Parser(Language(_tsjs.language())),
        "typescript": Parser(Language(_tsts.language_typescript())),
        "tsx": Parser(Language(_tsts.language_tsx())),
    }
    AVAILABLE = True
except Exception:  # tree-sitter missing: engine falls back to regex rules
    _PARSERS = {}
    AVAILABLE = False

TAINT_CATEGORIES = {"sqli", "cmdi", "code_injection", "xss", "deserialization", "path_traversal"}
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low"}
SOURCE_RE = re.compile(r"\breq(uest)?\.(query|body|params|cookies|headers)\b|"
                       r"\blocation\.(search|hash|href)\b|\bdocument\.(URL|cookie|referrer)\b")
CHILD_PROCESS_OBJS = {"child_process", "cp", "childProcess", "require(\"child_process\")",
                      "require('child_process')"}
SQL_PROPS = {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe"}
FS_FUNCS = {"readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync",
            "unlink", "unlinkSync", "sendFile", "download"}
SAFE_CONVERSIONS = {"parseInt", "parseFloat", "Number", "Boolean", "Number.parseInt", "Number.parseFloat",
                    "Math.floor", "Math.round", "Math.ceil", "Math.abs", "crypto.randomUUID", "randomUUID"}
SANITIZERS = {"path.basename": {"path_traversal"}, "basename": {"path_traversal"},
              "escapeHtml": {"xss"}, "escape": {"xss"}, "he.encode": {"xss"}, "he.escape": {"xss"},
              "validator.escape": {"xss"}, "DOMPurify.sanitize": {"xss"}, "sanitizeHtml": {"xss"},
              "xss": {"xss"}, "shellescape": {"cmdi"}, "shellQuote.quote": {"cmdi"}}
LITERALS = {"string", "number", "true", "false", "null", "undefined", "regex"}
FUNCTION_NODES = {"function_declaration", "function_expression", "arrow_function", "method_definition",
                  "generator_function_declaration"}
NO_TAINT = None


class _JSAnalyzer:
    def __init__(self, tree, src, source_file, lines):
        self.root = tree.root_node
        self.src = src
        self.sf = source_file
        self.lines = lines
        self.findings = []
        self.tainted = {}  # name -> frozenset of sink categories it is sanitized for
        self.values = {}  # name -> list of assigned expression nodes
        self.safe = set()
        self.funcs = {}  # name -> function node
        self.origins = {}  # tainted parameter name -> "callee(param) called with user input at line N"
        self.returns_source = set()
        self.uses_child_process = b"child_process" in src

    def text(self, node):
        return self.src[node.start_byte:node.end_byte].decode("utf-8", "ignore")

    def walk(self, node=None):
        stack = [node or self.root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    # ---- functions -------------------------------------------------------------
    def collect_functions(self):
        seen = {}
        for n in self.walk():
            name = None
            if n.type in {"function_declaration", "generator_function_declaration"}:
                name = n.child_by_field_name("name")
                fn = n
            elif n.type == "variable_declarator":
                value = n.child_by_field_name("value")
                if value is not None and value.type in {"arrow_function", "function_expression", "function"}:
                    name, fn = n.child_by_field_name("name"), value
            if name is not None and name.type == "identifier":
                seen.setdefault(self.text(name), []).append(fn)
        self.funcs = {k: v[0] for k, v in seen.items() if len(v) == 1}

    def params(self, fn):
        p = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        if p is None:
            return []
        if p.type == "identifier":
            return [self.text(p)]
        out = []
        for c in p.named_children:
            node = c.child_by_field_name("pattern") or c  # TypeScript required_parameter
            if node.type == "assignment_pattern":
                node = node.child_by_field_name("left")
            out.append(self.text(node) if node is not None and node.type == "identifier" else None)
        return out

    def returns(self, fn):
        body = fn.child_by_field_name("body")
        if body is None:
            return []
        if body.type != "statement_block":
            return [body]  # arrow function with an expression body
        return [r.named_children[0] for r in self.walk(body) if r.type == "return_statement" and r.named_children]

    def callee(self, call):
        fn = call.child_by_field_name("function")
        return self.funcs.get(self.text(fn)) if fn is not None and fn.type == "identifier" else None

    def call_args(self, call):
        a = call.child_by_field_name("arguments")
        return [c for c in a.named_children if c.type != "comment"] if a is not None else []

    # ---- taint -----------------------------------------------------------------
    def taint_info(self, node):
        t = node.type
        if t == "identifier":
            return self.tainted.get(self.text(node))
        if t in LITERALS:
            return NO_TAINT
        if t in {"member_expression", "subscript_expression"} and SOURCE_RE.search(self.text(node)):
            return frozenset()
        if t in FUNCTION_NODES:
            return NO_TAINT
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            name = self.text(fn) if fn is not None else ""
            if name in SAFE_CONVERSIONS:
                return NO_TAINT
            args = self.call_args(node)
            cleans = SANITIZERS.get(name)
            if cleans:
                inner = self._merge(args)
                return NO_TAINT if inner is None else inner | cleans
            target = self.callee(node)
            if target is not None:
                return frozenset() if target in self.returns_source else NO_TAINT
        return self._merge(node.named_children)

    def _merge(self, nodes):
        infos = [i for i in (self.taint_info(n) for n in nodes) if i is not None]
        if not infos:
            return NO_TAINT
        out = infos[0]
        for i in infos[1:]:
            out = out & i
        return out

    def is_tainted(self, node, category=None):
        info = self.taint_info(node)
        return info is not None and (category is None or category not in info)

    # ---- constants and string building -------------------------------------------
    def is_safe_value(self, node):
        t = node.type
        if t in LITERALS:
            return True
        if t == "template_string":
            return all(self.is_safe_value(s.named_children[0]) for s in node.named_children
                       if s.type == "template_substitution" and s.named_children)
        if t == "identifier":
            return self.text(node) in self.safe
        if t in {"binary_expression", "parenthesized_expression", "unary_expression"}:
            return all(self.is_safe_value(c) for c in node.named_children)
        if t == "ternary_expression":
            return self.is_safe_value(node.child_by_field_name("consequence")) and \
                self.is_safe_value(node.child_by_field_name("alternative"))
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            return fn is not None and self.text(fn) in SAFE_CONVERSIONS
        return False

    def pieces(self, node):
        if node.type == "template_string":
            return [s.named_children[0] for s in node.named_children
                    if s.type == "template_substitution" and s.named_children]
        if node.type == "binary_expression" and node.child_by_field_name("operator") is not None \
                and self.text(node.child_by_field_name("operator")) == "+":
            out = []
            for side in (node.child_by_field_name("left"), node.child_by_field_name("right")):
                sub = self.pieces(side)
                out += sub if sub is not None else [side]
            return out
        if node.type == "parenthesized_expression" and node.named_children:
            return self.pieces(node.named_children[0])
        return None

    def is_unsafe(self, node, category, depth=0):
        if self.is_safe_value(node):
            return False
        info = self.taint_info(node)
        if info is not None and category in info:
            return False
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, category, depth) for p in parts)
        if node.type == "identifier" and depth < 4 and self.values.get(self.text(node)):
            return any(self.is_unsafe(v, category, depth + 1) for v in self.values[self.text(node)])
        return True

    def is_dynamic(self, node, category=None, depth=0):
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, category) for p in parts if p.type != "string")
        if node.type == "identifier" and depth < 4:
            return any(self.is_dynamic(v, category, depth + 1) for v in self.values.get(self.text(node), []))
        return False

    def collect_vars(self):
        assigns = []
        for n in self.walk():
            if n.type == "variable_declarator":
                name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            elif n.type in {"assignment_expression", "augmented_assignment_expression"}:
                name, value = n.child_by_field_name("left"), n.child_by_field_name("right")
            else:
                continue
            if name is not None and value is not None and name.type == "identifier":
                assigns.append((self.text(name), value))
        for name, value in assigns:
            self.values.setdefault(name, []).append(value)
        for _ in range(3):
            self.safe = {n for n, vals in self.values.items() if all(self.is_safe_value(v) for v in vals)}
        calls = [n for n in self.walk() if n.type == "call_expression"]
        for _ in range(4):
            before = (len(self.tainted), len(self.returns_source))
            for name, value in assigns:
                info = self.taint_info(value)
                if info is not None:
                    prev = self.tainted.get(name)
                    self.tainted[name] = info if prev is None else prev & info
            for call in calls:
                fn = self.callee(call)
                if fn is None:
                    continue
                fname = self.text(call.child_by_field_name("function"))
                for param, arg in zip(self.params(fn), self.call_args(call)):
                    if param and param not in self.tainted and self.is_tainted(arg):
                        self.tainted[param] = frozenset()
                        self.origins[param] = f"{fname}({param}) is called with user input on line " \
                                              f"{call.start_point[0] + 1}"
            for fn in self.funcs.values():
                if fn not in self.returns_source and any(self.is_tainted(r) for r in self.returns(fn)):
                    self.returns_source.add(fn)
            if (len(self.tainted), len(self.returns_source)) == before:
                break

    def via(self, node):
        names = {self.text(n) for n in self.walk(node) if n.type == "identifier"}
        if SOURCE_RE.search(self.text(node)) or any(n in self.tainted and n not in self.origins for n in names):
            return ""
        return "; ".join(self.origins[n] for n in names if n in self.origins)

    def report(self, node, rule_id, category, title, message, tainted_hit, via=""):
        line = node.start_point[0] + 1
        snippet = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        if "nosast" in snippet:
            return
        severity = default_severity(category)
        if not tainted_hit and category in TAINT_CATEGORIES:
            # Dangerous sink but no proven path from user input: one level lower (same rule as the Python analyzer)
            severity = DOWNGRADE.get(severity, severity)
        if tainted_hit:
            message += " User-controlled input reaches this call"
            message += f" through a function argument ({via})." if via else "."
        self.findings.append(Finding(
            rule_id=rule_id, title=title, category=category, severity=severity,
            file=self.sf.rel, line=line, snippet=snippet[:300], message=message,
            detector="ast-js", confidence="high" if tainted_hit else "medium",
            language=self.sf.language))

    def run(self):
        self.collect_functions()
        self.collect_vars()
        for n in self.walk():
            if n.type == "call_expression":
                self.check_call(n)
            elif n.type == "new_expression":
                ctor = n.child_by_field_name("constructor")
                if ctor is not None and self.text(ctor) == "Function":
                    self.report(n, "JS-FUNC", "code_injection", "Code Injection",
                                "new Function() compiles a dynamic string into code.", self.is_tainted(n))
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    if prop is not None and self.text(prop) in {"innerHTML", "outerHTML"} \
                            and right is not None and self.is_unsafe(right, "xss"):
                        self.report(n, "JS-INNERHTML", "xss", "DOM-based XSS",
                                    f"Assigning non-constant data to {self.text(prop)} renders it as HTML.",
                                    self.is_tainted(right, "xss"), self.via(right))
        return self.findings

    def check_call(self, n):
        fn = n.child_by_field_name("function")
        args_node = n.child_by_field_name("arguments")
        if fn is None or args_node is None:
            return
        args = [c for c in args_node.named_children if c.type != "comment"]
        arg0 = args[0] if args else None
        if fn.type == "member_expression":
            obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
            obj_t = self.text(obj) if obj is not None else ""
            name = self.text(prop) if prop is not None else ""
        else:
            obj_t, name = "", self.text(fn)
        full = f"{obj_t}.{name}" if obj_t else name

        def hit(category):
            return arg0 is not None and self.is_tainted(arg0, category)

        def via():
            return self.via(arg0) if arg0 is not None else ""

        if name == "eval" and not obj_t and arg0 is not None and self.is_unsafe(arg0, "code_injection"):
            self.report(n, "JS-EVAL", "code_injection", "Code Injection",
                        "eval() executes a dynamic expression.", hit("code_injection"), via())
        if name in SQL_PROPS and obj_t and arg0 is not None and self.is_dynamic(arg0, "sqli"):
            self.report(n, "JS-SQLI", "sqli", "SQL Injection",
                        f"SQL passed to {full}() is built with concatenation or a template literal.",
                        hit("sqli"), via())
        is_cp = (obj_t in CHILD_PROCESS_OBJS) or (not obj_t and self.uses_child_process)
        if name in {"exec", "execSync"} and is_cp and arg0 is not None and self.is_unsafe(arg0, "cmdi"):
            self.report(n, "JS-CMDI", "cmdi", "OS Command Injection",
                        f"{full}() runs a dynamically built shell command.", hit("cmdi"), via())
        if name in {"createHash", "createCipher", "createCipheriv"} and arg0 is not None \
                and arg0.type == "string" and re.search(r"md5|sha1|des|rc4", self.text(arg0), re.I):
            self.report(n, "JS-WEAKCRYPTO", "weak_crypto", "Weak Cryptography",
                        f"{full}({self.text(arg0)}) uses a broken algorithm.", False)
        if obj_t in {"res", "response"} and name in {"send", "write", "end"} and arg0 is not None \
                and self.is_dynamic(arg0, "xss") and hit("xss") and "<" in self.text(arg0):
            self.report(n, "JS-XSS", "xss", "Reflected XSS",
                        "User input is concatenated into an HTML response.", True, via())
        if full in {"document.write", "document.writeln"} and arg0 is not None and self.is_unsafe(arg0, "xss"):
            self.report(n, "JS-DOCWRITE", "xss", "DOM-based XSS",
                        "document.write() with non-constant content.", hit("xss"), via())
        if name in FS_FUNCS and arg0 is not None and hit("path_traversal"):
            self.report(n, "JS-PATH", "path_traversal", "Path Traversal",
                        f"File path passed to {full}() is derived from user input.", True, via())


def scan_js(source_file, text, lines):
    lang = source_file.language
    if source_file.rel.endswith(".tsx"):
        lang = "tsx"
    parser = _PARSERS.get(lang)
    if parser is None:
        return []
    src = text.encode("utf-8")
    return _JSAnalyzer(parser.parse(src), src, source_file, lines).run()
