"""Python AST analysis: dangerous-API detection plus taint tracking.

Taint sources are request data (Flask/Django/FastAPI style), input() and sys.argv.
A name becomes tainted when it is assigned from a source or from another tainted
name. Taint also crosses function calls within the same file: a tainted argument
taints the callee's parameter, and a function that returns request data taints its
callers. Sanitizers stop taint for the sinks they protect (int() for everything,
shlex.quote for shell commands, html.escape for HTML, os.path.basename for paths),
and strings built only from constants are not reported.
"""
import ast

from .models import Finding
from .taxonomy import default_severity

REQUEST_ATTRS = {"args", "form", "values", "json", "cookies", "headers", "data", "files",
                 "get_json", "get_data", "query_params", "path_params", "GET", "POST", "body"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "text", "read_sql", "mogrify"}
SHELL_FUNCS = {"os.system", "os.popen", "os.popen2", "os.popen3", "commands.getoutput",
               "subprocess.getoutput", "subprocess.getstatusoutput"}
SUBPROCESS_FUNCS = {"subprocess.call", "subprocess.run", "subprocess.Popen",
                    "subprocess.check_output", "subprocess.check_call"}
DESERIALIZERS = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads",
                 "marshal.loads", "shelve.open", "jsonpickle.decode", "yaml.unsafe_load",
                 "pandas.read_pickle"}
WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "Crypto.Hash.MD5.new", "Crypto.Cipher.DES.new",
               "Crypto.Cipher.ARC4.new"}
FILE_SINKS = {"open", "send_file", "flask.send_file", "io.open", "os.remove", "shutil.rmtree"}
HTTP_CLIENTS = {"requests.get", "requests.post", "requests.put", "requests.delete",
                "requests.head", "requests.request", "urllib.request.urlopen", "httpx.get",
                "httpx.post", "urlopen"}
TAINT_CATEGORIES = {"sqli", "cmdi", "code_injection", "xss", "deserialization", "path_traversal"}
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low"}
HTML_RESPONSES = {"make_response", "flask.make_response", "Response", "HttpResponse",
                  "HTMLResponse"}
# Calls whose result is a number/UUID: safe in SQL, shell commands, HTML and paths
SAFE_CONVERSIONS = {"int", "float", "bool", "len", "abs", "round", "uuid.UUID", "uuid.uuid4"}
# Calls that neutralise input for one kind of sink only
SANITIZERS = {
    "html.escape": {"xss"}, "markupsafe.escape": {"xss"}, "flask.escape": {"xss"},
    "cgi.escape": {"xss"}, "bleach.clean": {"xss"}, "django.utils.html.escape": {"xss"},
    "shlex.quote": {"cmdi"}, "pipes.quote": {"cmdi"}, "shlex.join": {"cmdi"},
    "os.path.basename": {"path_traversal"}, "werkzeug.utils.secure_filename": {"path_traversal"},
    "secure_filename": {"path_traversal"},
}
NO_TAINT = None
UNKNOWN = object()  # assigned value we cannot reason about (tuple unpacking, loop variables)


class _State:
    """Per-function facts: tainted names, what each is sanitized for, and constant names."""

    def __init__(self):
        self.tainted = {}  # name -> frozenset of sink categories it is sanitized for
        self.values = {}  # name -> list of assigned value nodes (or UNKNOWN)
        self.safe = set()  # names only ever assigned constants or numeric conversions


class _Analyzer:
    def __init__(self, tree, source_file, lines):
        self.tree = tree
        self.sf = source_file
        self.lines = lines
        self.aliases = {}
        self.findings = []
        self.parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        self.funcs = {}  # name -> FunctionDef, for unambiguous names in this file
        self.param_taint = {}  # FunctionDef -> {param: "caller() -> callee(param)"}
        self.returns_source = set()  # functions that return user input
        self.passthrough = set()  # functions whose return value depends on their parameters
        self.module_consts = set()
        self.states = {}

    # ---- name resolution -------------------------------------------------
    def collect_imports(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def collect_functions(self):
        seen = {}
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seen.setdefault(node.name, []).append(node)
        self.funcs = {name: nodes[0] for name, nodes in seen.items() if len(nodes) == 1}
        self.param_taint = {fn: {} for fn in self.funcs.values()}

    def dotted(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self.dotted(node.func)
        if isinstance(node, ast.Subscript):
            return self.dotted(node.value)
        return ""

    def resolve(self, call):
        """The function in this file that `call` invokes: foo(...) or self.foo(...)."""
        f = call.func
        if isinstance(f, ast.Name) and f.id not in self.aliases:
            return self.funcs.get(f.id)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in {"self", "cls"}:
            return self.funcs.get(f.attr)
        return None

    @staticmethod
    def params(fn):
        names = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        return names[1:] if names and names[0] in {"self", "cls"} else names

    def bind(self, call, fn):
        """Pair each argument of `call` with the parameter of `fn` it is passed to."""
        names = self.params(fn)
        pairs = [(names[i], a) for i, a in enumerate(call.args) if i < len(names) and not isinstance(a, ast.Starred)]
        pairs += [(k.arg, k.value) for k in call.keywords if k.arg in names]
        return pairs

    # ---- taint ------------------------------------------------------------
    def is_source(self, node):
        name = self.dotted(node)
        parts = name.split(".")
        if "request" in parts:
            i = parts.index("request")
            if i + 1 < len(parts) and parts[i + 1] in REQUEST_ATTRS:
                return True
        if isinstance(node, ast.Call) and name == "input":
            return True
        return name == "sys.argv"

    def taint_info(self, node, st):
        """None if `node` carries no user input, else the sink categories it has been sanitized for."""
        if isinstance(node, ast.Name):
            if node.id in st.tainted:
                return st.tainted[node.id]
            return NO_TAINT
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)) and self.is_source(node):
            return frozenset()
        if isinstance(node, ast.Call):
            name = self.dotted(node.func)
            if name in SAFE_CONVERSIONS:
                return NO_TAINT
            cleans = SANITIZERS.get(name) or SANITIZERS.get(name.split(".")[-1], set())
            args = list(node.args) + [k.value for k in node.keywords]
            if cleans:
                inner = self._merge(args, st)
                return NO_TAINT if inner is None else inner | cleans
            callee = self.resolve(node)
            if callee is not None:
                if callee in self.returns_source:
                    return frozenset()
                return self._merge(args, st) if callee in self.passthrough else NO_TAINT
        return self._merge(list(ast.iter_child_nodes(node)), st)

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

    # ---- constants and string building -----------------------------------
    def is_safe_value(self, node, st):
        """Constants, names holding only constants, and numeric conversions."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            if node.id in st.values:
                return node.id in st.safe
            return node.id in self.module_consts
        if isinstance(node, ast.JoinedStr):
            return all(self.is_safe_value(v.value, st) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            return self.is_safe_value(node.left, st) and self.is_safe_value(node.right, st)
        if isinstance(node, ast.UnaryOp):
            return self.is_safe_value(node.operand, st)
        if isinstance(node, ast.IfExp):
            return self.is_safe_value(node.body, st) and self.is_safe_value(node.orelse, st)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self.is_safe_value(e, st) for e in node.elts)
        if isinstance(node, ast.Call):
            name = self.dotted(node.func)
            if name in SAFE_CONVERSIONS:
                return True
            if name == "str" or (isinstance(node.func, ast.Attribute) and node.func.attr == "format"
                                 and isinstance(node.func.value, ast.Constant)):
                return all(self.is_safe_value(a, st) for a in list(node.args) + [k.value for k in node.keywords])
        return False

    @staticmethod
    def pieces(node):
        """The interpolated parts of a string built with f-strings, +, % or .format(); None if not built."""
        if isinstance(node, ast.JoinedStr):
            return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            out = []
            for side in (node.left, node.right):
                sub = _Analyzer.pieces(side)
                out += sub if sub is not None else [side]
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            right = node.right
            parts = right.elts if isinstance(right, ast.Tuple) else \
                [v for v in right.values] if isinstance(right, ast.Dict) else [right]
            return ([] if isinstance(node.left, ast.Constant) else [node.left]) + list(parts)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = [] if isinstance(node.func.value, ast.Constant) else [node.func.value]
            return base + list(node.args) + [k.value for k in node.keywords]
        return None

    def is_unsafe(self, node, st, category, depth=0):
        """True if `node` may hold text an attacker influences, for a sink of `category`."""
        if self.is_safe_value(node, st):
            return False
        info = self.taint_info(node, st)
        if info is not None and category in info:
            return False  # sanitized for this sink
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, st, category, depth) for p in parts)
        if isinstance(node, ast.Name) and depth < 4 and st.values.get(node.id):
            return any(v is UNKNOWN or self.is_unsafe(v, st, category, depth + 1) for v in st.values[node.id])
        return True

    def is_dynamic(self, node, st, category, depth=0):
        """True if `node` is a string built from at least one non-constant, unsanitized part."""
        parts = self.pieces(node)
        if parts is not None:
            return any(self.is_unsafe(p, st, category) for p in parts)
        if isinstance(node, ast.Name) and depth < 4:
            return any(v is not UNKNOWN and self.is_dynamic(v, st, category, depth + 1)
                       for v in st.values.get(node.id, []))
        return False

    def scope_state(self, fn, seed=()):
        """Facts for one function (or the module when fn is None); `seed` names start tainted."""
        st = _State()
        if fn is not None:
            if self._is_handler(fn):
                st.tainted.update({a.arg: frozenset() for a in fn.args.args})
            st.tainted.update({p: frozenset() for p in seed})
        assigns = []
        body = ast.walk(fn) if fn is not None else ast.iter_child_nodes(self.tree)
        for node in body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                assigns.append((node.lineno, targets, node.value))
            elif isinstance(node, ast.AugAssign):
                value = ast.BinOp(left=node.target, op=node.op, right=node.value) \
                    if isinstance(node.target, ast.Name) else node.value
                assigns.append((node.lineno, [node.target], value))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        assigns.append((node.lineno, [item.optional_vars], item.context_expr))
            elif isinstance(node, ast.For):
                assigns.append((node.lineno, [node.target], node.iter))
        assigns.sort(key=lambda a: a[0])
        for _line, targets, value in assigns:
            for t in targets:
                if isinstance(t, ast.Name):
                    st.values.setdefault(t.id, []).append(value)
                else:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            st.values.setdefault(n.id, []).append(UNKNOWN)
        for _ in range(3):
            st.safe = {n for n, vals in st.values.items()
                       if all(v is not UNKNOWN and self.is_safe_value(v, st) for v in vals)}
        for _ in range(2):
            for _line, targets, value in assigns:
                info = self.taint_info(value, st)
                if info is None:
                    continue
                for n in (n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)):
                    prev = st.tainted.get(n)
                    st.tainted[n] = info if prev is None else prev & info
        return st

    def _is_handler(self, fn):
        for d in fn.decorator_list:
            name = self.dotted(d)
            if name.split(".")[-1] in {"route", "get", "post", "put", "delete", "patch", "api_view"}:
                return True
        return False

    def state(self, fn):
        if fn not in self.states:
            seed = self.param_taint.get(fn, {}) if fn is not None else {}
            self.states[fn] = self.scope_state(fn, seed)
        return self.states[fn]

    def propagate(self, calls):
        """One round of cross-function propagation; returns True if anything new was learned."""
        changed = False
        self.states = {}
        for fn in self.funcs.values():
            returns = [n.value for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None]
            if not returns:
                continue
            if fn not in self.returns_source:
                base = self.scope_state(fn)
                if any(self.is_tainted(r, base) for r in returns):
                    self.returns_source.add(fn)
                    changed = True
            if fn not in self.passthrough:
                seeded = self.scope_state(fn, self.params(fn))
                if any(self.is_tainted(r, seeded) for r in returns):
                    self.passthrough.add(fn)
                    changed = True
        for call, caller in calls:
            callee = self.resolve(call)
            if callee is None:
                continue
            st = self.state(caller)
            for param, arg in self.bind(call, callee):
                if param not in self.param_taint[callee] and self.is_tainted(arg, st):
                    where = f"{caller.name}()" if caller is not None else "module code"
                    self.param_taint[callee][param] = f"{where} -> {callee.name}({param})"
                    changed = True
        if changed:
            self.states = {}
        return changed

    def module_constants(self):
        st = self.scope_state(None)
        self.module_consts = {n for n in st.safe
                              if all(isinstance(v, (ast.Constant, ast.BinOp, ast.JoinedStr, ast.Tuple))
                                     for v in st.values[n])}

    # ---- reporting ---------------------------------------------------------
    def report(self, node, rule_id, category, title, message, tainted_hit, severity=None, via=""):
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if "nosast" in snippet:
            return
        severity = severity or default_severity(category)
        if not tainted_hit and category in TAINT_CATEGORIES:
            # Dangerous API but no proven path from user input: report one level lower
            severity = DOWNGRADE.get(severity, severity)
        if tainted_hit:
            message += " User-controlled input reaches this call"
            message += f" through a function argument ({via})." if via else "."
        self.findings.append(Finding(
            rule_id=rule_id, title=title, category=category,
            severity=severity, file=self.sf.rel, line=line,
            snippet=snippet[:300], message=message,
            detector="ast-python", confidence="high" if tainted_hit else "medium",
            language="python"))

    def via(self, fn, arg, category):
        """Describe the call chain when `arg` is tainted only because of a caller's argument."""
        origins = self.param_taint.get(fn)
        if not origins:
            return ""
        if self.is_tainted(arg, self.scope_state(fn), category):
            return ""  # tainted by request data read inside this function
        names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
        hits = [o for p, o in origins.items() if p in names]
        return "; ".join(hits or origins.values())

    def enclosing_function(self, node):
        cur = self.parents.get(node)
        while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cur = self.parents.get(cur)
        return cur

    # ---- checks ------------------------------------------------------------
    def run(self):
        self.collect_imports()
        self.collect_functions()
        self.module_constants()
        calls = [(n, self.enclosing_function(n)) for n in ast.walk(self.tree) if isinstance(n, ast.Call)]
        has_input = any(self.is_source(n) for n, _ in calls) or \
            any(self.is_source(n) for n in ast.walk(self.tree) if isinstance(n, (ast.Attribute, ast.Subscript))) or \
            any(self._is_handler(fn) for fn in self.funcs.values())
        if has_input:  # nothing can be tainted in a file that never reads user input
            for _ in range(5):
                if not self.propagate(calls):
                    break
        for node, fn in calls:
            self.check_call(node, fn, self.state(fn))
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Return) and node.value is not None:
                fn = self.enclosing_function(node)
                if fn is not None:
                    self.check_html_return(node, node.value, fn, self.state(fn))
            elif isinstance(node, ast.Assign) and self.enclosing_function(node) is None:
                self.check_module_assign(node)
        return self.findings

    def check_call(self, node, fn, st):
        name = self.dotted(node.func)
        short = name.split(".")[-1]
        args = node.args
        arg0 = args[0] if args else None
        kw = {k.arg: k.value for k in node.keywords if k.arg}

        def hit(category, target=arg0):
            return target is not None and self.is_tainted(target, st, category)

        def via(category, target=arg0):
            return self.via(fn, target, category) if fn is not None and target is not None else ""

        if short in SQL_METHODS and arg0 is not None and isinstance(node.func, ast.Attribute):
            if self.is_dynamic(arg0, st, "sqli"):
                self.report(node, "PY-SQLI", "sqli", "SQL Injection",
                            f"SQL query passed to {short}() is built with string formatting/concatenation.",
                            hit("sqli"), via=via("sqli"))
        if name in SHELL_FUNCS and arg0 is not None and self.is_unsafe(arg0, st, "cmdi"):
            self.report(node, "PY-CMDI", "cmdi", "OS Command Injection",
                        f"{name}() runs a dynamically built shell command.", hit("cmdi"), via=via("cmdi"))
        if name in SUBPROCESS_FUNCS and arg0 is not None:
            shell = kw.get("shell")
            if isinstance(shell, ast.Constant) and shell.value is True and self.is_unsafe(arg0, st, "cmdi"):
                self.report(node, "PY-CMDI-SHELL", "cmdi", "OS Command Injection",
                            f"{name}(shell=True) with a dynamic command string.", hit("cmdi"), via=via("cmdi"))
        if name in {"eval", "exec", "compile"} and arg0 is not None and self.is_unsafe(arg0, st, "code_injection"):
            self.report(node, "PY-EVAL", "code_injection", "Code Injection",
                        f"{name}() executes a dynamic expression.", hit("code_injection"),
                        via=via("code_injection"))
        if name in DESERIALIZERS:
            self.report(node, "PY-DESER", "deserialization", "Insecure Deserialization",
                        f"{name}() can execute arbitrary code when given untrusted data.",
                        hit("deserialization"), via=via("deserialization"))
        if name == "yaml.load":
            loader = kw.get("Loader")
            if loader is None or "Safe" not in self.dotted(loader):
                self.report(node, "PY-YAML", "deserialization", "Insecure Deserialization",
                            "yaml.load() without SafeLoader can construct arbitrary Python objects.",
                            hit("deserialization"), via=via("deserialization"))
        if name in WEAK_HASHES or (name == "hashlib.new" and arg0 is not None
                                   and isinstance(arg0, ast.Constant)
                                   and str(arg0.value).lower() in {"md5", "sha1"}):
            used = kw.get("usedforsecurity")
            if not (isinstance(used, ast.Constant) and used.value is False):
                self.report(node, "PY-WEAKHASH", "weak_crypto", "Weak Cryptography",
                            f"{name}() uses a broken hash/cipher algorithm.", False)
        if (name in FILE_SINKS or short in {"send_file", "send_from_directory"}) and args:
            target = args[-1] if short == "send_from_directory" else arg0
            if hit("path_traversal", target):
                self.report(node, "PY-PATH", "path_traversal", "Path Traversal",
                            f"File path passed to {short}() is derived from user input.", True,
                            via=via("path_traversal", target))
        if short == "render_template_string" and arg0 is not None and self.is_unsafe(arg0, st, "ssti"):
            taint0 = hit("ssti")
            self.report(node, "PY-SSTI", "xss", "Server-Side Template Injection / XSS",
                        "render_template_string() renders a non-constant template.", taint0,
                        severity="critical" if taint0 else None, via=via("ssti"))
        if (name in HTML_RESPONSES or short in {"Markup"}) and arg0 is not None:
            self.check_html_return(node, arg0, fn, st)
        if (name in HTTP_CLIENTS or name.startswith("requests.")) and hit("ssrf"):
            self.report(node, "PY-SSRF", "ssrf", "Server-Side Request Forgery",
                        f"Outbound request URL in {name}() comes from user input.", True, via=via("ssrf"))
        verify = kw.get("verify")
        if isinstance(verify, ast.Constant) and verify.value is False:
            self.report(node, "PY-TLS", "insecure_tls", "Disabled TLS Verification",
                        "Certificate verification is disabled (verify=False).", False)
        if short == "run" and isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
            self.report(node, "PY-DEBUG", "insecure_config", "Debug Mode Enabled",
                        "Application started with debug=True (interactive debugger exposes RCE).", False)
        if name == "tempfile.mktemp":
            self.report(node, "PY-MKTEMP", "unsafe_file", "Insecure Temporary File",
                        "tempfile.mktemp() is race-prone; an attacker can pre-create the file.", False)
        if name == "os.chmod" and len(args) > 1 and isinstance(args[1], ast.Constant) \
                and isinstance(args[1].value, int) and args[1].value & 0o002:
            self.report(node, "PY-CHMOD", "unsafe_file", "World-Writable Permissions",
                        f"os.chmod() sets world-writable mode {oct(args[1].value)}.", False)

    def check_html_return(self, node, value, fn, st):
        if isinstance(value, ast.Call) or self.pieces(value) is None:
            return
        if not self.is_dynamic(value, st, "xss") or not self.is_tainted(value, st, "xss"):
            return
        literal = " ".join(str(n.value) for n in ast.walk(value)
                           if isinstance(n, ast.Constant) and isinstance(n.value, str))
        if "<" in literal:
            self.report(node, "PY-XSS", "xss", "Cross-Site Scripting",
                        "User input is interpolated into an HTML response without escaping.", True,
                        via=self.via(fn, value, "xss") if fn is not None else "")

    def check_module_assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id.upper() == "DEBUG" \
                    and isinstance(node.value, ast.Constant) and node.value.value is True:
                self.report(node, "PY-DEBUG-FLAG", "insecure_config", "Debug Mode Enabled",
                            "DEBUG = True is set in module configuration.", False)


def scan_python(source_file, text, lines):
    try:
        tree = ast.parse(text, filename=source_file.rel)
    except (SyntaxError, ValueError, RecursionError):
        return []
    return _Analyzer(tree, source_file, lines).run()
