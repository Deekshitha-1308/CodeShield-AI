import ast
import re

RULES = [
    (r'\beval\s*\(', "High", "Security", "Use a safer parser or an explicit mapping instead of eval()."),
    (r'\bexec\s*\(', "High", "Security", "Avoid dynamic code execution; use explicit functions or validated inputs."),
    (r'\bpickle\.loads?\s*\(', "High", "Security", "Do not unpickle untrusted data. Prefer JSON for data exchange."),
    (r'\bsubprocess\.(?:run|Popen|call)\s*\([^)]*shell\s*=\s*True',
     "High", "Security", "Avoid shell=True with external input. Pass arguments as a list and validate inputs."),
    (r'\bdebug\s*=\s*True', "Medium", "Configuration", "Disable debug mode outside local development."),
    (r'\b(?:password|api_key|secret)\s*=\s*[\'"][^\'"]{4,}[\'"]',
     "High", "Secrets", "Move secrets to environment variables or a secret manager; rotate exposed credentials."),
    (r'\bassert\s+', "Low", "Reliability", "Do not use assert for input validation; assertions can be disabled."),
    (r'\bos\.system\s*\(', "High", "Security",
     "Avoid os.system() with user-controlled input. Use safer subprocess methods with validated arguments."),
    # Additional security rules
    (r'\bverify\s*=\s*False\b', "High", "Security",
     "TLS certificate verification is disabled. Enable certificate verification."),

    (r'\btempfile\.mktemp\s*\(', "High", "Security",
     "Avoid tempfile.mktemp(). Use safer temporary-file creation methods."),

    (r'\b(?:hashlib\.)?(?:md5|sha1)\s*\(', "Medium", "Security",
     "MD5 and SHA1 are unsuitable for security-sensitive hashing. Use an appropriate modern algorithm."),

    (r'\byaml\.load\s*\(', "High", "Security",
     "Review YAML loading. Use yaml.safe_load() for untrusted YAML."),
]

def analyze_code(code: str):
    findings = []
    lines = code.splitlines()

    def add(line, severity, category, message, evidence, suggestion):
        findings.append({
            "line": max(1, int(line)), "severity": severity, "category": category,
            "message": message, "evidence": evidence.strip()[:240], "suggestion": suggestion
        })

    # Pattern-based checks: fast, explainable baseline checks.
    for number, line in enumerate(lines, 1):
        for pattern, severity, category, suggestion in RULES:
            if re.search(pattern, line, re.IGNORECASE):
                label = {
                    "Security": "Potentially unsafe operation detected.",
                    "Secrets": "Possible hard-coded secret detected.",
                    "Configuration": "Potentially unsafe configuration detected.",
                    "Reliability": "Assertion used in application code."
                }.get(category, "Potential issue detected.")
                add(number, severity, category, label, line, suggestion)

        if re.search(r'\bexcept\s*:', line):
            add(number, "Medium", "Reliability",
                "Bare except catches nearly every exception and can hide errors.",
                line, "Catch specific exception types and handle them explicitly.")

        if "TODO" in line or "FIXME" in line:
            add(number, "Info", "Maintainability",
                "Unresolved TODO/FIXME marker found.", line,
                "Resolve the marker or create a tracked issue.")

    # AST-based checks: syntax and selected bug-prone patterns.
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        add(exc.lineno or 1, "High", "Bug",
            f"Python syntax error: {exc.msg}", lines[(exc.lineno or 1)-1] if lines else "",
            "Fix the syntax error before running or deploying this file.")
        return sorted(findings, key=lambda x: (["Critical","High","Medium","Low","Info"].index(x["severity"]), x["line"]))

    for node in ast.walk(tree):
        # 1. Detect unsafe subprocess shell execution
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""

            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    func_name = func.value.id + "." + func.attr

            if func_name in ("subprocess.run", "subprocess.call",
                             "subprocess.Popen"):
                for kw in node.keywords:
                    if (kw.arg == "shell" and
                            isinstance(kw.value, ast.Constant) and
                            kw.value.value is True):
                        add(node.lineno, "High", "Security",
                            "Subprocess is configured with shell=True.",
                            ast.get_source_segment(code, node) or "subprocess call",
                            "Avoid shell=True where possible. Pass validated arguments as a list.")

            # 2. Detect HTTP requests without timeout
            if func_name in (
                "requests.get", "requests.post",
                "requests.put", "requests.delete",
                "requests.patch"
            ):
                if not any(kw.arg == "timeout" for kw in node.keywords):
                    add(node.lineno, "Medium", "Reliability",
                        "HTTP request has no timeout configured.",
                        ast.get_source_segment(code, node) or "HTTP request",
                        "Set a reasonable timeout to prevent indefinite waiting.")

            # 3. Detect potentially unsafe YAML loading
            if func_name == "yaml.load":
                loader = next(
                    (kw.value for kw in node.keywords
                     if kw.arg == "Loader"),
                    None
                )

                safe_loader = (
                    isinstance(loader, ast.Name)
                    and loader.id in ("SafeLoader", "CSafeLoader")
                ) or (
                    isinstance(loader, ast.Attribute)
                    and loader.attr in ("SafeLoader", "CSafeLoader")
                )

                if not safe_loader:
                    add(node.lineno, "High", "Security",
                        "YAML is loaded without a recognized safe loader.",
                        ast.get_source_segment(code, node) or "yaml.load()",
                        "Use yaml.safe_load() when processing untrusted YAML.")

            # 4. Detect weak hashing functions
            if func_name in (
                "hashlib.md5", "hashlib.sha1", "md5", "sha1"
            ):
                add(node.lineno, "Medium", "Security",
                    "Weak hashing algorithm detected.",
                    ast.get_source_segment(code, node) or func_name,
                    "Use a modern hash algorithm for security-sensitive applications.")

            # 5. Detect unsafe temporary filename creation
            if func_name == "tempfile.mktemp":
                add(node.lineno, "High", "Security",
                    "Unsafe temporary filename creation detected.",
                    ast.get_source_segment(code, node) or func_name,
                    "Use tempfile.NamedTemporaryFile() or another secure temporary-file API.")

        # 6. Detect mutable default function arguments
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = node.args.defaults + [
                d for d in node.args.kw_defaults if d is not None
            ]

            for default in defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    add(node.lineno, "Medium", "Bug",
                        "Mutable default argument detected.",
                        f"Function: {node.name}",
                        "Use None as the default and create a new collection inside the function.")
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                if isinstance(node.right, ast.Constant) and node.right.value == 0:
                    add(node.lineno, "High", "Bug",
                        "Division or modulo by zero detected.",
                        ast.get_source_segment(code, node) or "division by zero",
                        "Check that the divisor is not zero before performing the operation.")
        if isinstance(node, ast.FunctionDef) and len(node.args.args) > 6:
            add(node.lineno, "Low", "Maintainability",
                f"Function '{node.name}' has many parameters.",
                f"def {node.name}(...)",
                "Consider grouping related parameters into a dataclass or configuration object.")

        if isinstance(node, ast.Compare):
            # Common Python bug: comparing values with `is` instead of equality.
            if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
                left = ast.get_source_segment(code, node) or "identity comparison"
                if not re.search(r'\b(?:None|True|False)\b', left):
                    add(node.lineno, "Medium", "Bug",
                        "Identity comparison may be incorrect for value comparison.",
                        left, "Use == or != for value comparison; reserve 'is' for singleton checks such as None.")

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            has_with = any(isinstance(parent, (ast.With, ast.AsyncWith)) and
                           node in ast.walk(parent) for parent in ast.walk(tree))
            if not has_with:
                add(node.lineno, "Low", "Reliability",
                    "File opened without an obvious context manager.",
                    ast.get_source_segment(code, node) or "open(...)",
                    "Prefer: with open(path, encoding='utf-8') as file: ...")

    # Duplicate exact non-empty lines can indicate accidental repeated code.
    seen = {}
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if len(stripped) > 12 and not stripped.startswith("#"):
            if stripped in seen:
                add(number, "Info", "Maintainability",
                    f"Repeated line also appears on line {seen[stripped]}.",
                    stripped, "Check whether the repeated statement is intentional.")
            else:
                seen[stripped] = number

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique = []
    keys = set()
    for f in findings:
        key = (f["line"], f["category"], f["message"])
        if key not in keys:
            keys.add(key)
            unique.append(f)
    return sorted(unique, key=lambda x: (order.get(x["severity"], 9), x["line"]))
