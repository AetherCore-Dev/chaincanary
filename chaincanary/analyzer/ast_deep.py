"""
AST-based obfuscation detector for Python source files.

Complements regex-based detection in static.py by catching patterns
that require structural analysis — string concatenation, chr() encoding,
indirect imports, encoded exec payloads, and deep call nesting.

This module NEVER executes analyzed code. It only parses the AST.
"""

from __future__ import annotations

import ast

from chaincanary.models import Finding, Severity

# Sinks where string obfuscation is suspicious
_DANGEROUS_SINKS = frozenset({
    "exec", "eval", "__import__", "getattr", "setattr",
    "delattr", "compile",
})

# Known safe attributes for getattr(__builtins__, ...) calls
_SAFE_BUILTINS = frozenset({
    "print", "len", "range", "int", "str", "float", "list",
    "dict", "set", "tuple", "bool", "type", "isinstance",
    "issubclass", "hasattr", "id", "repr", "abs", "min",
    "max", "sum", "sorted", "reversed", "enumerate", "zip",
    "map", "filter", "any", "all", "iter", "next", "hash",
    "hex", "oct", "bin", "ord", "pow", "round", "format",
    "input", "open", "super", "property", "staticmethod",
    "classmethod", "object", "vars", "dir",
})

# Encoding/decoding functions that are suspicious inside exec/eval
_ENCODING_FUNCS = frozenset({
    "b64decode", "b64encode", "decodebytes",
    "fromhex", "decode",
    # codecs
    "codecs.decode", "codecs.encode",
})

# Nesting depth threshold for flagging
_NESTING_THRESHOLD = 4


def analyze_ast_obfuscation(
    code: str,
    filename: str,
) -> list[Finding]:
    """
    Analyze Python source code for AST-level obfuscation patterns.

    Args:
        code: Python source code string.
        filename: File path (used for severity: __init__.py → higher).

    Returns:
        List of Finding objects for detected obfuscation patterns.
    """
    if not code or not code.strip():
        return []

    # Guard against pathologically large files
    if len(code) > 2 * 1024 * 1024:  # 2 MB
        return [Finding(
            rule_id="AST_FILE_TOO_LARGE",
            severity=Severity.MEDIUM,
            title=f"File too large for AST analysis ({len(code) // 1024} KB)",
            description="Skipped AST deep scan due to file size.",
            source="static",
        )]

    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        return []

    is_init = filename.endswith("__init__.py")
    visitor = _ObfuscationVisitor(filename=filename, is_init=is_init)

    try:
        visitor.visit(tree)
    except RecursionError:
        return [Finding(
            rule_id="AST_EXCESSIVE_NESTING",
            severity=Severity.HIGH,
            title="AST analysis aborted: pathologically deep nesting",
            description=(
                "File AST exceeded recursion limit — "
                "likely obfuscation or malformed code."
            ),
            source="static",
        )]

    return visitor.findings


class _ObfuscationVisitor(ast.NodeVisitor):
    """Single-pass AST visitor detecting obfuscation patterns."""

    def __init__(self, filename: str, is_init: bool) -> None:
        self.filename = filename
        self.is_init = is_init
        self.findings: list[Finding] = []
        self._builtins_flagged_nodes: set[int] = set()  # deduplicate

    # ── Pattern dispatch: Call nodes ─────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node)

        if name:
            self._check_string_concat_in_sink(node, name)
            self._check_chr_encoding(node, name)
            self._check_indirect_import(node, name)
            self._check_encoded_exec(node, name)
            self._check_compile_exec(node, name)
            self._check_builtins_access_via_getattr(node, name)

        self._check_deep_nesting(node)

        # Continue visiting child nodes
        self.generic_visit(node)

    # ── Pattern dispatch: Subscript nodes ────────────────────────

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        self._check_builtins_subscript(node)
        self.generic_visit(node)

    # ── Pattern 1: String concatenation in dangerous sinks ───────

    def _check_string_concat_in_sink(
        self, node: ast.Call, name: str,
    ) -> None:
        if name not in _DANGEROUS_SINKS:
            return
        for arg in node.args:
            if _is_string_concat(arg):
                resolved = _resolve_concat(arg)
                evidence = f"Resolved: {resolved!r}" if resolved else ""
                self._add_finding(
                    rule_id="AST_STRING_CONCAT_OBFUSCATION",
                    severity=Severity.HIGH,
                    title=(
                        f"String concatenation inside {name}() "
                        "hides true argument"
                    ),
                    description=(
                        f"The call to {name}() uses string concatenation "
                        "to obscure its argument. This is a common "
                        "obfuscation technique in supply chain attacks."
                    ),
                    evidence=evidence,
                )

    # ── Pattern 2: chr() encoding ────────────────────────────────

    def _check_chr_encoding(
        self, node: ast.Call, name: str,
    ) -> None:
        if name not in ("exec", "eval", "__import__"):
            return
        for arg in node.args:
            if _contains_chr_chain(arg):
                self._add_finding(
                    rule_id="AST_CHR_ENCODING",
                    severity=Severity.HIGH,
                    title=(
                        f"chr() chain inside {name}() encodes hidden string"
                    ),
                    description=(
                        f"The call to {name}() builds a string using "
                        "chr() calls to hide its content. "
                        "Example: chr(105)+chr(109) → 'im'."
                    ),
                )

    # ── Pattern 3: Indirect getattr / __import__ ─────────────────

    def _check_indirect_import(
        self, node: ast.Call, name: str,
    ) -> None:
        if name != "getattr" or len(node.args) < 2:
            return

        target = node.args[0]
        attr_arg = node.args[1]

        # Only flag when accessing __builtins__ or similar
        target_name = _node_name(target)
        if target_name not in ("__builtins__", "__builtin__"):
            return

        # Variable (non-literal) attr → suspicious
        if not isinstance(attr_arg, ast.Constant):
            self._builtins_flagged_nodes.add(id(node))
            self._add_finding(
                rule_id="AST_INDIRECT_IMPORT",
                severity=Severity.CRITICAL,
                title="Computed attribute on __builtins__",
                description=(
                    "getattr(__builtins__, <variable>) uses a "
                    "non-literal attribute name. This hides what "
                    "builtin is being accessed."
                ),
            )
            return

        # String concat in attr → suspicious
        if _is_string_concat(attr_arg):
            resolved = _resolve_concat(attr_arg)
            self._builtins_flagged_nodes.add(id(node))
            self._add_finding(
                rule_id="AST_INDIRECT_IMPORT",
                severity=Severity.CRITICAL,
                title="Obfuscated __builtins__ access via concat",
                description=(
                    "getattr(__builtins__, ...) uses string concatenation "
                    "to hide the attribute name."
                ),
                evidence=f"Resolved: {resolved!r}" if resolved else "",
            )
            return

        # Literal but safe → no flag
        if isinstance(attr_arg.value, str):
            if attr_arg.value in _SAFE_BUILTINS:
                return
            # Literal but dangerous (e.g., "__import__") — already
            # caught by builtins_access pattern, skip here to avoid dup

    # ── Pattern 4: Encoded exec/eval ─────────────────────────────

    def _check_encoded_exec(
        self, node: ast.Call, name: str,
    ) -> None:
        if name not in ("exec", "eval"):
            return
        for arg in node.args:
            if _contains_encoding_call(arg):
                enc_name = _find_encoding_func_name(arg)
                self._add_finding(
                    rule_id="AST_ENCODED_EXEC",
                    severity=Severity.HIGH,
                    title=(
                        f"{name}() with encoded payload"
                        f"{f' via {enc_name}' if enc_name else ''}"
                    ),
                    description=(
                        f"The call to {name}() wraps an encoding/decoding "
                        "function. This is a common technique to hide "
                        "malicious payloads in supply chain attacks."
                    ),
                )

    # ── Pattern 5: compile() + exec() ────────────────────────────

    def _check_compile_exec(
        self, node: ast.Call, name: str,
    ) -> None:
        if name not in ("exec", "eval"):
            return
        for arg in node.args:
            if isinstance(arg, ast.Call) and _call_name(arg) == "compile":
                self._add_finding(
                    rule_id="AST_COMPILE_EXEC",
                    severity=Severity.HIGH,
                    title=f"{name}(compile(...)) dynamically compiles code",
                    description=(
                        f"compile() is used to build code that is then "
                        f"passed to {name}(). This obscures the actual "
                        "code being executed."
                    ),
                )

    # ── Pattern 6: Deep nesting ──────────────────────────────────

    def _check_deep_nesting(self, node: ast.Call) -> None:
        depth = _call_depth(node)
        if depth >= _NESTING_THRESHOLD:
            self._add_finding(
                rule_id="AST_DEEP_NESTING",
                severity=Severity.MEDIUM,
                title=f"Deeply nested calls ({depth} levels)",
                description=(
                    f"A call chain is nested {depth} levels deep. "
                    "Excessive nesting can obscure malicious intent "
                    "(e.g., exec(eval(b64decode(decompress(...)))))."
                ),
            )

    # ── Pattern 7a: __builtins__ via getattr ─────────────────────

    def _check_builtins_access_via_getattr(
        self, node: ast.Call, name: str,
    ) -> None:
        if name != "getattr" or len(node.args) < 2:
            return
        # Skip if already flagged by _check_indirect_import
        if id(node) in self._builtins_flagged_nodes:
            return
        target_name = _node_name(node.args[0])
        if target_name in ("__builtins__", "__builtin__"):
            attr = node.args[1]
            # Only flag dangerous builtins, not safe ones
            if isinstance(attr, ast.Constant) and isinstance(
                attr.value, str,
            ):
                if attr.value in _SAFE_BUILTINS:
                    return
            self._add_finding(
                rule_id="AST_BUILTINS_ACCESS",
                severity=Severity.HIGH,
                title="Direct __builtins__ attribute access",
                description=(
                    "Code accesses __builtins__ directly via getattr(). "
                    "This is typically used to bypass import detection "
                    "or access dangerous builtins."
                ),
            )

    # ── Pattern 7b: __builtins__["..."] subscript ────────────────

    def _check_builtins_subscript(self, node: ast.Subscript) -> None:
        val_name = _node_name(node.value)
        if val_name not in ("__builtins__", "__builtin__"):
            return
        # Check if accessing a dangerous key
        if isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                if node.slice.value in _SAFE_BUILTINS:
                    return
        self._add_finding(
            rule_id="AST_BUILTINS_ACCESS",
            severity=Severity.HIGH,
            title="Direct __builtins__ subscript access",
            description=(
                "Code accesses __builtins__[...] directly. "
                "This technique bypasses normal import tracking."
            ),
        )

    # ── Finding builder ──────────────────────────────────────────

    def _add_finding(
        self,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        evidence: str = "",
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                source="static",
            )
        )


# ═══════════════════════════════════════════════════════════════════
# Helper functions (pure, stateless)
# ═══════════════════════════════════════════════════════════════════


def _call_name(node: ast.Call) -> str | None:
    """Extract the function name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _node_name(node: ast.expr) -> str | None:
    """Extract a simple name from a Name node."""
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_string_concat(node: ast.expr) -> bool:
    """Check if node is a BinOp chain of string additions."""
    if not isinstance(node, ast.BinOp):
        return False
    if not isinstance(node.op, ast.Add):
        return False
    return _is_string_leaf_or_concat(node.left) and _is_string_leaf_or_concat(
        node.right,
    )


def _is_string_leaf_or_concat(node: ast.expr) -> bool:
    """Check if node is either a string constant or a string concat."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_string_leaf_or_concat(
            node.left,
        ) and _is_string_leaf_or_concat(node.right)
    # chr() calls are also string-producing
    if isinstance(node, ast.Call) and _call_name(node) == "chr":
        return True
    return False


def _resolve_concat(node: ast.expr) -> str | None:
    """Try to statically resolve a string concatenation to its value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_concat(node.left)
        right = _resolve_concat(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _contains_chr_chain(node: ast.expr) -> bool:
    """Check if node contains a chain of chr() calls joined by +."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # At least one side must have chr()
        return _has_chr_call(node)
    return False


def _has_chr_call(node: ast.expr) -> bool:
    """Recursively check if any part of BinOp chain has chr()."""
    if isinstance(node, ast.Call) and _call_name(node) == "chr":
        return True
    if isinstance(node, ast.BinOp):
        return _has_chr_call(node.left) or _has_chr_call(node.right)
    return False


def _contains_encoding_call(node: ast.expr) -> bool:
    """Check if node or its children contain an encoding/decoding call."""
    if isinstance(node, ast.Call):
        name = _full_call_name(node)
        if name and any(ef in name for ef in _ENCODING_FUNCS):
            return True
        # Check arguments recursively
        for arg in node.args:
            if _contains_encoding_call(arg):
                return True
    # Check .decode() chains: bytes.fromhex(...).decode()
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _contains_encoding_call(node.func.value)
    return False


def _find_encoding_func_name(node: ast.expr) -> str | None:
    """Find the encoding function name in a call tree."""
    if isinstance(node, ast.Call):
        name = _full_call_name(node)
        if name and any(ef in name for ef in _ENCODING_FUNCS):
            return name
        for arg in node.args:
            result = _find_encoding_func_name(arg)
            if result:
                return result
        if isinstance(node.func, ast.Attribute):
            return _find_encoding_func_name(node.func.value)
    return None


def _full_call_name(node: ast.Call) -> str | None:
    """Get the full dotted call name (e.g., 'base64.b64decode')."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current: ast.expr = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _call_depth(node: ast.Call, depth: int = 1) -> int:
    """Count the nesting depth of Call nodes."""
    max_depth = depth
    for arg in node.args:
        if isinstance(arg, ast.Call):
            child_depth = _call_depth(arg, depth + 1)
            max_depth = max(max_depth, child_depth)
    # Also check func (e.g., method calls on call results)
    if isinstance(node.func, ast.Attribute) and isinstance(
        node.func.value, ast.Call,
    ):
        child_depth = _call_depth(node.func.value, depth + 1)
        max_depth = max(max_depth, child_depth)
    return max_depth
