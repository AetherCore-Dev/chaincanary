"""AST deep visitor for suspicious pattern detection."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from chaincanary.analyzer._patterns import SENSITIVE_PATHS


@dataclass
class ASTFindings:
    exec_calls: list[str]
    eval_calls: list[str]
    network_calls: list[str]
    subprocess_calls: list[str]
    obfuscation: list[str]
    sensitive_paths: list[str]


class DeepVisitor(ast.NodeVisitor):
    """
    Walk AST and collect suspicious patterns with source locations.
    More precise than regex -- understands code structure.
    """

    def __init__(self):
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.network_calls: list[str] = []
        self.subprocess_calls: list[str] = []
        self.obfuscation: list[str] = []
        self.sensitive_paths: list[str] = []
        self._imports: set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        loc = f"line {node.lineno}"

        if name == "exec":
            # Check if argument contains base64 decode -- obfuscation
            if node.args and self._contains_b64(node.args[0]):
                self.obfuscation.append(f"exec(base64.decode(...)) at {loc}")
            else:
                self.exec_calls.append(f"exec() at {loc}")

        elif name == "eval":
            if node.args and self._contains_b64(node.args[0]):
                self.obfuscation.append(f"eval(base64.decode(...)) at {loc}")
            else:
                self.eval_calls.append(f"eval() at {loc}")

        elif name in ("urlopen", "urlretrieve"):
            self.network_calls.append(f"{name}() at {loc}")

        elif any(
            name.startswith(p)
            for p in (
                "requests.",
                "httpx.",
                "aiohttp.",
                "urllib.request.",
            )
        ):
            self.network_calls.append(f"{name}() at {loc}")

        elif name in ("system", "popen", "Popen"):
            self.subprocess_calls.append(f"{name}() at {loc}")
        elif any(name.startswith(p) for p in ("subprocess.", "os.system", "os.popen")):
            self.subprocess_calls.append(f"{name}() at {loc}")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            for p in SENSITIVE_PATHS:
                if re.search(p, node.value, re.IGNORECASE):
                    self.sensitive_paths.append(node.value[:80])
        self.generic_visit(node)

    def _contains_b64(self, node: ast.expr) -> bool:
        """Check if an AST node represents a base64 decode call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "b64decode"
        )

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return f"{self._node_name(node.func.value)}.{node.func.attr}"
        return ""

    def _node_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._node_name(node.value)}.{node.attr}"
        return "?"

    def to_findings(self) -> ASTFindings:
        return ASTFindings(
            exec_calls=self.exec_calls,
            eval_calls=self.eval_calls,
            network_calls=self.network_calls,
            subprocess_calls=self.subprocess_calls,
            obfuscation=self.obfuscation,
            sensitive_paths=self.sensitive_paths,
        )
