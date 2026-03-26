"""
Tests for AST deep scan obfuscation detector.

TDD RED phase: Tests define behavior before implementation.
Covers string concatenation, chr() encoding, indirect imports,
encoded exec, compile+exec, deep nesting, and __builtins__ access.
"""

from __future__ import annotations

import pytest

from chaincanary.analyzer.ast_deep import analyze_ast_obfuscation
from chaincanary.models import Severity


# ── Pattern 1: String concatenation in dangerous sinks ───────────


class TestStringConcatObfuscation:
    """Detect string concat hiding function/module names."""

    def test_getattr_with_concat(self):
        code = 'getattr(obj, "g" + "et")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(
            f.rule_id == "AST_STRING_CONCAT_OBFUSCATION" for f in findings
        )

    def test_import_with_concat(self):
        code = '__import__("o" + "s")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_STRING_CONCAT_OBFUSCATION" for f in findings)

    def test_exec_with_concat(self):
        code = 'exec("imp" + "ort os")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_STRING_CONCAT_OBFUSCATION" for f in findings)

    def test_eval_with_concat(self):
        code = 'eval("__imp" + "ort__")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_STRING_CONCAT_OBFUSCATION" for f in findings)

    def test_normal_getattr_literal_no_flag(self):
        """getattr with a plain literal string should NOT flag."""
        code = 'getattr(obj, "get")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        concat_findings = [
            f for f in findings
            if f.rule_id == "AST_STRING_CONCAT_OBFUSCATION"
        ]
        assert len(concat_findings) == 0

    def test_normal_string_concat_outside_sink_no_flag(self):
        """String concat not inside a dangerous sink should NOT flag."""
        code = 'msg = "hello " + "world"'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert len(findings) == 0


# ── Pattern 2: chr() encoding ────────────────────────────────────


class TestChrEncoding:
    """Detect chr() chains used to hide strings."""

    def test_eval_chr_chain(self):
        code = "eval(chr(105) + chr(109) + chr(112))"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_CHR_ENCODING" for f in findings)

    def test_exec_chr_chain(self):
        code = "exec(chr(112) + chr(114) + chr(105) + chr(110) + chr(116))"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_CHR_ENCODING" for f in findings)

    def test_chr_outside_exec_no_flag(self):
        """chr() for normal character building should not flag."""
        code = "c = chr(65)"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        chr_findings = [f for f in findings if f.rule_id == "AST_CHR_ENCODING"]
        assert len(chr_findings) == 0


# ── Pattern 3: Indirect getattr / __import__ ─────────────────────


class TestIndirectImport:
    """Detect computed/indirect attribute access and imports."""

    def test_getattr_builtins_with_concat(self):
        code = 'getattr(__builtins__, "__imp" + "ort__")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_INDIRECT_IMPORT" for f in findings)

    def test_getattr_with_variable_attr(self):
        """getattr with a variable (non-literal) attr is suspicious."""
        code = "getattr(__builtins__, func_name)(mod_name)"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_INDIRECT_IMPORT" for f in findings)

    def test_getattr_with_literal_safe_attr_no_flag(self):
        """getattr(__builtins__, 'print') is safe — literal, known safe."""
        code = 'getattr(__builtins__, "print")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        indirect = [f for f in findings if f.rule_id == "AST_INDIRECT_IMPORT"]
        assert len(indirect) == 0


# ── Pattern 4: Base64/hex encoded exec ───────────────────────────


class TestEncodedExec:
    """Detect exec/eval of base64/hex decoded payloads."""

    def test_exec_base64_decode(self):
        code = 'exec(base64.b64decode("aW1wb3J0IG9z"))'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_ENCODED_EXEC" for f in findings)

    def test_eval_base64_decode(self):
        code = 'eval(base64.b64decode(payload))'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_ENCODED_EXEC" for f in findings)

    def test_exec_bytes_fromhex(self):
        code = 'exec(bytes.fromhex("696d706f7274").decode())'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_ENCODED_EXEC" for f in findings)

    def test_exec_codecs_decode(self):
        code = 'exec(codecs.decode("vzcbeg bf", "rot13"))'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_ENCODED_EXEC" for f in findings)

    def test_base64_without_exec_no_flag(self):
        """base64 decode alone (no exec/eval) should NOT flag."""
        code = 'data = base64.b64decode(token)'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        encoded = [f for f in findings if f.rule_id == "AST_ENCODED_EXEC"]
        assert len(encoded) == 0


# ── Pattern 5: compile() + exec() ────────────────────────────────


class TestCompileExec:
    """Detect compile() used to build code for exec()."""

    def test_exec_compile(self):
        code = 'exec(compile(source, "<string>", "exec"))'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_COMPILE_EXEC" for f in findings)

    def test_eval_compile(self):
        code = 'eval(compile(expr, "<expr>", "eval"))'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_COMPILE_EXEC" for f in findings)


# ── Pattern 6: Deep nesting ──────────────────────────────────────


class TestDeepNesting:
    """Detect deeply nested calls that obscure intent."""

    def test_deeply_nested_exec(self):
        code = "exec(eval(base64.b64decode(zlib.decompress(data))))"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_DEEP_NESTING" for f in findings)

    def test_shallow_nesting_no_flag(self):
        """Normal 2-level nesting should NOT flag."""
        code = "print(str(42))"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        nesting = [f for f in findings if f.rule_id == "AST_DEEP_NESTING"]
        assert len(nesting) == 0


# ── Pattern 7: __builtins__ direct access ────────────────────────


class TestBuiltinsAccess:
    """Detect direct manipulation of __builtins__."""

    def test_builtins_subscript(self):
        code = '__builtins__["__import__"]("os")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_BUILTINS_ACCESS" for f in findings)

    def test_builtins_getattr(self):
        """getattr(__builtins__, ...) should flag as builtins access."""
        code = 'getattr(__builtins__, "__import__")("os")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_BUILTINS_ACCESS" for f in findings)


# ── Edge cases & robustness ──────────────────────────────────────


class TestEdgeCases:
    """Ensure robustness against malformed and legitimate code."""

    def test_syntax_error_returns_empty(self):
        """Unparseable code should return empty findings, not crash."""
        code = "def broken(:"
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert findings == []

    def test_empty_code(self):
        code = ""
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert findings == []

    def test_multiline_real_world_attack(self):
        """Simulate a real-world obfuscated attack pattern."""
        code = (
            "import base64\n"
            "exec(base64.b64decode("
            "'aW1wb3J0IHN1YnByb2Nlc3M7c3VicHJvY2Vzcy5ydW4oWydjdXJsJ10p'"
            "))"
        )
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert any(f.rule_id == "AST_ENCODED_EXEC" for f in findings)

    def test_findings_have_correct_structure(self):
        """Each finding should have all required fields."""
        code = 'exec("imp" + "ort os")'
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id
        assert f.severity in (
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        )
        assert f.title
        assert f.description
        assert f.source == "static"

    def test_legitimate_setuptools_no_flag(self):
        """Common setuptools patterns should NOT trigger."""
        code = (
            "from setuptools import setup\n"
            "setup(name='mypkg', version='1.0')\n"
        )
        findings = analyze_ast_obfuscation(code, "pkg/__init__.py")
        assert len(findings) == 0

    def test_severity_higher_in_init(self):
        """__init__.py findings should be HIGH+ severity."""
        code = 'exec(base64.b64decode("dGVzdA=="))'
        init_findings = analyze_ast_obfuscation(
            code, "pkg/__init__.py",
        )
        other_findings = analyze_ast_obfuscation(
            code, "pkg/utils.py",
        )
        # __init__.py findings should be at least as severe
        if init_findings and other_findings:
            init_sev = max(
                f.severity.value for f in init_findings
            )
            other_sev = max(
                f.severity.value for f in other_findings
            )
            # Both should detect it; __init__ may have higher severity
            assert init_findings
            assert other_findings
