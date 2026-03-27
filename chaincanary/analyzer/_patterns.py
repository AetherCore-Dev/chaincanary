"""Pattern constants for static analysis."""

from __future__ import annotations

import re

# Network patterns in install hooks (setup.py, etc.)
NETWORK_PATTERNS = [
    r"\burllib\.request\b",
    r"\burllib2\.",
    r"\brequests\s*\.\s*(get|post|put|delete|head|request|Session)",
    r"\bhttpx\s*\.\s*(get|post|Client)",
    r"\baiohttp\s*\.",
    r"\bhttp\.client\b",
    r"\bsocket\.connect\b",
    r"\bsocket\.getaddrinfo\b",  # DNS exfil: encode data in hostname
    r"\bsocket\.gethostbyname\b",  # DNS exfil variant
    r"\burlopen\s*\(",
    r"\burlretrieve\s*\(",
]

# Subprocess in install hooks
SUBPROCESS_PATTERNS = [
    r"\bsubprocess\s*\.\s*(run|call|Popen|check_output|check_call)\b",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bPopen\s*\(",
]

# Obfuscation (applies everywhere)
OBFUSCATION_PATTERNS = [
    r"base64\.b64decode\s*\(.*?\)\s*[,)]\s*[\n\s]*exec",
    r"exec\s*\(\s*base64",
    r"eval\s*\(\s*base64",
    r"__import__\s*\(\s*['\"]base64['\"].*exec",
    r"zlib\.decompress\s*\(.*exec",
    r"marshal\.loads\s*\(",
    r"exec\s*\(\s*compile\s*\(",
]

# Sensitive paths accessed during install
SENSITIVE_PATHS = [
    r"~[/\\]\.ssh[/\\]",
    r"~[/\\]\.aws[/\\]",
    r"~[/\\]\.netrc\b",
    r"/etc/passwd\b",
    r"/etc/shadow\b",
    r"\.ssh[/\\]id_rsa\b",
    r"\.aws[/\\]credentials\b",
    r"~[/\\]\.config[/\\]gcloud",
]

CURL_WGET = [r"\bcurl\s", r"\bwget\s"]

# DNS exfiltration patterns -- encodes data into DNS lookups
DNS_EXFIL_PATTERNS = [
    r"socket\.getaddrinfo\s*\(",
    r"socket\.gethostbyname\s*\(",
    r"dns\.resolver\.",  # dnspython
    r"resolve\s*\(.*\..*\.",  # generic DNS resolve with dynamic hostname
]

# sys.modules indirect access (bypasses import name detection)
SYS_MODULES_PATTERNS = [
    r"sys\.modules\s*\[",
    r"sys\.modules\.get\s*\(",
]

# Network calls in ANY Python file (not just setup.py)
NETWORK_ANY_FILE = [
    r"\burlopen\s*\(",
    r"\brequests\.get\s*\(",
    r"\brequests\.post\s*\(",
    r"\bhttpx\.get\s*\(",
    r"\bsocket\.getaddrinfo\s*\(",  # DNS exfil
    r"\bsocket\.gethostbyname\s*\(",  # DNS exfil
]


def matches_any(text: str, patterns: list[str]) -> list[str]:
    """Return all patterns from *patterns* that match anywhere in *text*."""
    return [p for p in patterns if re.search(p, text, re.IGNORECASE | re.DOTALL)]
