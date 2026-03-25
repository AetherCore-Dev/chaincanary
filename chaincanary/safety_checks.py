"""
Package name safety checks.

1. Typosquatting detection — is this package suspiciously similar to a popular one?
2. Safe version validation — scan the recommended rollback version before suggesting it.
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Optional


# Top 200 most-downloaded PyPI packages (commonly typosquatted targets)
# Source: https://hugovk.github.io/top-pypi-packages/
_POPULAR_PACKAGES = {
    "requests", "urllib3", "setuptools", "pip", "wheel", "six", "certifi",
    "python-dateutil", "idna", "packaging", "cryptography", "boto3", "botocore",
    "pyyaml", "numpy", "pandas", "scipy", "matplotlib", "pillow", "sqlalchemy",
    "flask", "django", "fastapi", "uvicorn", "starlette", "pydantic", "httpx",
    "aiohttp", "click", "rich", "typer", "pytest", "pytest-cov", "mypy",
    "black", "ruff", "isort", "flake8", "pylint", "bandit", "safety",
    "pip-audit", "poetry", "hatch", "flit", "twine", "build",
    "openai", "anthropic", "langchain", "litellm", "transformers", "torch",
    "tensorflow", "keras", "scikit-learn", "xgboost", "lightgbm",
    "redis", "celery", "kombu", "billiard", "pymongo", "motor",
    "psycopg2", "psycopg2-binary", "asyncpg", "aiomysql", "pymysql",
    "boto", "s3transfer", "awscli", "google-cloud-storage", "azure-storage-blob",
    "paramiko", "fabric", "ansible", "docker", "kubernetes",
    "jwt", "pyjwt", "bcrypt", "passlib", "python-jose",
    "lxml", "beautifulsoup4", "selenium", "playwright", "scrapy",
    "arrow", "pendulum", "pytz", "tzdata",
    "attrs", "cattrs", "marshmallow", "cerberus",
    "jinja2", "mako", "chameleon",
    "werkzeug", "itsdangerous", "markupsafe",
    "grpcio", "protobuf", "thrift",
    "colorama", "termcolor", "tqdm", "alive-progress",
    "loguru", "structlog", "python-json-logger",
    "hypothesis", "faker", "factory-boy", "responses",
    "httpretty", "vcrpy", "respx",
    "invoke", "nox", "tox",
    "cachetools", "diskcache", "dogpile.cache",
    "pika", "kafka-python", "confluent-kafka",
    "stripe", "braintree", "paypalrestsdk",
    "twilio", "sendgrid", "mailchimp3",
    "sentry-sdk", "datadog", "newrelic",
    "prometheus-client", "opentelemetry-api",
    "psutil", "py-cpuinfo", "gputil",
    "pywin32", "pyobjc", "pyautogui",
    "cv2", "opencv-python", "imageio",
    "nltk", "spacy", "gensim", "textblob",
    "networkx", "igraph", "graph-tool",
}

# Normalise: lowercase, replace hyphens with underscores
def _norm(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _similarity(a: str, b: str) -> float:
    """SequenceMatcher similarity ratio [0, 1]."""
    return SequenceMatcher(None, a, b).ratio()


def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def check_typosquatting(package_name: str) -> Optional[dict]:
    """
    Check if a package name looks like a typosquat of a popular package.

    Returns a dict with match info, or None if no suspicious similarity found.
    """
    norm_input = _norm(package_name)

    best_match: Optional[str] = None
    best_distance = 999
    best_similarity = 0.0

    for popular in _POPULAR_PACKAGES:
        norm_popular = _norm(popular)

        if norm_input == norm_popular:
            return None  # exact match = this IS the popular package

        dist = _levenshtein(norm_input, norm_popular)
        sim = _similarity(norm_input, norm_popular)

        # Flag if: edit distance ≤ 2 AND similarity ≥ 0.75
        # (prevents flagging completely different short names)
        if dist <= 2 and sim >= 0.75:
            if dist < best_distance or (dist == best_distance and sim > best_similarity):
                best_distance = dist
                best_similarity = sim
                best_match = popular

    if best_match:
        return {
            "target": best_match,
            "distance": best_distance,
            "similarity": round(best_similarity, 3),
            "likely_typosquat": best_distance == 1,
        }
    return None


def check_git_dependency(raw_dep: str) -> bool:
    """Return True if the dependency is a git+https:// or git+ssh:// reference."""
    return raw_dep.strip().startswith(("git+", "-e git+", "git://"))
