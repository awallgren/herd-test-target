"""Intentional: Sensitive context leakage to AI/LLM endpoints.

These patterns show code that sends secrets, stack traces, internal URLs,
private code, and PII to external SaaS AI services without data boundary
controls. This is the "shadow AI" problem — developers integrating AI
APIs without governance.

Scanner should flag: secrets in API payloads, PII sent to external
endpoints, internal URLs/paths leaked, no data classification, missing
DLP controls.
"""

import json
import os
import traceback
import requests


# --- Stack traces with secrets sent to AI for debugging ---


def ai_debug_error(error: Exception) -> str:
    """Send an error to an AI service for debugging help.

    Intentional: Sends full stack trace (which may contain secrets,
    file paths, database connection strings, internal hostnames) to
    an external AI API. Also includes environment variables.
    """
    full_trace = traceback.format_exc()

    # Intentional: collects ALL environment variables including secrets
    env_context = {k: v for k, v in os.environ.items()}

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Debug this error:\n\n{full_trace}\n\n"
                        f"Environment:\n{json.dumps(env_context, indent=2)}\n\n"
                        f"Database URL: {os.environ.get('DATABASE_URL', 'not set')}\n"
                        f"AWS Region: {os.environ.get('AWS_DEFAULT_REGION', 'not set')}\n"
                        f"Service: {os.environ.get('SERVICE_NAME', 'unknown')}"
                    ),
                }
            ],
        },
    )
    return response.json()["choices"][0]["message"]["content"]


# --- Source code sent to AI for review ---


def ai_code_review(file_path: str) -> str:
    """Send source code to AI for security review.

    Intentional: Sends proprietary source code to external AI service
    without data classification. The code may contain trade secrets,
    proprietary algorithms, hardcoded credentials, or internal API schemas.
    """
    with open(file_path) as f:
        source_code = f.read()

    # Intentional: reads .env file and includes it for "context"
    env_content = ""
    if os.path.exists(".env"):
        with open(".env") as f:
            env_content = f.read()

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "Content-Type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Review this code for security issues:\n\n"
                        f"```\n{source_code}\n```\n\n"
                        f"Environment config:\n{env_content}\n\n"
                        f"This runs on internal host: "
                        f"{os.environ.get('INTERNAL_HOST', 'app.corp.internal')}"
                    ),
                }
            ],
        },
    )
    return response.json()["content"][0]["text"]


# --- Customer data sent to AI for analysis ---


def ai_analyze_user_behavior(user_data: list[dict]) -> str:
    """Send user behavior data to AI for analysis.

    Intentional: Sends PII (names, emails, IP addresses, session data)
    to an external AI service. Violates GDPR, CCPA, and most data
    processing agreements.
    """
    # Intentional: no redaction of PII fields
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Analyze this user behavior data and identify patterns:\n\n"
                        f"{json.dumps(user_data, indent=2)}"
                    ),
                }
            ],
        },
    )
    return response.json()["choices"][0]["message"]["content"]


# --- Logs with secrets piped to AI ---


class AILogger:
    """Logger that sends error logs to AI for automatic analysis.

    Intentional: All log messages, including those containing secrets,
    tokens, and internal system details, are sent to an external AI
    service for "intelligent alerting."
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.buffer = []

    def log(self, level: str, message: str, context: dict = None):
        """Log a message and periodically flush to AI.

        Intentional: context dict may contain request headers (with
        auth tokens), database queries (with user data), or internal
        service URLs.
        """
        entry = {
            "level": level,
            "message": message,
            "context": context or {},
            "timestamp": __import__("time").time(),
            "hostname": os.uname().nodename,
            "pid": os.getpid(),
        }
        self.buffer.append(entry)

        if len(self.buffer) >= 10:
            self._flush()

    def _flush(self):
        """Send buffered logs to AI for analysis.

        Intentional: batch sends all accumulated logs including any
        secrets, tokens, or PII that were logged.
        """
        requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Analyze these application logs for errors, "
                            "anomalies, and security issues:\n\n"
                            f"{json.dumps(self.buffer, indent=2)}"
                        ),
                    }
                ],
            },
        )
        self.buffer = []


# --- Git diff with secrets sent for AI review ---


def ai_review_diff(repo_path: str) -> str:
    """Send git diff to AI for pre-commit review.

    Intentional: git diff may contain newly added secrets, API keys,
    or credentials. Sending the raw diff to an external service leaks them.
    """
    import subprocess

    diff = subprocess.check_output(
        ["git", "diff", "--cached"],
        cwd=repo_path,
    ).decode()

    # Intentional: also grabs git config which may contain tokens
    git_config = subprocess.check_output(
        ["git", "config", "--list"],
        cwd=repo_path,
    ).decode()

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Review this git diff for issues:\n\n{diff}\n\n"
                        f"Git config:\n{git_config}"
                    ),
                }
            ],
        },
    )
    return response.json()["choices"][0]["message"]["content"]
