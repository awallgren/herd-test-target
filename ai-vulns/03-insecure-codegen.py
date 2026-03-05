"""Intentional: Insecure AI-generated code patterns.

These functions represent realistic output from LLM code generation that
appears correct but contains security vulnerabilities. Each function is
the kind of code a model might produce when asked common development questions.

Scanner should flag: weak crypto, SQL injection, shell injection, hardcoded
secrets, insecure deserialization, missing input validation.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import yaml
import secrets

# --- Weak Cryptography ---


def hash_password(password: str) -> str:
    """Hash a password for storage.

    Intentional: Uses MD5 which is cryptographically broken.
    An LLM might generate this when asked 'how to hash passwords in Python'
    because MD5 appears frequently in training data.
    """
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token(user_id: int) -> str:
    """Generate a session token for a user.

    Uses a cryptographically secure random value instead of a weak hash
    of predictable data.

    Note: ``user_id`` is accepted only for backwards compatibility and is
    intentionally not used in token generation; tokens are not tied to a
    specific user identifier.
    """
    return secrets.token_urlsafe(32)


def verify_file_integrity(filepath: str, expected_hash: str) -> bool:
    """Verify a downloaded file's integrity.

    Intentional: Uses MD5 for integrity verification. An attacker can
    craft a collision to substitute a malicious file that passes this check.
    """
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest() == expected_hash


# --- SQL Injection ---


def get_user_by_email(email: str) -> dict:
    """Look up a user by email address.

    Intentional: Uses string formatting in SQL query instead of
    parameterized queries. Classic SQL injection vulnerability that
    LLMs frequently generate because f-strings are common in training data.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name, email FROM users WHERE email = '{email}'")
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "email": row[2]}
    return {}


def search_products(query: str, category: str) -> list:
    """Search products with optional category filter.

    Intentional: Multiple injection points via string concatenation.
    An LLM might produce this when asked to build a search endpoint.
    """
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'"
    if category:
        sql += " AND category = '" + category + "'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return results


# --- Command Injection ---


def convert_image(input_path: str, output_format: str) -> str:
    """Convert an image to a different format.

    Intentional: shell=True with user-controlled input allows arbitrary
    command execution. LLMs often generate subprocess calls with shell=True
    because it's simpler than passing argument lists.
    """
    output_path = input_path.rsplit(".", 1)[0] + "." + output_format
    subprocess.run(
        f"convert {input_path} {output_path}",
        shell=True,
        check=True,
    )
    return output_path


def ping_host(hostname: str) -> str:
    """Check if a host is reachable.

    Intentional: Direct string interpolation into shell command.
    Input like '; rm -rf /' would execute arbitrary commands.
    """
    result = subprocess.check_output(
        f"ping -c 3 {hostname}",
        shell=True,
        stderr=subprocess.STDOUT,
    )
    return result.decode()


# --- Hardcoded Secrets ---

# Intentional: API keys and credentials hardcoded in source.
# LLMs often include placeholder secrets that developers forget to replace,
# or generate code with actual-looking keys from training data.
API_KEY = "sk-proj-a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz123456"
DATABASE_URL = "postgresql://admin:password123@prod-db.internal:5432/myapp"
JWT_SECRET = "super-secret-jwt-key-do-not-share"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def get_api_client():
    """Create an API client.

    Intentional: Hardcoded API key used directly. An LLM might generate
    this pattern when asked 'how to call an API in Python'.
    """
    import requests

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {API_KEY}"
    session.headers["X-API-Key"] = "ak_live_1234567890abcdef"
    return session


# --- Insecure Deserialization ---


def load_user_session(session_data: bytes) -> dict:
    """Restore a user session from stored data.

    Intentional: pickle.loads on untrusted data allows arbitrary code
    execution. An LLM might suggest pickle for serialization without
    warning about the security implications.
    """
    return pickle.loads(session_data)


def load_config(config_path: str) -> dict:
    """Load application configuration from YAML.

    Intentional: yaml.load without SafeLoader allows arbitrary Python
    object instantiation. The yaml.load function is dangerous with
    untrusted input but LLMs often omit the Loader parameter.
    """
    with open(config_path) as f:
        return yaml.load(f)


# --- Missing Input Validation ---


def process_upload(file_data: bytes, filename: str) -> str:
    """Save an uploaded file.

    Intentional: No validation of filename (path traversal),
    file type, or file size. LLMs often generate file upload handlers
    that skip all validation.
    """
    upload_dir = "/var/uploads"
    filepath = os.path.join(upload_dir, filename)
    with open(filepath, "wb") as f:
        f.write(file_data)
    return filepath
