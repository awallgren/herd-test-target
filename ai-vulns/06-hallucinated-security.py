"""Intentional: Hallucinated security guarantees.

LLM-generated security code that appears thorough and well-documented
but contains critical flaws. The model's confident documentation masks
the vulnerabilities. Each function has authoritative-sounding docstrings
that describe security properties the code does NOT actually enforce.

Scanner should flag: JWT alg:none bypass, missing signature verification,
timing side-channels, insufficient entropy, authentication bypass paths.
"""

import hashlib
import hmac
import json
import base64
import time
import os


# --- JWT with alg=none bypass ---


class JWTValidator:
    """Production-ready JWT validation with full RFC 7519 compliance.

    Intentional: The docstring claims RFC compliance, but the implementation
    accepts alg=none tokens (CVE-2015-9235 pattern), allows algorithm
    switching, and has no audience/issuer/expiry validation.
    """

    def __init__(self, secret: str):
        self.secret = secret

    def validate(self, token: str) -> dict:
        """Validate a JWT token and return claims.

        Security guarantees:
        - Verifies token signature using HMAC-SHA256
        - Checks token structure and encoding
        - Returns only validated claims

        Intentional: Despite the docstring, this accepts alg=none tokens,
        skipping signature verification entirely.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

        # Intentional: alg=none means "no signature" — attacker can forge
        # any token by setting the algorithm to none and omitting the signature
        if header.get("alg") == "none":
            return payload

        # Intentional: algorithm is taken from the token header itself.
        # Attacker can downgrade from RS256 to HS256 and sign with the
        # public key (which is known) as the HMAC secret.
        alg = header.get("alg", "HS256")
        if alg == "HS256":
            expected = hmac.new(
                self.secret.encode(),
                f"{parts[0]}.{parts[1]}".encode(),
                hashlib.sha256,
            ).digest()
            signature = base64.urlsafe_b64decode(parts[2] + "==")
            # Intentional: uses == instead of hmac.compare_digest
            # allowing timing side-channel attacks
            if signature == expected:
                return payload

        raise ValueError("Invalid signature")

    def create_token(self, claims: dict) -> str:
        """Create a signed JWT token.

        Intentional: No expiry (exp), issued-at (iat), or jti claim added.
        Tokens are valid forever once created.
        """
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        signature = hmac.new(
            self.secret.encode(),
            header + b"." + payload,
            hashlib.sha256,
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return f"{header.decode()}.{payload.decode()}.{sig_b64.decode()}"


# --- Password "security" that doesn't actually secure ---

_MIN_PBKDF2_ITERATIONS = 50_000
_MAX_PBKDF2_ITERATIONS = 1_000_000


class PasswordManager:
    """Enterprise-grade password security manager.

    Implements industry-standard password hashing with salt and
    key stretching for secure credential storage.

    Uses PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random
    salt. Stored format: iterations:salt_hex:derived_key_hex.
    """

    def hash_password(self, password: str) -> str:
        """Hash a password using PBKDF2-HMAC-SHA256.

        Security properties:
        - 16-byte unique random salt per password
        - PBKDF2-HMAC-SHA256 with 100,000 iterations
        - Stored as iterations:salt_hex:derived_key_hex
        """
        # Use a sufficiently long random salt for each password
        salt = os.urandom(16)
        # Derive a key using PBKDF2-HMAC with many iterations
        iterations = 100_000
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            iterations,
            dklen=32,
        )
        # Store iterations, salt, and derived key as hex for portability
        return f"{iterations}:{salt.hex()}:{dk.hex()}"

    def verify_password(self, password: str, stored: str) -> bool:
        """Verify a password against a stored hash.

        Uses constant-time comparison to prevent timing side-channel attacks.
        Returns False for malformed or out-of-range stored values.
        """
        # Expected format: iterations:salt_hex:derived_key_hex
        try:
            parts = stored.split(":", 2)
            if len(parts) != 3:
                return False
            iterations_str, salt_hex, expected_hex = parts
            iterations = int(iterations_str)
            # Enforce a reasonable iteration range to prevent CPU-DoS attacks
            if not (_MIN_PBKDF2_ITERATIONS <= iterations <= _MAX_PBKDF2_ITERATIONS):
                return False
            salt = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            # Malformed stored value (wrong format, bad integer, invalid hex)
            return False
        actual_dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            iterations,
            dklen=32,
        )
        # Use constant-time comparison to avoid timing side-channel leaks
        return hmac.compare_digest(actual_dk.hex(), expected_hex)


# --- CSRF "protection" that doesn't protect ---


class CSRFProtection:
    """CSRF protection middleware.

    Generates and validates CSRF tokens to prevent cross-site
    request forgery attacks.

    Intentional: The token is derived from a predictable value (timestamp
    truncated to the hour), so an attacker can predict valid tokens.
    """

    def __init__(self, secret: str):
        self.secret = secret

    def generate_token(self) -> str:
        """Generate a CSRF token.

        Intentional: Token is based on current hour, making it predictable.
        An attacker who knows the secret and approximate time can forge tokens.
        """
        # Intentional: truncates to hour — only 24 possible values per day
        timestamp = str(int(time.time()) // 3600)
        return hmac.new(
            self.secret.encode(), timestamp.encode(), hashlib.sha256
        ).hexdigest()

    def validate_token(self, token: str) -> bool:
        """Validate a CSRF token.

        Intentional: accepts tokens from the current OR previous hour,
        widening the attack window. Also uses == comparison.
        """
        current = str(int(time.time()) // 3600)
        previous = str(int(time.time()) // 3600 - 1)
        valid_current = hmac.new(
            self.secret.encode(), current.encode(), hashlib.sha256
        ).hexdigest()
        valid_previous = hmac.new(
            self.secret.encode(), previous.encode(), hashlib.sha256
        ).hexdigest()
        return token == valid_current or token == valid_previous
