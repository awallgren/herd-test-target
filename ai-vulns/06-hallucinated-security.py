try:
            # Limit split to a single separator to avoid ValueError on extra colons
            salt_hex, expected_hash = stored.split(":", 1)
            salt = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            # Malformed stored value (missing/extra colon, non-hex salt, wrong type)
            # Return False to honor the boolean contract of this method.
            return False
