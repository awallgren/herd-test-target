try:
            parts = stored.split(":", 2)
            if len(parts) != 3:
                return False
            iterations_str, salt_hex, expected_hex = parts
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            # Malformed stored value (wrong format, bad integer, invalid hex)
            return False
