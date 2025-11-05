#!/usr/bin/env python3
"""
Test script to verify password hash masking in logs
"""

import logging
import re
import sys

class SensitiveDataFilter(logging.Filter):
    """Filter to mask password hashes in log messages"""

    def __init__(self):
        super().__init__()
        # Patterns for password hashes that should be masked
        self.sensitive_patterns = [
            # Bcrypt password hashes (format: $2a/b/y$rounds$salt$hash)
            (r'\$2[aby]\$[0-9]{1,2}\$[A-Za-z0-9./]{53}', '[PASSWORD_HASH_MASKED]'),
            # SHA-256/512 password hashes (format: $5$ or $6$)
            (r'\$[56]\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}', '[PASSWORD_HASH_MASKED]'),
            # MD5 password hashes (format: $1$)
            (r'\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}', '[PASSWORD_HASH_MASKED]'),
            # Generic password hash patterns in VALUES clauses
            (r"VALUES\s*\(\s*[\'\"]\$[0-9a-zA-Z./]+\$[\'\"]", "VALUES('[PASSWORD_HASH_MASKED]'"),
            # Password hash in SET clauses
            (r"SET\s+password\s*=\s*[\'\"]\$[0-9a-zA-Z./]+\$[\'\"]", "SET password='[PASSWORD_HASH_MASKED]'"),
        ]

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            # Apply all masking patterns
            masked_msg = record.msg
            for pattern, replacement in self.sensitive_patterns:
                masked_msg = re.sub(pattern, replacement, masked_msg, flags=re.IGNORECASE)

            record.msg = masked_msg

        return True

def test_hash_masking():
    """Test that password hashes are properly masked"""

    # Create a test logger with our filter
    logger = logging.getLogger('test_logger')
    logger.setLevel(logging.DEBUG)

    # Create console handler for testing
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    # Add our sensitive data filter
    sensitive_filter = SensitiveDataFilter()
    handler.addFilter(sensitive_filter)

    logger.addHandler(handler)

    print("Testing Password Hash Masking")
    print("=" * 40)

    # Test cases with password hashes
    test_cases = [
        # Bcrypt hash
        "INSERT INTO users (password) VALUES ('$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LezKdskj7kQXJK4mO')",
        # SHA-256 hash
        "UPDATE users SET password='$5$salt$hashvaluehere123456789012345678901234567890123456789012345678901234567890'",
        # MD5 hash
        "INSERT INTO users (password) VALUES ('$1$salt$hashvaluehere123456789012345678901234567890')",
        # Normal SQL without hashes (should pass through)
        "SELECT id, name, email FROM users WHERE id = 1",
        # Mixed message with hash
        "User updated password to '$2a$12$newpasswordhash1234567890123456789012345678901234567890'",
    ]

    print("Testing SQL queries with password hashes:")
    print("-" * 40)

    for i, test_msg in enumerate(test_cases, 1):
        print(f"\nTest {i}:")
        print(f"Original: {test_msg}")
        logger.info(test_msg)
        print()

    print("Testing completed!")

if __name__ == '__main__':
    test_hash_masking()
