def mac_block(mac: bytes) -> str:
    return f""",
{{
    "tag": "AuthenticatedEncryptionTag",
    "type": "ByteString",
    "value": "{mac.hex().upper()}"
}}
"""


def nonce_block(nonce: bytes) -> str:
    return f""",
    {{
        "tag": "IvCounterNonce",
        "type": "ByteString",
        "value": "{nonce.hex().upper()}"
    }}
    """