from enum import Enum


class Algorithm(Enum):
    AES_GCM = 1
    AES_GCM_SIV = 2
    AES_XTS = 3
    CHACHA20_POLY1305 = 4


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

def split_list(lst: list[bytes], parts: int) -> list[list[bytes]]:
    k, m = divmod(len(lst), parts)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(parts)]