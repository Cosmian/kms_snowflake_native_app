from enum import Enum

class Algorithm(Enum):
    AES_GCM = 1
    AES_GCM_SIV = 2
    AES_XTS = 3
    CHACHA20_POLY1305 = 4

def to_padded_iv(input_string: str, algorithm: Algorithm) -> bytes:
    """
    Convert a string to a padded bytes IV for symmetric encryption
    Args:
        input_string: the string that will be used as a nonce
        algorithm: the algorithm used for encryption 

    Returns:
        bytes: the padded IV
    """
    # Convert string to bytes
    byte_array = input_string.encode('utf-8')

    if algorithm == Algorithm.AES_XTS:
        if len(byte_array) > 16:
            raise ValueError("AES XTS requires a nonce of 16 bytes maximum")
        padded_byte_array = byte_array.ljust(16, b'\0')
    else:
        if len(byte_array) > 12:
            raise ValueError(f"The nonce should be less than 12 bytes for {algorithm}")
        padded_byte_array = byte_array.ljust(12, b'\0')

    return padded_byte_array


def split_list(lst: list[bytes], parts: int) -> list[list[bytes]]:
    k, m = divmod(len(lst), parts)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(parts)]