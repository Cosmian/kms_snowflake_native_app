###
# Copyright (c) 2023, Cosmian Technologies SAS
# All rights reserved.
#
# These tests code requires a working Cosmian KMS server
#
###


import pandas as pd
import random
import logging

from cosmian_kms import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_aes_gcm_siv, decrypt_aes_gcm_siv
from initialize import NUM_THREADS

logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})

key_id = '0d319307-f766-4869-b90a-02096edb9431'


def test_performance_aes_gcm_udf():
    _performance_aes_gcm_udf(1)
    _performance_aes_gcm_udf(2)
    _performance_aes_gcm_udf(100001)


def _performance_aes_gcm_udf(batch_size: int):
    plaintext_size = 64
    slog.info(f"Testing AES GCM performance with batch size {batch_size}")

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes_gcm(data_frame)
    # do some verifications
    assert len(encryptions) == batch_size
    for v in encryptions.values:
        assert len(v) == plaintext_size + 12 + 16

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: encryptions.values})
    recovered = decrypt_aes_gcm(data_frame)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == recovered[i]


def test_performance_aes_gcm_siv_udf():
    _performance_aes_gcm_siv_udf(1)
    _performance_aes_gcm_siv_udf(2)
    _performance_aes_gcm_siv_udf(100001)


def simulate_snowflake_udf():
    """
    Simulate the behavior of a snowflake UDF
    """
    num_workers = 4
    num_batches = 100
    batch_size = 4000
    plaintext_size = 64
    nonce_str = 'abcde'

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        executor.map(_performance_aes_gcm_siv_udf, [batch_size for _ in range(num_batches)])
    #


def encrypt_batch_with_aes_gcm_siv(batch_size: int, nonce_str: str, plaintext_size: int) -> (pd.DataFrame, list[bytes]):
    """
    Encrypt a batch of data with AES GCM SIV
    """
    keys: list[str] = [key_id for _ in range(batch_size)]
    nonces: list[str] = [nonce_str for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: nonces, 2: plaintexts})
    encryptions = encrypt_aes_gcm_siv(data_frame)
    return encryptions, plaintexts


def decrypt_batch_with_aes_gcm_siv(batch_size: int, nonce_str: str, ciphertexts: list[bytes]) -> list[bytes]:
    """
    Decrypt a batch of data with AES GCM SIV
    """
    keys: list[str] = [key_id for _ in range(batch_size)]
    nonces: list[str] = [nonce_str for _ in range(batch_size)]
    encrypted_df = pd.DataFrame({0: keys, 1: nonces, 2: ciphertexts})
    plaintexts = decrypt_aes_gcm_siv(encrypted_df)
    return plaintexts


def _performance_aes_gcm_siv_udf(batch_size: int):
    plaintext_size = 64
    slog.info(f"Testing AES GCM SIV performance with batch size {batch_size}")
    nonce_str = 'abcde'

    encrypted_df, plaintexts = encrypt_batch_with_aes_gcm_siv(batch_size, nonce_str, plaintext_size)

    # do some verifications
    assert len(encrypted_df) == batch_size
    for v in encrypted_df.values:
        assert len(v) == plaintext_size + 16

    # decrypt the data
    recovered = decrypt_batch_with_aes_gcm_siv(batch_size, nonce_str, encrypted_df.values)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == recovered[i]


def test_aes_gcm_siv_cache():
    """
    Test the cache for AES GCM SIV
    The logs should show that two caches hit at the end of the test
    """
    nonce_str = 'abcde'
    plaintexts = [b'1234567890', b'abcdefghijk']

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(len(plaintexts))]
    nonces: list[str] = [nonce_str for _ in range(len(plaintexts))]
    enc_data_frame = pd.DataFrame({0: keys, 1: nonces, 2: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes_gcm_siv(enc_data_frame)

    # decrypt the data
    dec_data_frame = pd.DataFrame({0: keys, 1: nonces, 2: encryptions.values})
    _recovered = decrypt_aes_gcm_siv(dec_data_frame)

    # encrypt again
    _encryptions = encrypt_aes_gcm_siv(enc_data_frame)

    # decrypt the data again
    _recovered = decrypt_aes_gcm_siv(dec_data_frame)


if __name__ == '__main__':
    test_performance_aes_gcm_udf()
    test_performance_aes_gcm_siv_udf()
