###
# Copyright (c) 2023, Cosmian Technologies SAS
# All rights reserved.
#
# These tests code requires a working Cosmian KMS server
#
###
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import pandas as pd
import random

from client_configuration import ClientConfiguration
from cosmian_kms import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_aes_gcm_siv, decrypt_aes_gcm_siv
from initialize import slog
from op_decrypt import decrypt
from op_encrypt import encrypt
from op_shared import Algorithm

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
    conf = ClientConfiguration.from_json('{"kms_server_url": "https://kms-snowflake-test.cosmian.dev"}')
    encryption_time_1, decryption_time_1 = _performance_aes_gcm_siv_udf(conf, 1)
    # _performance_aes_gcm_siv_udf(2)
    encryption_time_4096, decryption_time_4096 = _performance_aes_gcm_siv_udf(conf, 4096)
    encryption_time_10001, decryption_time_10001 = _performance_aes_gcm_siv_udf(conf, 100001)
    slog.info(
        f"AES-GCM-SIV size=1 | encrypt={encryption_time_1 * 1000:.3f}ms/v | decrypt={decryption_time_1 * 1000:.3f}ms/v")
    slog.info(
        f"AES-GCM-SIV size=4096 | encrypt={encryption_time_4096 * 1000 / 4096:.3f}ms/v | decrypt={decryption_time_4096 * 1000 / 4096:.3f}ms/v")
    slog.info(
        f"AES-GCM-SIV size=100001 | encrypt={encryption_time_10001 * 1000 / 100001:.3f}ms/v | decrypt={decryption_time_10001 * 1000 / 100001:.3f}ms/v")


def test_simulate_snowflake_udf():
    simulate_snowflake_udf("https://kms-snowflake-test.cosmian.dev", num_batches=125)
    simulate_snowflake_udf("https://kms.ca-indosuez.com", num_batches=125)


def simulate_snowflake_udf(url_s: str, num_workers: int = 4,
                           num_batches: int = 250,
                           batch_size: int = 4000) -> (float, float):
    """
    Simulate the behavior of a snowflake UDF
    """
    plaintext_size = 64
    nonce_str = 'abcde'
    json = '{"kms_server_url": "' + url_s + '"}'
    configuration = ClientConfiguration.from_json(json)
    slog.info(f"===== Simulating snowflake UDF using KMS at {url_s} =====")
    slog.info(f"{url_s}: {num_batches} batches of {batch_size} values over {num_workers} workers ==>")

    # Encrypt the data
    t_enc_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        result: list[(pd.Series, bytes, float)] = list(
            executor.map(partial(encrypt_batch_with_aes_gcm_siv, configuration, batch_size, nonce_str),
                         [plaintext_size for _ in range(num_batches)]))
    t_enc_elapsed = time.perf_counter() - t_enc_start
    ciphertexts = [res[0].values for res in result]
    total_encryption_time = sum([res[2] for res in result])

    # Decrypt the data
    t_dec_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        result: list[(pd.Series, float)] = list(
            executor.map(partial(decrypt_batch_with_aes_gcm_siv, configuration, batch_size, nonce_str),
                         ciphertexts))
    t_dec_elapsed = time.perf_counter() - t_dec_start
    total_decryption_time = sum([res[1] for res in result])

    slog.info('============================================================')
    slog.info(
        f"Total encryption time: {total_encryption_time :.3f}s, {total_encryption_time * 1000000 / (batch_size * num_batches):.0f}µs/v")
    slog.info(
        f"Total decryption time: {total_decryption_time :.3f}s, {total_decryption_time * 1000000 / (batch_size * num_batches):.0f}µs/v")
    slog.info('============================================================')
    slog.info(
        f"Amortized encryption time: {t_enc_elapsed :.3f}s, {t_enc_elapsed * 1000000 / (batch_size * num_batches):.0f}µs/v")
    slog.info(
        f"Amortized decryption time: {t_dec_elapsed :.3f}s, {t_dec_elapsed * 1000000 / (batch_size * num_batches):.0f}µs/v")
    slog.info('============================================================')


def encrypt_batch_with_aes_gcm_siv(configuration: ClientConfiguration, batch_size: int, nonce_str: str,
                                   plaintext_size: int) -> (pd.Series, list[bytes], float):
    """
    Encrypt a batch of data with AES GCM SIV
    Returns the encrypted data, the plaintexts and the total time
    """
    keys: list[str] = [key_id for _ in range(batch_size)]
    nonces: list[str] = [nonce_str for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: nonces, 2: plaintexts})
    encryptions, total_time = encrypt(data_frame, algorithm=Algorithm.AES_GCM_SIV, configuration=configuration)
    return encryptions, plaintexts, total_time


def decrypt_batch_with_aes_gcm_siv(configuration: ClientConfiguration, batch_size: int, nonce_str: str,
                                   ciphertexts: list[bytes]) -> (pd.Series, float):
    """
    Decrypt a batch of data with AES GCM SIV
    Returns the decrypted data and the total time
    """
    keys: list[str] = [key_id for _ in range(batch_size)]
    nonces: list[str] = [nonce_str for _ in range(batch_size)]
    encrypted_df = pd.DataFrame({0: keys, 1: nonces, 2: ciphertexts})
    plaintexts, total_time = decrypt(encrypted_df, algorithm=Algorithm.AES_GCM_SIV, configuration=configuration)
    return plaintexts, total_time


def _performance_aes_gcm_siv_udf(configuration: ClientConfiguration, batch_size: int) -> (float, float):
    """
    Test the performance of AES GCM SIV
    Args:
        configuration: the configuration to use 
        batch_size: the batch size
    Returns:
        the encryption time and the decryption time
    """
    plaintext_size = 64
    slog.info(f"Testing AES GCM SIV performance with batch size {batch_size}")
    nonce_str = 'abcde'

    encrypted_df, plaintexts, encryption_time = encrypt_batch_with_aes_gcm_siv(configuration, batch_size, nonce_str,
                                                                               plaintext_size)

    # do some verifications
    assert len(encrypted_df) == batch_size
    for v in encrypted_df.values:
        assert len(v) == plaintext_size + 16

    # decrypt the data
    recovered, decryption_time = decrypt_batch_with_aes_gcm_siv(configuration, batch_size, nonce_str,
                                                                encrypted_df.values)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == recovered[i]

    return encryption_time, decryption_time


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
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else None
    if url is None:
        test_performance_aes_gcm_udf()
        test_performance_aes_gcm_siv_udf()
    else:
        simulate_snowflake_udf(url)
