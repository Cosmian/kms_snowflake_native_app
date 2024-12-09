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

#    simulate_snowflake_udf("https://kms.ca-indosuez.com")
#    simulate_snowflake_udf("https://kms-snowflake-test.cosmian.dev")

# Keep-alive
#
# 2024-12-09 22:27:47 [    INFO] ===== Simulating snowflake UDF using KMS at https://kms-snowflake-test.cosmian.dev ===== (perf_tests.py:88) | thread_id=-1
# 2024-12-09 22:27:47 [    INFO] https://kms-snowflake-test.cosmian.dev: 125 batches of 4000 values over 4 workers ==> (perf_tests.py:89) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] ============================================================ (perf_tests.py:110) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] Total encryption time: 39.903s, 80µs/v (perf_tests.py:111) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] Total decryption time: 46.651s, 93µs/v (perf_tests.py:113) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] ============================================================ (perf_tests.py:115) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] Amortized encryption time: 10.103s, 20µs/v (perf_tests.py:116) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] Amortized decryption time: 11.912s, 24µs/v (perf_tests.py:118) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] ============================================================ (perf_tests.py:120) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] ===== Simulating snowflake UDF using KMS at https://kms.ca-indosuez.com ===== (perf_tests.py:88) | thread_id=-1
# 2024-12-09 22:28:09 [    INFO] https://kms.ca-indosuez.com: 125 batches of 4000 values over 4 workers ==> (perf_tests.py:89) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] ============================================================ (perf_tests.py:110) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] Total encryption time: 56.725s, 113µs/v (perf_tests.py:111) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] Total decryption time: 46.092s, 92µs/v (perf_tests.py:113) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] ============================================================ (perf_tests.py:115) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] Amortized encryption time: 14.375s, 29µs/v (perf_tests.py:116) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] Amortized decryption time: 11.634s, 23µs/v (perf_tests.py:118) | thread_id=-1
# 2024-12-09 22:28:35 [    INFO] ============================================================ (perf_tests.py:120) | thread_id=-1

# Connection close
# 2024-12-09 22:29:42 [    INFO] ===== Simulating snowflake UDF using KMS at https://kms-snowflake-test.cosmian.dev ===== (perf_tests.py:88) | thread_id=-1
# 2024-12-09 22:29:42 [    INFO] https://kms-snowflake-test.cosmian.dev: 125 batches of 4000 values over 4 workers ==> (perf_tests.py:89) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] ============================================================ (perf_tests.py:110) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] Total encryption time: 78.231s, 156µs/v (perf_tests.py:111) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] Total decryption time: 75.550s, 151µs/v (perf_tests.py:113) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] ============================================================ (perf_tests.py:115) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] Amortized encryption time: 20.004s, 40µs/v (perf_tests.py:116) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] Amortized decryption time: 19.222s, 38µs/v (perf_tests.py:118) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] ============================================================ (perf_tests.py:120) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] ===== Simulating snowflake UDF using KMS at https://kms.ca-indosuez.com ===== (perf_tests.py:88) | thread_id=-1
# 2024-12-09 22:30:21 [    INFO] https://kms.ca-indosuez.com: 125 batches of 4000 values over 4 workers ==> (perf_tests.py:89) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] ============================================================ (perf_tests.py:110) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] Total encryption time: 74.411s, 149µs/v (perf_tests.py:111) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] Total decryption time: 77.654s, 155µs/v (perf_tests.py:113) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] ============================================================ (perf_tests.py:115) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] Amortized encryption time: 18.883s, 38µs/v (perf_tests.py:116) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] Amortized decryption time: 19.780s, 40µs/v (perf_tests.py:118) | thread_id=-1
# 2024-12-09 22:31:00 [    INFO] ============================================================ (perf_tests.py:120) | thread_id=-1
