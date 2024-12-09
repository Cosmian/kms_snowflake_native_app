import threading
import time

import pandas as pd

from bulk_data import BulkData
from client_configuration import ClientConfiguration
from initialize import LRU_CACHE_ENCRYPT, slog, logger
from kmip_encrypt import create_encrypt_request, parse_encrypt_response
from kmip_post import kmip_post
from op_shared import Algorithm, to_padded_iv
from session import get_thread_local_session


def encrypt(df: pd.DataFrame, algorithm: Algorithm, configuration: ClientConfiguration) -> (pd.Series, float):
    """
    snowflake python udf to encrypt data using AES GCM
    """

    # This is a Pandas Series
    # same key for everyone
    key_id = df[0][0]
    key_id_bytes = key_id.encode('utf-8')
    if df.shape[1] > 2:
        nonce = to_padded_iv(df[1][0], algorithm)
        plaintexts = df[2]
    else:
        nonce = None
        plaintexts = df[1]

    # Check if the plaintext is in the cache for AES GCM SIV
    # This is pretty basic: the cache is really used if all the plaintexts are in the cache.
    # It does not handle partial cache hits.
    if algorithm == Algorithm.AES_GCM_SIV:
        result: list[bytes] = []
        for pt in plaintexts:
            plaintext = LRU_CACHE_ENCRYPT.get([key_id_bytes, nonce, pt])
            if plaintext is None:
                # not in cache, run the query
                break
            result.append(plaintext)
        if len(result) == len(plaintexts):
            slog.debug(f"encrypt cache hit")
            return pd.Series(result)

    # We do not use the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        # There is only one plaintext, no bulk encoding
        encrypt_request = create_encrypt_request(
            key_id=key_id,
            plaintext=plaintexts[0],
            algorithm=algorithm,
            nonce=nonce
        )
    else:
        encrypt_request = create_encrypt_request(
            key_id=key_id,
            plaintext=BulkData(plaintexts).serialize(),
            algorithm=algorithm,
            nonce=nonce
        )
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    # get the session from the thread local
    result: dict = kmip_post(configuration, get_thread_local_session(), encrypt_request)
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        ciphertexts = [parse_encrypt_response(result)]
    else:
        ciphertexts = BulkData.deserialize(parse_encrypt_response(result)).data
    # For AES GCM SIV, remove the nonce from the ciphertext
    if algorithm == Algorithm.AES_GCM_SIV:
        ciphertexts = [ct[12:] for ct in ciphertexts]

    # for AES GCM SIV, store the ciphertexts in the cache
    if algorithm == Algorithm.AES_GCM_SIV:
        for ct, pt in zip(ciphertexts, plaintexts):
            LRU_CACHE_ENCRYPT.put([key_id_bytes, nonce, pt], ct)

    series = pd.Series(ciphertexts)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        f"encrypt: {algorithm}, size: {len(plaintexts)}, POST: {t_post_operations * 1000000 / len(ciphertexts):.3f} µs/c" +
        f" Overhead: {(t_prepare_requests + t_parse_encrypt_response_payload) * 1000000 / len(ciphertexts):.3f} µs/c",
        extra={"thread_id": threading.get_ident()}
    )
    return series, t_post_operations + t_prepare_requests + t_parse_encrypt_response_payload
