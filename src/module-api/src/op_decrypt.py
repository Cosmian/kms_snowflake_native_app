import threading
import threading
import time

import pandas as pd

from bulk_data import BulkData
from client_configuration import ClientConfiguration
from initialize import LRU_CACHE_DECRYPT, slog, logger
from kmip_decrypt import create_decrypt_request, parse_decrypt_response
from kmip_post import kmip_post
from op_shared import Algorithm, to_padded_iv
from session import get_thread_local_session


def decrypt(df: pd.DataFrame, algorithm: Algorithm, configuration: ClientConfiguration) -> (pd.Series, float):
    """
    snowflake python udf to decrypt data using a symmetric key scheme 
    """
    assert isinstance(df, pd.DataFrame)

    key_id = df[0][0]
    key_id_bytes = key_id.encode('utf-8')
    if df.shape[1] > 2:
        # AES GCM SIV
        iv = to_padded_iv(df[1][0], algorithm)
        ciphertexts = df[2]
    else:
        # AES GCM or AES XTS
        iv = None
        ciphertexts = df[1]

    # Check if the ciphertext is in the cache for AES GCM SIV
    # This is pretty basic: the cache is really used if all the ciphertexts are in the cache.
    # It does not handle partial cache hits.
    if algorithm == Algorithm.AES_GCM_SIV:
        result: list[bytes] = []
        for ct in ciphertexts:
            plaintext = LRU_CACHE_DECRYPT.get([key_id_bytes, iv, ct])
            if plaintext is None:
                # not in cache, run the query
                break
            result.append(plaintext)
        if len(result) == len(ciphertexts):
            slog.debug(f"decrypt cache hit")
            return pd.Series(result)

    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        decrypt_request = create_decrypt_request(
            key_id=key_id,
            ciphertext=ciphertexts[0],
            algorithm=algorithm,
            nonce=iv
        )
    else:
        # got AES GCM SIV, prepend all ciphertexts with the nonce
        if algorithm == Algorithm.AES_GCM_SIV:
            ciphertexts = [iv + ct for ct in ciphertexts]
        decrypt_request = create_decrypt_request(
            key_id=key_id,
            ciphertext=BulkData(ciphertexts),
            algorithm=algorithm,
            nonce=None
        )
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    # get the session from the thread local
    session = get_thread_local_session()
    try:
        result: dict = kmip_post(configuration, session, decrypt_request)
    except Exception as e:
        slog.error(f"Error in KMIP POST {e}")
        raise e
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        plaintexts = [parse_decrypt_response(result)]
    else:
        plaintexts = BulkData.deserialize(parse_decrypt_response(result)).data

    # for AES GCM SIV, store the plaintext in the cache
    if algorithm == Algorithm.AES_GCM_SIV:
        for ct, pt in zip(ciphertexts, plaintexts):
            # nonce is prepended in ciphertext; do not repeat it in the cache key
            LRU_CACHE_DECRYPT.put([key_id_bytes, ct], pt)

    series = pd.Series(plaintexts)
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.info(
        f"decrypt: {algorithm}, size: {len(plaintexts)}, POST: {t_post_operations * 1000000 / len(ciphertexts):.3f} µs/c" +
        f" Overhead: {(t_prepare_requests + t_parse_decrypt_response_payload) * 1000000 / len(ciphertexts):.3f} µs/c",
        extra={"thread_id": threading.get_ident()}
    )
    return series, t_prepare_requests + t_post_operations + t_parse_decrypt_response_payload
