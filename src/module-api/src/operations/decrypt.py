import math
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import pandas as pd

from client_configuration import ClientConfiguration
from initialize import LRU_CACHE_DECRYPT, THRESHOLD, NUM_THREADS, slog,  logger
from operations.bulk_data import BulkData
from operations.common import Algorithm, to_padded_iv, split_list
from operations.kmip.kmip_decrypt import create_decrypt_request, parse_decrypt_response
from operations.kmip.kmip_post import kmip_post
from session import get_thread_local_session


def decrypt(df: pd.DataFrame, algorithm: Algorithm, configuration: ClientConfiguration):
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

    slog.debug("decrypt cache miss")

    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        decrypt_requests = [
            create_decrypt_request(
                key_id=key_id,
                ciphertext=ciphertexts[0],
                algorithm=algorithm,
                nonce=iv
            )
        ]
    else:
        # got AES GCM SIV, prepend all ciphertexts with the nonce
        if algorithm == Algorithm.AES_GCM_SIV:
            ciphertexts = [iv + ct for ct in ciphertexts]
        if len(ciphertexts) <= THRESHOLD:
            # There are multiple ciphertexts, but their number is small (i.e., below the threshold)
            # We do one query, bulk encoding. This is where all snowflake requests will end up
            # currently as the snowflake dataframes are always 4096 rows, much lower than the threshold.
            slog.debug(f"decrypt: no threadpool")
            decrypt_requests = [
                create_decrypt_request(
                    key_id=key_id,
                    ciphertext=BulkData(ciphertexts),
                    algorithm=algorithm,
                    nonce=None
                )
            ]
        else:
            slog.debug(f"decrypt: threadpool with {NUM_THREADS} threads")
            # Split the ciphertexts into chunks
            splits = math.floor(len(ciphertexts) / THRESHOLD) + 1
            split_series = split_list(ciphertexts, splits)
            decrypt_requests = [create_decrypt_request(
                key_id=key_id,
                ciphertext=BulkData(chunk),
                algorithm=algorithm,
                nonce=None
            ) for chunk in split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    # get the session from the thread local
    session = get_thread_local_session()
    if len(decrypt_requests) == 1:
        try:
            results: list[dict] = [kmip_post(configuration, session, decrypt_requests[0])]
        except Exception as e:
            results = []
            slog.error(f"Error in KMIP POST {e}; silently replacing data with NULL")
    else:
        # Post the operations in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: list[dict] = list(executor.map(partial(kmip_post, configuration, session), decrypt_requests))
    t_post_operations = time.perf_counter() - t_start

    if not results:
        plaintexts = [[] * len(ciphertexts)]
    else:
        # Parse the response
        t_start = time.perf_counter()
        if no_bulk_data_encoding:
            plaintexts = [parse_decrypt_response(results[0])]
        else:
            plaintexts = [ct for r in results for ct in BulkData.deserialize(parse_decrypt_response(r)).data]

        # for AES GCM SIV, store the plaintext in the cache
        if algorithm == Algorithm.AES_GCM_SIV:
            for ct, pt in zip(ciphertexts, plaintexts):
                # nonce is prepended in ciphertext; do not repeat it in the cache key
                LRU_CACHE_DECRYPT.put([key_id_bytes, ct], pt)

    data_frame = pd.Series(plaintexts)
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.info(
        "decrypt_aes",
        extra={
            "size": len(df[1]),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_decrypt_response_payload
        }
    )
    return data_frame
