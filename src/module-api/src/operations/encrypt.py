import math
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List
import pandas as pd
from bulk_data import BulkData
from client_configuration import ClientConfiguration
from operations.common import Algorithm, to_padded_iv, split_list
from initialize import  LRU_CACHE_ENCRYPT, slog, THRESHOLD, NUM_THREADS, logger
from kmip.kmip_encrypt import create_encrypt_request, \
    parse_encrypt_response
from kmip.kmip_post import kmip_post
from session import get_thread_local_session


def encrypt(df: pd.DataFrame, algorithm: Algorithm, configuration: ClientConfiguration):
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

    slog.debug("encrypt cache miss")

    # We do not use the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        # There is only one plaintext, no bulk encoding
        encrypt_requests = [
            create_encrypt_request(
                key_id=key_id,
                plaintext=plaintexts[0],
                algorithm=algorithm,
                nonce=nonce
            )
        ]
    else:
        if len(plaintexts) <= THRESHOLD:
            # There are multiple plaintexts but their number is small (i.e. below the threshold)
            # We do one query, bulk encoding. This is where all snowflake requests will end up
            # currently as the snowflake dataframes are always 4096 rows, much lower than the threshold.
            encrypt_requests = [
                create_encrypt_request(
                    key_id=key_id,
                    plaintext=BulkData(plaintexts).serialize(),
                    algorithm=algorithm,
                    nonce=nonce
                )
            ]
        else:
            # If the numer of row sis above the threshold (never happens currently)
            # Split the plaintexts into chunks which will be sent over multiple threads
            splits = math.floor(len(plaintexts) / THRESHOLD) + 1
            split_series = split_list(plaintexts, splits)
            encrypt_requests = [
                create_encrypt_request(
                    key_id=key_id,
                    plaintext=BulkData(chunk).serialize(), algorithm
                    =algorithm,
                    nonce=nonce
                ) for chunk in
                split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    # get the session from the thread local
    session = get_thread_local_session()
    if len(encrypt_requests) == 1:
        slog.debug(f"encrypt: no threadpool")
        results: List[dict] = [kmip_post(configuration, session, encrypt_requests[0])]
    else:
        # Post the operations in parallel
        slog.debug(f"encrypt: threadpool with {NUM_THREADS} threads")
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(
                executor.map(partial(kmip_post, configuration, get_thread_local_session()), encrypt_requests))
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        ciphertexts = [parse_encrypt_response(results[0])]
    else:
        ciphertexts = [ct for r in results for ct in BulkData.deserialize(parse_encrypt_response(r)).data]
    # For AES GCM SIV, remove the nonce from the ciphertext
    if algorithm == Algorithm.AES_GCM_SIV:
        ciphertexts = [ct[12:] for ct in ciphertexts]

    # for AES GCM SIV, store the ciphertexts in the cache
    if algorithm == Algorithm.AES_GCM_SIV:
        for ct, pt in zip(ciphertexts, plaintexts):
            LRU_CACHE_ENCRYPT.put([key_id_bytes, nonce, pt], ct)

    data_frame = pd.Series(ciphertexts)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.info(
        "encrypt_aes",
        extra={
            "size": len(plaintexts),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_encrypt_response_payload
        }
    )
    return data_frame
