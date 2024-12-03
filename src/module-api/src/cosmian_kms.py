import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List
import math
import pandas as pd
from bulk_data import BulkData
from client_configuration import ClientConfiguration
from kmip_decrypt import create_decrypt_request, \
    parse_decrypt_response
from encrypt import encrypt
from kmip_post import kmip_post
from shared import Algorithm, split_list




# These are the UDFs exposed to snowflake. They are defined as vectorized UDFs.
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs

def encrypt_aes_gcm(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM)


encrypt_aes_gcm._sf_vectorized_input = pd.DataFrame


def encrypt_aes_gcm_siv(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM_SIV)


encrypt_aes_gcm_siv._sf_vectorized_input = pd.DataFrame


def encrypt_aes_xts(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_XTS)


encrypt_aes_xts._sf_vectorized_input = pd.DataFrame


def encrypt_chacha20_poly1305(data: pd.DataFrame):
    return encrypt(data, Algorithm.CHACHA20_POLY1305)


encrypt_chacha20_poly1305._sf_vectorized_input = pd.DataFrame




def decrypt_aes_gcm(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM)


decrypt_aes_gcm._sf_vectorized_input = pd.DataFrame


# decrypt_aes_gcm._sf_max_batch_size = 5000000

def decrypt_aes_gcm_siv(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM_SIV)


decrypt_aes_gcm_siv._sf_vectorized_input = pd.DataFrame


def decrypt_aes_xts(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_XTS)


decrypt_aes_xts._sf_vectorized_input = pd.DataFrame


def decrypt_chacha20_poly1305(data: pd.DataFrame):
    return decrypt(data, Algorithm.CHACHA20_POLY1305)


decrypt_chacha20_poly1305._sf_vectorized_input = pd.DataFrame





def decrypt(df: pd.DataFrame, algorithm: Algorithm):
    """
    snowflake python udf to decrypt data using a symmetric key scheme 
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    key_id = df[0][0]
    key_id_bytes = key_id.encode('utf-8')
    if df.shape[1] > 2:
        # AES GCM SIV
        iv = to_padded_iv(df[1][0], algorithm)
        ciphertexts = df[2]
    else:
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
            # There are multiple ciphertexts but their number is small (i.e. below the threshold)
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
            results: List[dict] = [kmip_post(configuration, session, decrypt_requests[0])]
        except Exception as e:
            results = []
            slog.error(f"Error in KMIP POST {e}; silently replacing data with NULL")
    else:
        # Post the operations in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), decrypt_requests))
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
