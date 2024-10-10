import logging
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List, Optional
import math

import numpy as np
import pandas as pd
import requests

from bulk_data import BulkData
from client_configuration import ClientConfiguration
from kmip_decrypt import create_decrypt_request, \
    parse_decrypt_response
from kmip_encrypt import create_encrypt_request, \
    parse_encrypt_response
from kmip_post import kmip_post
from shared import Algorithm, split_list

snowflake_logger = logging.getLogger("kms_decrypt")
logger = snowflake_logger
slog = logging.LoggerAdapter(snowflake_logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})

# TODO: These values need to be de-harcoded via configuration

# CONFIGURATION = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
# CONFIGURATION = '{"kms_server_url": "http://172.16.49.130:9998"}'
# CONFIGURATION = '{"kms_server_url": "http://localhost:9998"}'
CONFIGURATION = '{"kms_server_url": "https://kms-snowflake-test.cosmian.dev"}'
# the heuristic seems to be 5 times the number of cores for 64 bytes plaintexts
NUM_THREADS = 40
THRESHOLD = 100000
session = requests.Session()


def set_configuration(configuration: str):
    global CONFIGURATION
    CONFIGURATION = configuration


# Set this function to be a snowflake vectorized function
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


def encrypt(df: pd.DataFrame, algorithm: Algorithm):
    """
    snowflake python udf to encrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    # This is a Pandas Series
    plaintexts = df[1]
    # same key for everyone
    key_id = df[0][0]

    nonce: Optional[bytes] = None
    if df.shape[1] > 2:
        nonce = to_padded_nonce(df[2][0], algorithm)

    # We do not u®se the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
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
            encrypt_requests = [
                create_encrypt_request(
                    key_id=key_id,
                    plaintext=BulkData(plaintexts).serialize(),
                    algorithm=algorithm,
                    nonce=nonce
                )
            ]
        else:
            # Split the plaintexts into chunks
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
    if len(encrypt_requests) == 1:
        slog.info(f"encrypt: no threadpool")
        results: List[dict] = [kmip_post(configuration, session, encrypt_requests[0])]
    else:
        # Post the operations in parallel
        slog.info(f"encrypt: threadpool with {NUM_THREADS} threads")
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), encrypt_requests))
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
    data_frame = pd.Series(ciphertexts)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "encrypt_aes",
        extra={
            "size": len(plaintexts),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_encrypt_response_payload
        }
    )
    return data_frame


# Set this function to be a snowflake vectorized function
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs

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


# Set the maximum batch size 
# encrypt_aes._sf_max_batch_size = 5000000


def decrypt(df: pd.DataFrame, algorithm: Algorithm):
    """
    snowflake python udf to decrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    key_id = df[0][0]
    ciphertexts = df[1]

    nonce: Optional[bytes] = None
    if df.shape[1] > 2:
        nonce = to_padded_nonce(df[2][0], algorithm)

    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        decrypt_requests = [
            create_decrypt_request(
                key_id=key_id,
                ciphertext=ciphertexts[0],
                algorithm=algorithm,
                nonce=nonce
            )
        ]
    else:
        # got AES GCM SIV, prepend all ciphertexts with the nonce
        if algorithm == Algorithm.AES_GCM_SIV:
            ciphertexts = [nonce + ct for ct in ciphertexts]
        if len(ciphertexts) <= THRESHOLD:
            slog.info(f"decrypt: no threadpool")
            decrypt_requests = [
                create_decrypt_request(
                    key_id=key_id,
                    ciphertext=BulkData(ciphertexts),
                    algorithm=algorithm,
                    nonce=None
                )
            ]
        else:
            slog.info(f"decrypt: threadpool with {NUM_THREADS} threads")
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
    if len(decrypt_requests) == 1:
        results: List[dict] = [kmip_post(configuration, session, decrypt_requests[0])]
    else:
        # Post the operations in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), decrypt_requests))
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        plaintexts = [parse_decrypt_response(results[0])]
    else:
        plaintexts = [ct for r in results for ct in BulkData.deserialize(parse_decrypt_response(r)).data]
    data_frame = pd.Series(plaintexts)
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "decrypt_aes",
        extra={
            "size": len(df[1]),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_decrypt_response_payload
        }
    )
    return data_frame


def to_padded_nonce(input_string: str, algorithm: Algorithm) -> bytes:
    """
    Convert a string to a padded bytes nonce for symmetric encryption
    Args:
        input_string: the string that will be used as a nonce
        algorithm: the algorithm used for encryption 

    Returns:
        bytes: the padded nonce
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

# class DecryptAES:
# 
#     def __init__(self):
#         pass
# 
#     def end_partition(self, data: pd.DataFrame):
#         """
#         snowflake python udf to decrypt data using AES GCM
#         """
#         configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)
# 
#         num_columns = data.shape[1]
#         slog.info(f"num_columns: {num_columns}")
#         key_ids = data[0]
#         serie_length = len(data[1])
#         slog.info(f"serie_length: {serie_length}")
#         ciphertexts = [data[i][j] for j in range(serie_length) for i in range(1, num_columns)]
# 
#         # We do not use the bulk data encoding if there is only one ciphertext
#         no_bulk_data_encoding = len(ciphertexts) == 1
# 
#         t_start = time.perf_counter()
#         if no_bulk_data_encoding:
#             requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=ciphertexts[0], is_authenticated_aes=True)]
#         else:
#             # if len(ciphertexts) <= THRESHOLD:
#             slog.info(f"decrypt: no threadpool")
#             requests = [
#                 create_decrypt_request(
#                     key_id=key_ids[0],
#                     ciphertext=BulkData(ciphertexts).serialize(),
#                 )
#             ]
#             # else:
#             #     slog.info(f"decrypt: threadpool with {NUM_THREADS} threads")
#             #     # Split the ciphertexts into chunks
#             #     splits = int(len(ciphertexts) / THRESHOLD)+1
#             #     split_series = np.array_split(ciphertexts, splits)
#             #     requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=BulkData(chunk).serialize()) for chunk
#             #                 in split_series]
#         t_prepare_requests = time.perf_counter() - t_start
# 
#         # Post the operations
#         t_start = time.perf_counter()
#         if len(requests) == 1:
#             results: List[dict] = [kmip_post(configuration, requests[0])]
#         else:
#             # Post the operations in parallel
#             with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
#                 results: List[dict] = list(executor.map(partial(kmip_post, configuration), requests))
#         t_post_operations = time.perf_counter() - t_start
# 
#         # Parse the response
#         t_start = time.perf_counter()
#         if no_bulk_data_encoding:
#             plaintexts = [parse_decrypt_response(results[0])]
#         else:
#             plaintexts = [ct for r in results for ct in BulkData.deserialize(parse_decrypt_response(r)).data]
#         # split the plaintexts into num_columns lists
#         plaintexts = [plaintexts[i:i + serie_length] for i in range(0, len(plaintexts) - 1, serie_length)]
#         # print(f"plaintexts: {plaintexts}")
#         data_frame = pd.DataFrame([pd.Series(plaintext) for plaintext in plaintexts])
#         t_parse_decrypt_response_payload = time.perf_counter() - t_start
# 
#         # split the plaintexts into num_columns pandas series
#         data_frame = pd.DataFrame(data_frame.values.reshape(-1, num_columns - 1))
# 
#         logger.debug(
#             "decrypt_aes_t",
#             extra={
#                 "size": len(data[1]),
#                 "request": t_prepare_requests,
#                 "post": t_post_operations,
#                 "response": t_parse_decrypt_response_payload
#             }
#         )
#         return data_frame
# 
# 
# # Set this function to be a snowflake vectorized function
# # see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-tabular-vectorized
# DecryptAES.end_partition._sf_vectorized_input = pd.DataFrame
