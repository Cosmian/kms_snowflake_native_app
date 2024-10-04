import logging
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List
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


def encrypt_aes(data: pd.DataFrame):
    """
    snowflake python udf to encrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    # These is a Pandas Series
    plaintexts = data[1]
    # same key for everyone
    key_id = data[0][0]

    # We do not u®se the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        requests = [create_encrypt_request(key_id=key_id, cleartext=plaintexts[0])]
    else:
        if len(plaintexts) <= THRESHOLD:
            requests = [
                create_encrypt_request(
                    key_id=key_id,
                    cleartext=BulkData(plaintexts).serialize()
                )
            ]
        else:
            # Split the plaintexts into chunks
            splits = math.floor(len(plaintexts) / THRESHOLD) + 1
            split_series = np.array_split(plaintexts, splits)
            requests = [create_encrypt_request(key_id=key_id, cleartext=BulkData(chunk).serialize()) for chunk in
                        split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    if len(requests) == 1:
        slog.info(f"encrypt: no threadpool")
        results: List[dict] = [kmip_post(configuration, session, requests[0])]
    else:
        # Post the operations in parallel
        slog.info(f"encrypt: threadpool with {NUM_THREADS} threads")
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), requests))
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        ciphertexts = [parse_encrypt_response(results[0])]
    else:
        ciphertexts = [ct for r in results for ct in BulkData.deserialize(parse_encrypt_response(r)).data]
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
encrypt_aes._sf_vectorized_input = pd.DataFrame


# Set the maximum batch size 
# encrypt_aes._sf_max_batch_size = 5000000


def decrypt_aes(data: pd.DataFrame):
    """
    snowflake python udf to decrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    key_ids = data[0]
    ciphertexts = data[1]
    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=ciphertexts[0], is_authenticated_aes=True)]
    else:
        if len(ciphertexts) <= THRESHOLD:
            requests = [
                create_decrypt_request(
                    key_id=key_ids[0],
                    ciphertext=BulkData(ciphertexts).serialize(),
                )
            ]
        else:
            # Split the ciphertexts into chunks
            splits = math.floor(len(ciphertexts) / THRESHOLD) + 1
            split_series = np.array_split(ciphertexts, splits)
            requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=BulkData(chunk).serialize()) for chunk in
                        split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    if len(requests) == 1:
        results: List[dict] = [kmip_post(configuration, session, requests[0])]
    else:
        # Post the operations in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), requests))
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
            "size": len(data[1]),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_decrypt_response_payload
        }
    )
    return data_frame


# Set this function to be a snowflake vectorized function
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs
decrypt_aes._sf_vectorized_input = pd.DataFrame


# decrypt_aes._sf_max_batch_size = 5000000


class DecryptAES:

    def __init__(self):
        pass

    def end_partition(self, data: pd.DataFrame):
        """
        snowflake python udf to decrypt data using AES GCM
        """
        configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

        num_columns = data.shape[1]
        slog.info(f"num_columns: {num_columns}")
        key_ids = data[0]
        serie_length = len(data[1])
        slog.info(f"serie_length: {serie_length}")
        ciphertexts = [data[i][j] for j in range(serie_length) for i in range(1, num_columns)]

        # We do not use the bulk data encoding if there is only one ciphertext
        no_bulk_data_encoding = len(ciphertexts) == 1

        t_start = time.perf_counter()
        if no_bulk_data_encoding:
            requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=ciphertexts[0], is_authenticated_aes=True)]
        else:
            # if len(ciphertexts) <= THRESHOLD:
            slog.info(f"decrypt: no threadpool")
            requests = [
                create_decrypt_request(
                    key_id=key_ids[0],
                    ciphertext=BulkData(ciphertexts).serialize(),
                )
            ]
            # else:
            #     slog.info(f"decrypt: threadpool with {NUM_THREADS} threads")
            #     # Split the ciphertexts into chunks
            #     splits = int(len(ciphertexts) / THRESHOLD)+1
            #     split_series = np.array_split(ciphertexts, splits)
            #     requests = [create_decrypt_request(key_id=key_ids[0], ciphertext=BulkData(chunk).serialize()) for chunk
            #                 in split_series]
        t_prepare_requests = time.perf_counter() - t_start

        # Post the operations
        t_start = time.perf_counter()
        if len(requests) == 1:
            results: List[dict] = [kmip_post(configuration, requests[0])]
        else:
            # Post the operations in parallel
            with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
                results: List[dict] = list(executor.map(partial(kmip_post, configuration), requests))
        t_post_operations = time.perf_counter() - t_start

        # Parse the response
        t_start = time.perf_counter()
        if no_bulk_data_encoding:
            plaintexts = [parse_decrypt_response(results[0])]
        else:
            plaintexts = [ct for r in results for ct in BulkData.deserialize(parse_decrypt_response(r)).data]
        # split the plaintexts into num_columns lists
        plaintexts = [plaintexts[i:i + serie_length] for i in range(0, len(plaintexts) - 1, serie_length)]
        # print(f"plaintexts: {plaintexts}")
        data_frame = pd.DataFrame([pd.Series(plaintext) for plaintext in plaintexts])
        t_parse_decrypt_response_payload = time.perf_counter() - t_start

        # split the plaintexts into num_columns pandas series
        data_frame = pd.DataFrame(data_frame.values.reshape(-1, num_columns - 1))

        logger.debug(
            "decrypt_aes_t",
            extra={
                "size": len(data[1]),
                "request": t_prepare_requests,
                "post": t_post_operations,
                "response": t_parse_decrypt_response_payload
            }
        )
        return data_frame


# Set this function to be a snowflake vectorized function
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-tabular-vectorized
DecryptAES.end_partition._sf_vectorized_input = pd.DataFrame
