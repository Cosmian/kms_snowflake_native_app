import json
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List

import pandas

from lib.aes.aes_gcm_decrypt import create_aes_gcm_decrypt_request, \
    parse_decrypt_response_payload
from lib.aes.aes_gcm_encrypt import create_aes_gcm_encrypt_request, \
    parse_encrypt_response_payload
from lib.aes.create_aes_key import create_aes_key
from lib.bulk_data import BulkData
from lib.client_configuration import ClientConfiguration
from lib.kmip_post import kmip_post

snowflake_logger = logging.getLogger("kms_decrypt")

# configuration = 'kms.json'
# CONFIGURATION = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
CONFIGURATION = '{"kms_server_url": "http://172.16.49.130:9998"}'
NUM_THREADS = 8
THRESHOLD = 200000


def encrypt_aes(data: pandas.DataFrame, logger=snowflake_logger):
    """
    snowflake python udf to encrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)
    batch_id = random.randint(0, 10000)

    key_ids = data[0]
    plaintexts = data[1]
    # We do not use the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        requests = [create_aes_gcm_encrypt_request(key_id=key_ids[0], cleartext=plaintexts[0])]
    else:
        if len(plaintexts) <= THRESHOLD:
            requests = [
                create_aes_gcm_encrypt_request(
                    key_id=key_ids[0],
                    cleartext=BulkData(plaintexts).serialize()
                )
            ]
        else:
            # Split the plaintexts into chunks
            k, m = divmod(len(plaintexts), NUM_THREADS)
            requests = [
                create_aes_gcm_encrypt_request(
                    key_id=key_ids[0],
                    cleartext=BulkData(plaintexts[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]).serialize()
                )
                for i in range(NUM_THREADS)
            ]
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
    ciphertexts=[]
    if no_bulk_data_encoding:
        ciphertexts.append(parse_encrypt_response_payload(results[0]))
    else:
        for r in results:
            ct = BulkData.deserialize(parse_encrypt_response_payload(r)).data
            ciphertexts.extend(ct)
    data_frame = pandas.Series(ciphertexts)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "encrypt_aes",
        extra={
            "id": batch_id,
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
encrypt_aes._sf_vectorized_input = pandas.DataFrame
# Set the maximum batch size 
encrypt_aes._sf_max_batch_size = 500000


def decrypt_aes(data: pandas.DataFrame, logger=snowflake_logger):
    """
    snowflake python udf to decrypt data using AES GCM
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)
    batch_id = random.randint(0, 10000)

    key_ids = data[0]
    ciphertexts = data[1]
    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        requests = [create_aes_gcm_decrypt_request(key_id=key_ids[0], ciphertext=ciphertexts[0])]
    else:
        if len(ciphertexts) <= THRESHOLD:
            requests = [
                create_aes_gcm_decrypt_request(
                    key_id=key_ids[0],
                    ciphertext=BulkData(ciphertexts).serialize(),
                    bulk=True
                )
            ]
        else:
            # Split the ciphertexts into chunks
            k, m = divmod(len(ciphertexts), NUM_THREADS)
            requests = [
                create_aes_gcm_decrypt_request(
                    key_id=key_ids[0],
                    ciphertext=BulkData(ciphertexts[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]).serialize(),
                    bulk=True
                )
                for i in range(NUM_THREADS)
            ]
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
    ciphertexts=[]
    if no_bulk_data_encoding:
        ciphertexts.append(parse_decrypt_response_payload(results[0]))
    else:
        for r in results:
            ct = BulkData.deserialize(parse_decrypt_response_payload(r)).data
            ciphertexts.extend(ct)
    data_frame = pandas.Series(ciphertexts)
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "decrypt_aes",
        extra={
            "id": batch_id,
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
decrypt_aes._sf_vectorized_input = pandas.DataFrame
decrypt_aes._sf_max_batch_size = 500000


def create_key_aes(user):
    key = create_aes_key(size=256, tags=["tag1", "tag2"], conf_path=CONFIGURATION)
    return key

# def test():
#     data = []
#     print("reading data")
#     with open("./data/generated_data_1000000.csv", 'r') as file:
#         csvreader = csv.reader(file)
#         for row in csvreader:
#             data.append(row[1])
#     print("end reading data")
#     key = '0d319307-f766-4869-b90a-02096edb9431'
#     print("creating encrypt request")
#     print(data[1:11])
#     clear = [create_aes_gcm_encrypt_request(key_id=key, cleartext=x.encode("utf-8")) for x in data[1:11]]
#     print("clear: ", clear)
#     print("encrypt request done")
#     print("post_operations beginning")
#     bulk = post_operations(clear, batch_id=0, num_threads=10, threshold=1500, conf_path=CONFIGURATION)
#     print("end post_operations")
#     res = [parse_encrypt_response_payload(x.value) for x in bulk]
# 
#     print("starting decrypt")
#     print("created decrypt request")
#     ctx = [create_aes_gcm_decrypt_request(key_id=key, ciphertext=x) for x in res]
#     bulk = post_operations(ctx, batch_id=0, num_threads=10, threshold=1500, conf_path=CONFIGURATION)
#     print("end post operations")
#     res = [parse_decrypt_response_payload(x.value) for x in bulk]
#     print(res)
#     return res
# 
# 
# if __name__ == "__main__":
#     test()
