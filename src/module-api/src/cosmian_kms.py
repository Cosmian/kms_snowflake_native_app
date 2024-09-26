import pandas
from create_aes_key import create_aes_key
from aes_gcm_decrypt import create_aes_gcm_decrypt_request, \
    parse_decrypt_response_payload
from aes_gcm_encrypt import create_aes_gcm_encrypt_request, \
    parse_encrypt_response_payload
from bulk import post_operations, DEFAULT_NUM_THREADS
import csv
import logging
import random
import time

snowflake_logger = logging.getLogger("kms_decrypt")

# configuration = 'kms.json'
CONFIGURATION = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
NUM_THREADS = 2
THRESHOLD = 100


def encrypt_aes(data: pandas.DataFrame, logger=snowflake_logger):
    """
    snowflake python udf to encrypt data using AES GCM
    """
    batch_id = random.randint(0, 10000)

    key_ids = data[0]
    cleartexts = data[1]

    encryptions = []
    t_start = time.perf_counter()
    for i in range(0, len(data)):
        enc = create_aes_gcm_encrypt_request(key_id=key_ids[i], cleartext=cleartexts[i].encode('utf-8'))
        encryptions.append(enc)
    t_create_aes_gcm_encrypt_request = time.perf_counter() - t_start

    t_start = time.perf_counter()
    bulk = post_operations(encryptions, batch_id, num_threads=NUM_THREADS, threshold=THRESHOLD, conf_path=CONFIGURATION)
    t_post_operations = time.perf_counter() - t_start

    results = []
    t_start = time.perf_counter()
    for b in bulk:
        assert b.operation == 'Encrypt'
        res = parse_encrypt_response_payload(b.value)
        results.append(res)
    data_frame = pandas.Series(results)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "encrypt_aes",
        extra={
            "id": batch_id,
            "size": len(data[1]),
            "request": t_create_aes_gcm_encrypt_request,
            "post": t_post_operations,
            "response": t_parse_encrypt_response_payload
        }
    )
    return data_frame


# Set this function to be a snowflake vectorized function
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs
encrypt_aes._sf_vectorized_input = pandas.DataFrame
# Set the maximum batch size to 20,000
encrypt_aes._sf_max_batch_size = 20000


def decrypt_aes(data: pandas.DataFrame, logger=snowflake_logger):
    """
    snowflake python udf to decrypt data using AES GCM
    """
    batch_id = random.randint(0, 10000)

    key_ids = data[0]
    ciphertexts = data[1]

    # Create the decrypt request array
    decryptions = []
    t_start = time.perf_counter()
    for i in range(0, len(data)):
        enc = create_aes_gcm_decrypt_request(key_id=key_ids[i], ciphertext=ciphertexts[i])
        decryptions.append(enc)
    t_create_aes_gcm_decrypt_request = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    bulk = post_operations(decryptions, batch_id, num_threads=NUM_THREADS, threshold=THRESHOLD, conf_path=CONFIGURATION)
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    results = []
    t_start = time.perf_counter()
    for b in bulk:
        assert b.operation == 'Decrypt'
        res = parse_decrypt_response_payload(b.value)
        results.append(res.decode('utf-8'))
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.debug(
        "decrypt_aes",
        extra={
            "id": batch_id,
            "size": len(data[1]),
            "request": t_create_aes_gcm_decrypt_request,
            "post": t_post_operations,
            "response": t_parse_decrypt_response_payload
        }
    )
    return results


# Set this function to be a snowflake vectorized function
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs
decrypt_aes._sf_vectorized_input = pandas.DataFrame
# Set the maximum batch size to 20,000
decrypt_aes._sf_max_batch_size = 20000


def create_key_aes(user):
    key = create_aes_key(size=256, tags=["tag1", "tag2"], conf_path=CONFIGURATION)
    return key


def test():
    data = []
    print("reading data")
    with open("./data/generated_data_1000000.csv", 'r') as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            data.append(row[1])
    print("end reading data")
    key = '0d319307-f766-4869-b90a-02096edb9431'
    print("creating encrypt request")
    print(data[1:11])
    clear = [create_aes_gcm_encrypt_request(key_id=key, cleartext=x.encode("utf-8")) for x in data[1:11]]
    print("clear: ", clear)
    print("encrypt request done")
    print("post_operations beginning")
    bulk = post_operations(clear, num_threads=10, threshold=1500, conf_path=CONFIGURATION)
    print("end post_operations")
    res = [parse_encrypt_response_payload(x.value) for x in bulk]

    print("starting decrypt")
    print("created decrypt request")
    ctx = [create_aes_gcm_decrypt_request(key_id=key, ciphertext=x) for x in res]
    bulk = post_operations(ctx, num_threads=10, threshold=1500, conf_path=CONFIGURATION)
    print("end post operations")
    res = [parse_decrypt_response_payload(x.value) for x in bulk]
    print(res)
    return res


if __name__ == "__main__":
    main()
