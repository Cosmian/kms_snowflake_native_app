from typing import List
import pandas
from _snowflake import vectorized
from create_aes_key import create_aes_key
from aes_gcm_decrypt import create_aes_gcm_decrypt_request, \
    parse_decrypt_response_payload
from aes_gcm_encrypt import create_aes_gcm_encrypt_request, \
    parse_encrypt_response_payload
from bulk import post_operations
import csv
import logging
import random
import time


logger = logging.getLogger("kms_decrypt")

# configuration = 'kms.json'
configuration = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
@vectorized(input=pandas.DataFrame, max_batch_size=20000)
def encrypt_aes(data):
    encryptions = []
    pks = data[0]
    ds = data[1]

    for i in range(0,len(data)):
        enc = create_aes_gcm_encrypt_request(key_id=pks[i], data=ds[i].encode('utf-8'))
        encryptions.append(enc)

    bulk = post_operations(encryptions,0, num_threads=4, threshold=1000, conf_path=configuration)
    results = []

    for b in bulk:
      assert b.operation == 'Encrypt'
      res = parse_encrypt_response_payload(b.value)
      results.append(res.decode('utf-8'))
    return pandas.Series(results)


@vectorized(input=pandas.DataFrame, max_batch_size=20000)
def decrypt_aes(data):
    r = random.randint(0,10000)
    decryptions = []
    sks = data[0]
    ds = data[1]
    start_create_aes_gcm_decrypt_request = time.perf_counter()
    for i in range(0,len(data)):
        enc = create_aes_gcm_decrypt_request(key_id=sks[i], ciphertext=ds[i])
        decryptions.append(enc)
    end_create_aes_gcm_decrypt_request = time.perf_counter()
    logger.debug("loop create_aes_gcm_decrypt_request",
                  extra ={"id batch" : r,
                    "order" : 1,
                    "#processed_data" :
                        len(data[1]),
                    "time_for_single_exec" :
                        (end_create_aes_gcm_decrypt_request
                            - start_create_aes_gcm_decrypt_request) / len(data[1]),
                    "effective_time" : end_create_aes_gcm_decrypt_request -
                        start_create_aes_gcm_decrypt_request,
                    "size snowflake batch" : len(data[1])})
    start_post_operations = time.perf_counter()
    bulk = post_operations(decryptions,r,num_threads=4, threshold=1000, conf_path=configuration)
    end_post_operations = time.perf_counter()
    logger.debug("post_operations",
                  extra ={"id batch" : r,
                    "order" : 8,
                    "#processed_data" :
                        len(data[1]),
                    "time_for_single_exec" :
                        (end_post_operations
                            - start_post_operations) / len(data[1]),
                    "effective_time" : end_post_operations -
                        start_post_operations,
                    "size snowflake batch" : len(data[1])})
    results = []
    start_parse_decrypt_response_payload = time.perf_counter()
    for b in bulk:
      assert b.operation == 'Decrypt'
      res = parse_decrypt_response_payload(b.value)
      results.append(res.decode('utf-8'))
    end_parse_decrypt_response_payload = time.perf_counter()
    logger.debug("loop parse_decrypt_response_payload",
                 extra ={"id batch" : r,
                        "order" : 9,
                        "#processed_data" :
                            len(data[1]),
                        "time_for_single_exec" :
                            (end_parse_decrypt_response_payload
                                - start_parse_decrypt_response_payload) / len(data[1]),
                        "effective_time" : end_parse_decrypt_response_payload -
                            start_parse_decrypt_response_payload,
                        "size snowflake batch" : len(data[1])})
    start_final_pandas = time.perf_counter()
    res = pandas.Series(results)
    end_final_pandas = time.perf_counter()
    logger.debug("pandas.Series(results)", extra ={"id batch" : r,
                "order" : 10,
                "#processed_data" :
                    len(data[1]),
                "time_for_single_exec" :
                    (end_final_pandas
                        - start_final_pandas) / len(data[1]),
                "effective_time" : end_final_pandas - start_final_pandas,
                "size snowflake batch" : len(data[1])})

    return res


def create_key_aes(user):
    key = create_aes_key(size=256, tags=["tag1", "tag2"], conf_path=configuration)
    return key

def test() :
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
    clear = [create_aes_gcm_encrypt_request(key_id=key, data=x.encode("utf-8")) for x in data[1:11]]
    print("clear: ", clear)
    print("encrypt request done")
    print("post_operations beginning")
    bulk = post_operations(clear, num_threads=10, threshold=1500, conf_path=configuration)
    print("end post_operations")
    res = [parse_encrypt_response_payload(x.value) for x in bulk]

    print("starting decrypt")
    print("created decrypt request")
    ctx = [create_aes_gcm_decrypt_request(key_id=key, ciphertext=x) for x in res]
    bulk = post_operations(ctx, num_threads=10, threshold=1500, conf_path=configuration)
    print("end post operations")
    res = [parse_decrypt_response_payload(x.value) for x in bulk]
    print(res)
    return res

def main():
    #test in locale
    test()

if __name__ == "__main__":
    main()
