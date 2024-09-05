import os
import requests
from requests import Response
import math
from typing import List
import pandas
import _snowflake
from _snowflake import vectorized
from operator import itemgetter
from concurrent.futures import ThreadPoolExecutor
from create_aes_key import create_aes_key
from aes_gcm_decrypt import create_aes_gcm_decrypt_request, \
    parse_decrypt_response_payload
from aes_gcm_encrypt import create_aes_gcm_encrypt_request, \
    parse_encrypt_response_payload
from bulk import post_operations
import csv

# configuration = 'kms.json'
configuration = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
@vectorized(input=pandas.DataFrame, max_batch_size=20000)
def encrypt_aes(data):
    encryptions = []
    pks = data[0]
    ds = data[1]
    threads = data[2][0]
    min_elem = data[3][0]

    for i in range(0,len(data)):
        enc = create_aes_gcm_encrypt_request(key_id=pks[i], data=ds[i].encode('utf-8'))
        encryptions.append(enc)

    bulk = post_operations(encryptions, num_threads=int(math.floor(len(data)/5000)) + 1, threshold=min_elem, conf_path=configuration)
    results = []

    for b in bulk:
      assert b.operation == 'Encrypt'
      res = parse_encrypt_response_payload(b.value)
      results.append(res)
    return pandas.Series(results)


@vectorized(input=pandas.DataFrame, max_batch_size=20000)
def decrypt_aes(data):
    decryptions = []
    sks = data[0]
    ds = data[1]
    threads = data[2][0]
    min_elem = data[3][0]
    for i in range(0,len(data)):
        enc = create_aes_gcm_decrypt_request(key_id=sks[i], ciphertext=ds[i])
        decryptions.append(enc)
    bulk = post_operations(decryptions,num_threads=int(math.floor(len(data)/5000)) + 1, threshold=min_elem, conf_path=configuration)
    results = []
    for b in bulk:
      assert b.operation == 'Decrypt'
      res = parse_decrypt_response_payload(b.value)
      results.append(res)
    return pandas.Series(results)


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
    clear = [create_aes_gcm_encrypt_request(key_id=key, data=x.encode('utf-8')) for x in data[1:11]]
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
