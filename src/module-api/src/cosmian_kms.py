import json
import os
import requests
from requests import Response
from jsonpath_ng import ext
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


configuration = '~/module-api/kms.json'

@vectorized(input=pandas.DataFrame)
def encrypt_aes(data):
    encryptions = []
    pks = data[0]
    ds = data[1]
    threads = data[2][0]
    min_elem = data[3][0]

    for i in range(0,len(data)):
        enc = create_aes_gcm_encrypt_request(key_id=pks[i], data=ds[i].encode('utf-8'))
        encryptions.append(enc)

    bulk = post_operations(encryptions, num_threads=threads, threshold=min_elem, conf_path=configuration)
    results = []

    for b in bulk:
      assert b.operation == 'Encrypt'
      res = parse_encrypt_response_payload(b.to_dict())
      results.append(res)
    return pandas.Series(results)


@vectorized(input=pandas.DataFrame)
def decrypt_aes(data):
    decryptions = []
    sks = data[0]
    ds = data[1]
    threads = data[2][0]
    min_elem = data[3][0]

    for i in range(0,len(data)):
        enc = create_aes_gcm_decrypt_request(key_id=sks[i], ciphertext=ds[i])
        decryptions.append(enc)
    bulk = post_operations(decryptions,num_threads=threads, threshold=min_elem, conf_path=configuration)
    results = []
    for b in bulk:
      assert b.operation == 'Decrypt'
      res = parse_decrypt_response_payload(b.to_dict())
      results.append(res)
    return pandas.Series(results)


def create_key_aes(user):
    key = create_aes_key(size=256, tags=["tag1", "tag2"], conf_path=configuration)
    return key

# @vectorized(input=pandas.DataFrame)
# def encrypt_rsa(data):
#     #res = encrypt_with_rsa(key_id=data[0], cleartext=data[1].encode("utf-8"))
#     #return res.hex()
#     pks = data[0]
#     ds = data[1]
#     # try:
#     #   assert len(pks) == 1000
#     # except AssertionError as e:
#     #     raise AssertionError("length of the list is: "+ str(len(pks)))
#     encryptions = [create_rsa_encrypt_request(key_id=pks[i], data=ds[i].encode("utf-8")) for i in range(0,len(ds))]
#     bulk = post_operations(encryptions, num_threads=5)
#     results = []
#     for result in bulk:
#          res = parse_encrypt_response_payload_rsa(result.to_dict())
#          results.append(res)
#     return pandas.Series(results)

# @vectorized(input=pandas.DataFrame)
# def identity(data):
#     decryptions = []
#     sks = data[0]
#     ds = data[1]
#     threads = 10
#     min_elem = 1000

#     res = []

#     with requests.Session() as session:
#       for i in range(0,len(data[0])):
#         x = session.get('https://snowflake-kms.cosmian.dev/version')
#         res.append(i)

#     return pandas.Series(res)


# @vectorized(input=pandas.DataFrame)
# def decrypt_rsa(data):
#     #res = decrypt_with_rsa(key_id=user_key, ciphertext=bytes.fromhex(data))
#     #return res.decode("utf-8")
#     decryptions = []
#     sks = data[0]
#     ds = data[1]
#     # try:
#     #   assert len(sks) == 1000
#     # except AssertionError as e:
#     #     raise AssertionError("length of the list is: "+ str(len(sks)))
#     for i in range(0,len(ds)):
#         # try:
#         #   assert pk == d
#         # except AssertionError as e:
#         #     raise AssertionError("id: " + str(id) + " public key: " + str(pk) + " data: " + str(d))
#         dec = create_rsa_decrypt_request(key_id=sks[i], ciphertext=ds[i])
#         decryptions.append(dec)
#     bulk = post_operations(decryptions, num_threads=5)
#     results = []
#     for b in bulk:
#       assert b.operation == 'Decrypt'
#       res = parse_decrypt_response_payload_rsa(b.to_dict())
#       results.append(res)
#     return pandas.Series(results)

# def create_keypair_rsa(user):
#     keys = create_rsa_key_pair(size=2048, tags=["tag1", "tag2"])
#     return (keys.pk, keys.sk)




def main():
    # Your code here
    print("initialized")

if __name__ == "__main__":
    main()
