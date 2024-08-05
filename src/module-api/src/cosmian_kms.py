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

    bulk = post_operations(encryptions, num_threads=threads, threshold=min_elem)
    results = []

    for b in bulk:
      assert b.operation == 'Encrypt'
      res = parse_encrypt_response_payload_aes(b.to_dict())
      results.append(res)
    return pandas.Series(results)

def encrypt_aes_single(key,data):
    return encrypt_with_aes_gcm(key_id=key, cleartext=data.encode('utf-8'))

@vectorized(input=pandas.DataFrame)
def encrypt_rsa(data):
    #res = encrypt_with_rsa(key_id=data[0], cleartext=data[1].encode("utf-8"))
    #return res.hex()
    pks = data[0]
    ds = data[1]
    # try:
    #   assert len(pks) == 1000
    # except AssertionError as e:
    #     raise AssertionError("length of the list is: "+ str(len(pks)))
    encryptions = [create_rsa_encrypt_request(key_id=pks[i], data=ds[i].encode("utf-8")) for i in range(0,len(ds))]
    bulk = post_operations(encryptions, num_threads=5)
    results = []
    for result in bulk:
         res = parse_encrypt_response_payload_rsa(result.to_dict())
         results.append(res)
    return pandas.Series(results)

@vectorized(input=pandas.DataFrame)
def identity(data):
    decryptions = []
    sks = data[0]
    ds = data[1]
    threads = 10
    min_elem = 1000

    res = []

    with requests.Session() as session:
      for i in range(0,len(data[0])):
        x = session.get('https://snowflake-kms.cosmian.dev/version')
        res.append(i)

    return pandas.Series(res)

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
    bulk = post_operations(decryptions,num_threads=threads, threshold=min_elem)
    results = []
    for b in bulk:
      assert b.operation == 'Decrypt'
      res = parse_decrypt_response_payload_aes(b.to_dict())
      results.append(res)
    return pandas.Series(results)

@vectorized(input=pandas.DataFrame)
def decrypt_rsa(data):
    #res = decrypt_with_rsa(key_id=user_key, ciphertext=bytes.fromhex(data))
    #return res.decode("utf-8")
    decryptions = []
    sks = data[0]
    ds = data[1]
    # try:
    #   assert len(sks) == 1000
    # except AssertionError as e:
    #     raise AssertionError("length of the list is: "+ str(len(sks)))
    for i in range(0,len(ds)):
        # try:
        #   assert pk == d
        # except AssertionError as e:
        #     raise AssertionError("id: " + str(id) + " public key: " + str(pk) + " data: " + str(d))
        dec = create_rsa_decrypt_request(key_id=sks[i], ciphertext=ds[i])
        decryptions.append(dec)
    bulk = post_operations(decryptions, num_threads=5)
    results = []
    for b in bulk:
      assert b.operation == 'Decrypt'
      res = parse_decrypt_response_payload_rsa(b.to_dict())
      results.append(res)
    return pandas.Series(results)



def create_keypair_rsa(user):
    keys = create_rsa_key_pair(size=2048, tags=["tag1", "tag2"])
    return (keys.pk, keys.sk)

def create_key_aes(user):
    key = create_aes_key(size=256, tags=["tag1", "tag2"])
    return key


configuration = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'
#configuration = '{"kms_server_url": "https://20.86.128.166"}'

# POST


def read_kms_configuration(conf: str = configuration):
    """
    Read  the KMS configuration

    Returns:
      dict: KMS configuration
    """
    # Define the file path
    # file_path = os.path.expanduser(conf_path)
    # Open the file and load the JSON
    # with open(file_path, 'r') as f:
    data = json.loads(conf)
    return data


def kmip_post(json_str: str, conf: str = configuration) -> requests.Response:
    """
    Post a KMIP request to a KMIP server

    Returns:
      dict: KMIP response
    """
    conf = read_kms_configuration(conf)

    # if "kms_server_url" in conf:
    kms_server_url = conf["kms_server_url"] + "/kmip/2_1"
    # else:
    #    raise Exception("kms_server_url not found in configuration file " + conf)

    headers = {
        "Content-Type": "application/json",
    }

    if "kms_access_token" in conf:
        headers["Authorization"] = "Bearer " + conf["kms_access_token"]

    return requests.post(kms_server_url, headers=headers, data=json_str)

# ENCRYPT RSA

# This JSON was generated using the following CLI command:


# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms rsa encrypt -e ckm-rsa-aes-key-wrap -k e4d41132-8363-4e8a-9758-bdea38e87f6d cleartext.txt -o ciphertext.enc
#
# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
RSA_ENCRYPT = """
{
  "tag": "Encrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "e4d41132-8363-4e8a-9758-bdea38e87f6d"
    },
    {
      "tag": "CryptographicParameters",
      "type": "Structure",
      "value": [
        {
          "tag": "PaddingMethod",
          "type": "Enumeration",
          "value": "OAEP"
        },
        {
          "tag": "HashingAlgorithm",
          "type": "Enumeration",
          "value": "SHA256"
        },
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        }
      ]
    },
    {
      "tag": "Data",
      "type": "ByteString",
      "value": "2D2D2D0A7469746C653A20436F6E7472696275746F72730A2D2D2D0A0A2D2020204272756E6F2047726965646572205C3C3C6272756E6F2E6772696564657240636F736D69616E2E636F6D3E5C3E0A"
    }
  ]
}
"""

# request
KEY_ID_OR_TAGS_PATH_RSA = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH_RSA = ext.parse('$..value[?tag = "Data"]')

# response
CIPHERTEXT_PATH_RSA = ext.parse('$..value[?tag = "Data"]')


def create_rsa_encrypt_request(key_id: str, data: bytes) -> dict:
    """
    Create an RSA encrypt request

    Args:
      key_id (str): RSA key ID
      data (bytes): data to encrypt

    Returns:
      str: the RSA encrypt request
    """
    req = json.loads(RSA_ENCRYPT)

    # set the key ID
    KEY_ID_OR_TAGS_PATH_RSA.find(req)[0].value['value'] = key_id

    # set the data
    DATA_PATH_RSA.find(req)[0].value['value'] = data.hex().upper()

    return req


def parse_encrypt_response_rsa(response: requests.Response) -> bytes:
    """
    Parse an RSA encrypt response

    Args:
      response (str): the RSA encrypt response

    Returns:
      bytes: the encrypted data
    """
    return parse_encrypt_response_payload_rsa(response.json())


def parse_encrypt_response_payload_rsa(payload: dict) -> bytes:
    return bytes.fromhex(CIPHERTEXT_PATH_RSA.find(payload)[0].value['value'])


def encrypt_with_rsa(key_id: str, cleartext: bytes, conf: str = configuration) -> bytes:
    """
    Encrypt cleartext with RSA

    Args:
      key_id (str): RSA key ID
      cleartext (bytes): cleartext to encrypt
      conf_path (str): KMS configuration file path

    Returns:
      bytes: ciphertext
    """
    req = create_rsa_encrypt_request(key_id, cleartext)
    response = kmip_post(json.dumps(req), conf)
    ciphertext = parse_encrypt_response_rsa(response)
    return ciphertext


# DECRYPT


# This JSON was generated using the following CLI command:

# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms rsa decrypt -e ckm-rsa-aes-key-wrap -k 96125549-e115-42b9-ad57-9b51ee3ebed3 ciphertext.enc -o cleartext.txt
#
# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
RSA_DECRYPT = """
{
  "tag": "Decrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "96125549-e115-42b9-ad57-9b51ee3ebed3"
    },
    {
      "tag": "CryptographicParameters",
      "type": "Structure",
      "value": [
        {
          "tag": "PaddingMethod",
          "type": "Enumeration",
          "value": "OAEP"
        },
        {
          "tag": "HashingAlgorithm",
          "type": "Enumeration",
          "value": "SHA256"
        },
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        }
      ]
    },
    {
      "tag": "Data",
      "type": "ByteString",
      "value": "A693527349617764BECB5D6A103967A673B2C292C08E3376902D8DB68B5763BEEFD6C524286778A44034F55B5C9AF310ED92EDA13B178D0BF2F126BB6E65E329C550835ABA528F6BE5A51DA79A4577C23D3C20C88BE9FFC752E6BE6EDA7E9942AAF24CE4119CFE455D1CCF60E8F2C5025A1FADE8B99E4675613CF0EFCEDFA9FD5BD46EEB781105B27E61C412161984EBDBC8E27C4C5ED5DA4AA2C876D4BFB8E5C846C41702B5182EFD205EF071FEBD668189B2A4588FB030110D9886DB2B0E6E7F5831D4100F5CFED82489AEA8D7E0AF853506EC28486109CB2BADCF1A4846015271F5530EF1B448126069F8F6EB6E4ECCDA0B816EAFB74095C015FBA18797C53F150EAED4B7CB1B327AAFAED1217FBFAE117C01A830B7CB40BA0688804EBF5F902B13CE3D03F292130EF78BB9B5D9CAADC7F776FA3F0C6D9C30D8D6AE643954D82976FC58199A1CEDC6770F986572181CBA0B7FBC4673C1C8EDFDED53DE64E569CD7839A14138A7F49A87458DF69FA4915F1E088A41E70C5C0C181C5D7890F07261E4D38E83E8EA25C526D14719801A93B3DCAB24A95EC211EF9819733D80C68225FC6CBDFC29F27205F3AB07703435A07189F8D949B0A80B8BF461170EE4A40F3D4CDCCF3B76406A4148FE450A1C1FB35423AEE054BFFC7262787EECF4F1C99A22112399EE7D7E37FB631FE135224A21F3262DD464A74FA189095F73BCD743DD87D6D8022A88A553C972EA6D7AA402FCB660C6215E08583751C0769D43CE93791ECFF046427FB81C72B629581627A711741457B685C6D3DDDCBDE05635A5C09391AEA666641A745EB13273B54575CB1C21838595EA61A5"
    }
  ]
}
"""

# request
KEY_ID_OR_TAGS_PATH_RSA = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH_RSA = ext.parse('$..value[?tag = "Data"]')

# response
CIPHERTEXT_PATH_RSA = ext.parse('$..value[?tag = "Data"]')


def create_rsa_decrypt_request(key_id: str, ciphertext: bytes) -> dict:
    """
    Create an RSA decrypt request

    Args:
      key_id (str): RSA key ID
      ciphertext (bytes): ciphertext to decrypt

    Returns:
      str: the RSA encrypt request
    """
    req = json.loads(RSA_DECRYPT)

    # set the key ID
    KEY_ID_OR_TAGS_PATH_RSA.find(req)[0].value['value'] = key_id

    # set the ciphertext
    DATA_PATH_RSA.find(req)[0].value['value'] = ciphertext.hex().upper()

    return req


def parse_decrypt_response_rsa(response: requests.Response) -> bytes:
    """
    Parse an RSA decrypt response

    Args:
      response (str): the RSA decrypt response

    Returns:
      bytes: the cleartext data
    """
    return parse_decrypt_response_payload_rsa(response.json())


def parse_decrypt_response_payload_rsa(payload: dict) -> bytes:
    return bytes.fromhex(CIPHERTEXT_PATH_RSA.find(payload)[0].value['value'])


def decrypt_with_rsa(key_id: str, ciphertext: bytes, conf: str = configuration) -> bytes:
    """
    Decrypt ciphertext with RSA

    Args:
      key_id (str): RSA key ID
      ciphertext (bytes): ciphertext to decrypt
      conf_path (str): KMS configuration file path

    Returns:
      bytes: cleartext
    """
    req = create_rsa_decrypt_request(key_id, ciphertext)
    response = kmip_post(json.dumps(req), conf)
    cleartext = parse_decrypt_response_rsa(response)
    return cleartext


# CREATE KEY PAIR


class Keypair:
    sk: str
    pk: str

    def __init__(self, sk: str, pk: str):
        self.sk = sk
        self.pk = pk


CREATE_RSA_KEYPAIR = json.loads("""
{
  "tag": "CreateKeyPair",
  "type": "Structure",
  "value": [
    {
      "tag": "CommonAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        },
        {
          "tag": "VendorAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "VendorAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "VendorIdentification",
                  "type": "TextString",
                  "value": "cosmian"
                },
                {
                  "tag": "AttributeName",
                  "type": "TextString",
                  "value": "tag"
                },
                {
                  "tag": "AttributeValue",
                  "type": "ByteString",
                  "value": "5B22746573745F6B6579225D"
                }
              ]
            }
          ]
        }
      ]
    },
    {
      "tag": "PrivateKeyAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        }
      ]
    },
    {
      "tag": "PublicKeyAttributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "RSA"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 2048
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2097152
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentRSAPrivateKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "PrivateKey"
        }
      ]
    }
  ]
}
""")

# request
KEY_SIZE_PATH_RSA = ext.parse('$..value[?tag = "CryptographicLength"]')
TAGS_PATH_RSA = ext.parse('$..value[?tag = "VendorAttributes"]')
# response
PRIVATE_KEY_PATH_RSA = ext.parse('$..value[?tag = "PrivateKeyUniqueIdentifier"]')
PUBLIC_KEY_PATH_RSA = ext.parse('$..value[?tag = "PublicKeyUniqueIdentifier"]')


def create_keypair_request(key_size: int = 2048, tags: list = None) -> dict:
    req = CREATE_RSA_KEYPAIR.copy()

    # Set the  key size path
    if key_size != 2048:
        ks_path = KEY_SIZE_PATH_RSA.find(req)
        ks_path[0].value['value'] = key_size

    # Set the tags
    if tags is not None:
        # Convert list to JSON string
        json_str = json.dumps(tags)
        # Convert JSON string to hex bytes
        hex_str = json_str.encode('utf-8').hex().upper()
        # Set the tags path
        tags_path = TAGS_PATH_RSA.find(req)
        tags_path[0].value['value'][0]['value'][2]['value'] = hex_str
    else:
        # remove the VendorAttributes path
        TAGS_PATH.filter(lambda d: True, req)

    return req


def parse_keypair_response_rsa(response: Response) -> Keypair:
    response_json = response.json()
    return parse_keypair_response_payload_rsa(response_json)


def parse_keypair_response_payload_rsa(payload: dict) -> Keypair:
    private_key = PRIVATE_KEY_PATH_RSA.find(payload)[0].value['value']
    public_key = PUBLIC_KEY_PATH_RSA.find(payload)[0].value['value']
    return Keypair(sk=private_key, pk=public_key)


def create_rsa_key_pair(size: int = 2048, tags: List[str] = None, conf: str = configuration) -> Keypair:
    """Create a RSA key pair

    Returns:
        dict: RSA key pair (sk,pk)
    """
    req = create_keypair_request(size, tags)
    response = kmip_post(json.dumps(req), conf)
    keypair = parse_keypair_response_rsa(response)
    return keypair




# AES DECRYPT

AES_GCM_DECRYPT = """
{
  "tag": "Decrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "25b0b9e6-fd68-4d2f-bda8-ca4ae5b9bc3c"
    },
    {
      "tag": "Data",
      "type": "ByteString",
      "value": "7292EFE...3913"
    },
    {
      "tag": "IvCounterNonce",
      "type": "ByteString",
      "value": "4A5A36F173C600602446AAAB"
    },
    {
      "tag": "AuthenticatedEncryptionTag",
      "type": "ByteString",
      "value": "391B60222172A025CEA0007479B432EE"
    }
  ]
}
"""

# request
KEY_ID_OR_TAGS_PATH_AES = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH_AES = ext.parse('$..value[?tag = "Data"]')
NONCE_PATH_AES = ext.parse('$..value[?tag = "IvCounterNonce"]')
TAG_PATH_AES = ext.parse('$..value[?tag = "AuthenticatedEncryptionTag"]')

# response
CLEARTEXT_PATH_AES = ext.parse('$..value[?tag = "Data"]')


def create_aes_gcm_decrypt_request(key_id: str, ciphertext: bytes) -> dict:
    """
    Create an AES GCM decrypt request

    Args:
      key_id (str): AES key ID
      ciphertext (bytes): ciphertext to decrypt

    Returns:
      str: the RSA encrypt request
    """
    req = json.loads(AES_GCM_DECRYPT)
    hex_string = ciphertext.hex().upper()

    # set the key ID
    KEY_ID_OR_TAGS_PATH_AES.find(req)[0].value['value'] = key_id

    # set the nonce
    NONCE_PATH_AES.find(req)[0].value['value'] = hex_string[:24]
    # set the data
    DATA_PATH_AES.find(req)[0].value['value'] = hex_string[24:-32]
    # set the tag
    TAG_PATH_AES.find(req)[0].value['value'] = hex_string[-32:]

    return req


def parse_decrypt_response_aes(response: requests.Response) -> bytes:
    """
    Parse an AES GCM decrypt response

    Args:
      response (str): the AES GCM decrypt response

    Returns:
      bytes: the cleartext data
    """
    return parse_decrypt_response_payload_aes(response.json())


def parse_decrypt_response_payload_aes(payload: dict) -> bytes:
    """
    Parse an AES GCM decrypt response JSON

    Args:
      payload (dict): the AES GCM decrypt JSON response

    Returns:
      bytes: the cleartext data
    """
    return bytes.fromhex(CLEARTEXT_PATH_AES.find(payload)[0].value['value'])

def decrypt_with_aes_gcm(key_id: str, ciphertext: bytes, conf_path: str = configuration) -> bytes:
    """
    Decrypt ciphertext with AES GCM

    Args:
      key_id (str): AES key ID
      ciphertext (bytes): ciphertext to decrypt
      conf_path (str): KMS configuration file path

    Returns:
      bytes: cleartext
    """
    req = create_aes_gcm_decrypt_request(key_id, ciphertext)
    response = kmip_post(json.dumps(req), conf_path)
    cleartext = parse_decrypt_response_aes(response)
    return cleartext


# AES ENCRYPT

AES_ENCRYPT = """
{
  "tag": "Encrypt",
  "type": "Structure",
  "value": [
    {
      "tag": "UniqueIdentifier",
      "type": "TextString",
      "value": "e4d41132-8363-4e8a-9758-bdea38e87f6d"
    },
    {
      "tag": "Data",
      "type": "ByteString",
      "value": "2D2D2D0A746974...36F6D3E5C3E0A"
    }
  ]
}
"""

# request
KEY_ID_OR_TAGS_PATH_AES = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH_AES = ext.parse('$..value[?tag = "Data"]')

# response
CIPHERTEXT_PATH_AES = ext.parse('$..value[?tag = "Data"]')
NONCE_PATH_AES = ext.parse('$..value[?tag = "IvCounterNonce"]')
TAG_PATH_AES = ext.parse('$..value[?tag = "AuthenticatedEncryptionTag"]')


def create_aes_gcm_encrypt_request(key_id: str, data: bytes) -> dict:
    """
    Create an AES GCM encrypt request

    Args:
      key_id (str): AES key ID
      data (bytes): data to encrypt

    Returns:
      str: the AES encrypt request
    """
    req = json.loads(AES_ENCRYPT)

    # set the key ID
    KEY_ID_OR_TAGS_PATH_AES.find(req)[0].value['value'] = key_id

    # set the data
    DATA_PATH_AES.find(req)[0].value['value'] = data.hex().upper()

    return req


def parse_encrypt_response_aes(response: requests.Response) -> bytes:
    """
    Parse an AES encrypt response
    Args:
        response: the AES GCM encrypt response

    Returns:
        bytes: the concatenated nonce, ciphertext and tag

    """
    return parse_encrypt_response_payload_aes(response.json())


def parse_encrypt_response_payload_aes(payload: dict) -> bytes:
    """
    Parse an AES encrypt response JSON payload
    Args:
        response: the AES GCM encrypt response

    Returns:
        bytes: the concatenated nonce, ciphertext and tag

    """
    ciphertext = CIPHERTEXT_PATH_AES.find(payload)[0].value['value']
    nonce = NONCE_PATH_AES.find(payload)[0].value['value']
    tag = TAG_PATH_AES.find(payload)[0].value['value']
    return bytes.fromhex(nonce+ciphertext+tag)

def encrypt_with_aes_gcm(key_id: str, cleartext: bytes, conf_path: str = configuration) -> bytes:
    """
    Encrypt cleartext with AES GCM

    Args:
      key_id (str): RSA key ID
      cleartext (bytes): cleartext to encrypt
      conf_path (str): KMS configuration file path

    Returns:
      bytes: AES GCM encrypted data as the concatenation of the nonce, ciphertext and tag
    """
    req = create_aes_gcm_encrypt_request(key_id, cleartext)
    response = kmip_post(json.dumps(req), conf_path)
    ciphertext = parse_encrypt_response_aes(response)
    return ciphertext

# AES KEYGEN

CREATE_AES_KEY = json.loads("""
{
  "tag": "Create",
  "type": "Structure",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SymmetricKey"
    },
    {
      "tag": "Attributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 256
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2108
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentSymmetricKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "SymmetricKey"
        },
        {
          "tag": "VendorAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "VendorAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "VendorIdentification",
                  "type": "TextString",
                  "value": "cosmian"
                },
                {
                  "tag": "AttributeName",
                  "type": "TextString",
                  "value": "tag"
                },
                {
                  "tag": "AttributeValue",
                  "type": "ByteString",
                  "value": "5B226165735F6B6579225D"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
""")

# request
KEY_SIZE_PATH_AES = ext.parse('$..value[?tag = "CryptographicLength"]')
TAGS_PATH_AES = ext.parse('$..value[?tag = "VendorAttributes"]')
# response
RESPONSE_KEY_PATH_AES = ext.parse('$..value[?tag = "UniqueIdentifier"]')


def create_aes_key_request(key_size: int = 2048, tags: list = None) -> dict:
    req = CREATE_AES_KEY.copy()

    # Set the  key size path
    if key_size != 256:
        ks_path = KEY_SIZE_PATH_AES.find(req)
        ks_path[0].value['value'] = key_size

    # Set the tags
    if tags is not None:
        # Convert list to JSON string
        json_str = json.dumps(tags)
        # Convert JSON string to hex bytes
        hex_str = json_str.encode('utf-8').hex().upper()
        # Set the tags path
        tags_path = TAGS_PATH_AES.find(req)
        tags_path[0].value['value'][0]['value'][2]['value'] = hex_str
    else:
        # remove the VendorAttributes path
        TAGS_PATH.filter(lambda d: True, req)

    return req


def parse_aes_key_response_aes(response: Response) -> str:
    response_json = response.json()
    return parse_aes_key_payload_aes(response_json)


def parse_aes_key_payload_aes(payload: dict) -> str:
    return RESPONSE_KEY_PATH_AES.find(payload)[0].value['value']


def create_aes_key(size: int = 256, tags: List[str] = None, conf_path: str = configuration) -> str:
    """Create an AES key

    Returns:
        an hex string of the AES key
    """
    req = create_aes_key_request(size, tags)
    response = kmip_post(json.dumps(req), conf_path)
    keypair = parse_aes_key_response_aes(response)
    return keypair


# PARALLEL BULK

class BulkResult:
    operation: str
    value: dict

    def __init__(self, operation: str, value: dict):
        self.operation = operation
        self.value = value

    def __str__(self):
        return f"{self.operation}: {self.value}"

    def to_dict(self):
        return {
            'operation': self.operation,
            'value': self.value
        }


BULK_MESSAGE = """
{
    "tag": "Message",
    "type": "Structure",
    "value": [
        {
            "tag": "Header",
            "type": "Structure",
            "value": [
                {
                    "tag": "ProtocolVersion",
                    "type": "Structure",
                    "value": [
                        {
                            "tag": "ProtocolVersionMajor",
                            "type": "Integer",
                            "value": 2
                        },
                        {
                            "tag": "ProtocolVersionMinor",
                            "type": "Integer",
                            "value": 1
                        }
                    ]
                },
                {
                    "tag": "MaximumResponseSize",
                    "type": "Integer",
                    "value": 9999
                },
                {
                    "tag": "BatchCount",
                    "type": "Integer",
                    "value": 2
                }
            ]
        },
        {
            "tag": "Items",
            "type": "Structure",
            "value": [
            ]
        }
    ]
}
"""

ITEMS_PATH = ext.parse('$..value[?tag = "Items"]')

BATCHED_OPERATION = """
 {
    "tag": "Items",
    "type": "Structure",
    "value": [
        {
            "tag": "Operation",
            "type": "Enumeration",
            "value": "CreateKeyPair"
        },
        {
            "tag": "RequestPayload",
            "type": "Structure",
            "value": []
        }
    ]
}
"""

RESPONSE_OPERATION = ext.parse('$..value[?tag = "Operation"]')
RESPONSE_PAYLOAD_PATH = ext.parse('$..value[?tag = "ResponsePayload"]')


def create_bulk_message(operations: List[dict]) -> dict:
    """
    Create a bulk message

    Returns:
      dict: the bulk message
    """
    ops = []
    for operation in operations:
        op = json.loads(BATCHED_OPERATION)
        op["value"][0]["value"] = operation['tag']
        op["value"][1]["value"] = operation["value"]
        ops.append(op)

    bulk_message = json.loads(BULK_MESSAGE)
    ITEMS_PATH.find(bulk_message)[0].value['value'] = ops
    return bulk_message


def parse_bulk_responses(response: requests.Response) -> List[BulkResult]:
    response_json = response.json()
    res = []
    for item in ITEMS_PATH.find(response_json)[0].value['value']:
        operation_tag = RESPONSE_OPERATION.find(item)[0].value['value']
        payload = RESPONSE_PAYLOAD_PATH.find(item)[0].value['value']
        res.append(BulkResult(operation_tag, payload))
    return res


# The threshold number of operations for multithreading
MULTI_THREAD_THRESHOLD = 300
# The default number of threads to use
NUM_THREADS = 5


def post_operations(operations: List[dict], num_threads=NUM_THREADS, threshold=MULTI_THREAD_THRESHOLD,
                    conf_path: str = configuration) -> List[BulkResult]:
    """
    Post a list of operations to the KMS
    Args:
        operations: the operations to post
        num_threads: the number of threads to use. Defaults to NUM_THREADS
        threshold: the threshold number of operations for multithreading. Defaults to MULTI_THREAD_THRESHOLD
        conf_path: the path to the configuration file. Defaults to configuration

    Returns:
        List[BulkResult]: the results of the operations
    """
    num_operations = len(operations)
    # do not multithread for less than threshold operations
    if num_operations < threshold:
        return post_operations_chunk(operations, conf_path)

    # Split the operations into chunks
    k, m = divmod(len(operations), num_threads)
    #chunks = [(i,operations[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]) for i in range(num_threads)]
    chunks = [operations[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_threads)]

    # Post the operations in parallel
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(post_operations_chunk, chunks))

    #results = sorted(results, key=lambda tup: tup[0])
    #results = [map(lambda x: x[1],result) for result in results]

    # Flatten the list of results
    combined_results = [item for sublist in results for item in sublist]
    return combined_results


def post_operations_chunk(chunk: List[dict], #tuple[int,List[dict]],
                           conf_path: str = configuration) -> List[BulkResult]:#List[tuple[int,BulkResult]]:
    #(id,chunk) = chunk
    req = create_bulk_message(chunk)
    response = kmip_post(json.dumps(req), conf_path)
    results = parse_bulk_responses(response)
    return results

if __name__ == "__main__":
    key_id = "0d319307-f766-4869-b90a-02096edb9431"
    create_keypair_rsa('azer')
