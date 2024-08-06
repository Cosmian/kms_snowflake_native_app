import json

import requests
from jsonpath_ng import ext

from kmip_post import kmip_post

# This JSON was generated using the following CLI command:

# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms sym decrypt -k 25b0b9e6-fd68-4d2f-bda8-ca4ae5b9bc3c -o /tmp/readme.md /tmp/readme.enc
#
# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
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
KEY_ID_OR_TAGS_PATH = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH = ext.parse('$..value[?tag = "Data"]')
NONCE_PATH = ext.parse('$..value[?tag = "IvCounterNonce"]')
TAG_PATH = ext.parse('$..value[?tag = "AuthenticatedEncryptionTag"]')

# response
CLEARTEXT_PATH = ext.parse('$..value[?tag = "Data"]')


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
    KEY_ID_OR_TAGS_PATH.find(req)[0].value['value'] = key_id

    # set the nonce
    NONCE_PATH.find(req)[0].value['value'] = hex_string[:24]
    # set the data
    DATA_PATH.find(req)[0].value['value'] = hex_string[24:-32]
    # set the tag
    TAG_PATH.find(req)[0].value['value'] = hex_string[-32:]

    return req


def parse_decrypt_response(response: requests.Response) -> bytes:
    """
    Parse an AES GCM decrypt response

    Args:
      response (str): the AES GCM decrypt response

    Returns:
      bytes: the cleartext data
    """
    return parse_decrypt_response_payload(response.json())


def parse_decrypt_response_payload(payload: dict) -> bytes:
    """
    Parse an AES GCM decrypt response JSON

    Args:
      payload (dict): the AES GCM decrypt JSON response

    Returns:
      bytes: the cleartext data
    """
    return bytes.fromhex(CLEARTEXT_PATH.find(payload)[0].value['value'])

def decrypt_with_aes_gcm(key_id: str, ciphertext: bytes, conf_path: str = "~/.cosmian/kms.json") -> bytes:
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
    cleartext = parse_decrypt_response(response)
    return cleartext
