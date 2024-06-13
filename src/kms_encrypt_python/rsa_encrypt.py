import json
from typing import List, Any

import requests
from jsonpath_ng import ext

from kms_encrypt_python.kmip_post import kmip_post

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
KEY_ID_OR_TAGS_PATH = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH = ext.parse('$..value[?tag = "Data"]')

# response
CIPHERTEXT_PATH = ext.parse('$..value[?tag = "Data"]')


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
    KEY_ID_OR_TAGS_PATH.find(req)[0].value['value'] = key_id

    # set the data
    DATA_PATH.find(req)[0].value['value'] = data.hex().upper()

    return req


def parse_encrypt_response(response: requests.Response) -> bytes:
    """
    Parse an RSA encrypt response

    Args:
      response (str): the RSA encrypt response

    Returns:
      bytes: the encrypted data
    """
    return parse_encrypt_response_payload(response.json())


def parse_encrypt_response_payload(payload: dict) -> bytes:
    return bytes.fromhex(CIPHERTEXT_PATH.find(payload)[0].value['value'])


def encrypt_with_rsa(key_id: str, cleartext: bytes, conf_path: str = "~/.cosmian/kms.json") -> bytes:
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
    response = kmip_post(json.dumps(req), conf_path)
    ciphertext = parse_encrypt_response(response)
    return ciphertext


def bulk_encrypt_with_rsa(key_id: str, cleartext: List[bytes], conf_path: str = "~/.cosmian/kms.json") -> bytes:
    pass
