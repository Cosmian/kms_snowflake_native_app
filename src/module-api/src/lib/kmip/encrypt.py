import orjson
from copy import deepcopy
import requests
from lib.kmip_post import kmip_post

# This JSON was generated using the following CLI command:
#
# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms rsa encrypt -k 25b0b9e6-fd68-4d2f-bda8-ca4ae5b9bc3c cleartext.txt -o ciphertext.enc

# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
ENCRYPT = orjson.loads("""
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
""")



def create_encrypt_request(key_id: str, cleartext: bytes) -> dict:
    """
    Create an AES GCM encrypt request

    Args:
      key_id (str): AES key ID
      cleartext (bytes): data to encrypt

    Returns:
      str: the AES encrypt request
    """
    req = deepcopy(ENCRYPT)

    # set the key ID
    req['value'][0]['value'] = key_id
    # KEY_ID_OR_TAGS_PATH.find(req)[0].value['value'] = key_id

    # set the data
    req['value'][1]['value'] = cleartext.hex().upper()
    # DATA_PATH.find(req)[0].value['value'] = data.hex().upper()

    return req


def parse_encrypt_response(response: dict) -> bytes:
    """
    Parse an AES encrypt response JSON payload
    Args:
        response: the AES GCM encrypt response

    Returns:
        bytes: the concatenated nonce, ciphertext and tag

    """
    values = response['value']
    nonce = ''
    ciphertext = ''
    tag = ''
    for value in values:
        if value['tag'] == 'Data':
            ciphertext = value['value']
        elif value['tag'] == 'IvCounterNonce':
            nonce = value['value']
        elif value['tag'] == 'AuthenticatedEncryptionTag':
            tag = value['value']
    return bytes.fromhex(nonce+ciphertext+tag)

