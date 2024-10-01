import orjson
import requests
from copy import deepcopy
from lib.kmip_post import kmip_post

# This JSON was generated using the following CLI command:

# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms sym decrypt -k 25b0b9e6-fd68-4d2f-bda8-ca4ae5b9bc3c -o /tmp/readme.md /tmp/readme.enc
#
# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
AES_GCM_DECRYPT = orjson.loads("""
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
""")

# request
# KEY_ID_OR_TAGS_PATH = ext.parse('$..value[?tag = "UniqueIdentifier"]')
# DATA_PATH = ext.parse('$..value[?tag = "Data"]')
# NONCE_PATH = ext.parse('$..value[?tag = "IvCounterNonce"]')
# TAG_PATH = ext.parse('$..value[?tag = "AuthenticatedEncryptionTag"]')

# response
# CLEARTEXT_PATH = ext.parse('$..value[?tag = "Data"]')


def create_aes_gcm_decrypt_request(key_id: str, ciphertext: bytearray, bulk = False) -> dict:
    """
    Create an AES GCM decrypt request

    Args:
      key_id (str): AES key ID
      ciphertext (bytes): ciphertext to decrypt

    Returns:
      str: the RSA encrypt request
    """
    req = deepcopy(AES_GCM_DECRYPT)
    hex_string = ciphertext.hex().upper()
    # set the key ID
    req['value'][0]['value'] = key_id

    if bulk:
        # set the data
        req['value'][1]['value'] = hex_string
    else:
        # set the nonce
        req['value'][2]['value'] = hex_string[:24]
        # set the data
        req['value'][1]['value'] = hex_string[24:-32]
        # set the tag
        req['value'][3]['value'] = hex_string[-32:]

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


def parse_decrypt_response_payload(response: dict) -> bytearray:
    """
    Parse an AES GCM decrypt response JSON

    Args:
      response (dict): the AES GCM decrypt JSON response

    Returns:
      bytes: the cleartext data
    """
    values = response['value']
    plaintext = ''
    for value in values:
        if value['tag'] == 'Data':
            plaintext = value['value']
    return bytearray.fromhex(plaintext)

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
    response = kmip_post(orjson.dumps(req), conf_path)
    cleartext = parse_decrypt_response(response)
    return cleartext
