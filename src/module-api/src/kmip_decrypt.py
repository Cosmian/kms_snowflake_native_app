import orjson
from copy import deepcopy

# This JSON was generated using the following CLI command:

# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" \
# ckms sym decrypt -k 25b0b9e6-fd68-4d2f-bda8-ca4ae5b9bc3c -o /tmp/readme.md /tmp/readme.enc
#
# Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
DECRYPT = orjson.loads("""
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




def create_decrypt_request(key_id: str, ciphertext: bytes, is_authenticated_aes = False) -> dict:
    """
    Create an AES GCM decrypt request

    Args:
      key_id (str): AES key ID
      ciphertext (bytes): ciphertext to decrypt
      is_authenticated_aes: whether the ciphertext is an AES concatenation of nonce, data and tag

    Returns:
      dict: the Decrypt request
    """
    req = deepcopy(DECRYPT)
    hex_string = ciphertext.hex().upper()
    # set the key ID
    req['value'][0]['value'] = key_id

    if is_authenticated_aes:
        # set the nonce
        req['value'][2]['value'] = hex_string[:24]
        # set the data
        req['value'][1]['value'] = hex_string[24:-32]
        # set the tag
        req['value'][3]['value'] = hex_string[-32:]
    else:
        # set the data
        req['value'][1]['value'] = hex_string

    return req




def parse_decrypt_response(response: dict) -> bytes:
    """
        Parse a decrypt response JSON

    Args:
      response (dict): the decrypt JSON response

    Returns:
      bytes: the cleartext data
    """
    values = response['value']
    plaintext = ''
    for value in values:
        if value['tag'] == 'Data':
            plaintext = value['value']
    return bytes.fromhex(plaintext)


