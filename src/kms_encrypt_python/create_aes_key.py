import json
from typing import List
from jsonpath_ng import ext
from requests import Response

from kms_encrypt_python.kmip_post import kmip_post


# This JSON was generated using the following CLI command:
# RUST_LOG="cosmian_kms_client::kms_rest_client=debug" ckms sym keys create -a aes -l 256 --tag aes_key
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
KEY_SIZE_PATH = ext.parse('$..value[?tag = "CryptographicLength"]')
TAGS_PATH = ext.parse('$..value[?tag = "VendorAttributes"]')
# response
RESPONSE_KEY_PATH = ext.parse('$..value[?tag = "UniqueIdentifier"]')


def create_aes_key_request(key_size: int = 2048, tags: list = None) -> dict:
    req = CREATE_AES_KEY.copy()

    # Set the  key size path
    if key_size != 256:
        ks_path = KEY_SIZE_PATH.find(req)
        ks_path[0].value['value'] = key_size

    # Set the tags
    if tags is not None:
        # Convert list to JSON string
        json_str = json.dumps(tags)
        # Convert JSON string to hex bytes
        hex_str = json_str.encode('utf-8').hex().upper()
        # Set the tags path
        tags_path = TAGS_PATH.find(req)
        tags_path[0].value['value'][0]['value'][2]['value'] = hex_str
    else:
        # remove the VendorAttributes path
        TAGS_PATH.filter(lambda d: True, req)

    return req


def parse_aes_key_response(response: Response) -> str:
    response_json = response.json()
    return parse_aes_key_payload(response_json)


def parse_aes_key_payload(payload: dict) -> str:
    return RESPONSE_KEY_PATH.find(payload)[0].value['value']


def create_aes_key(size: int = 256, tags: List[str] = None, conf_path: str = "~/.cosmian/kms.json") -> str:
    """Create an AES key

    Returns:
        an hex string of the AES key
    """
    req = create_aes_key_request(size, tags)
    response = kmip_post(json.dumps(req), conf_path)
    keypair = parse_aes_key_response(response)
    return keypair
