import binascii
import json
from typing import List
from jsonpath_ng import ext
from requests import Response

from kms_encrypt_python.kmip_post import kmip_post


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
KEY_SIZE_PATH = ext.parse('$..value[?tag = "CryptographicLength"]')
TAGS_PATH = ext.parse('$..value[?tag = "VendorAttributes"]')
# response
PRIVATE_KEY_PATH = ext.parse('$..value[?tag = "PrivateKeyUniqueIdentifier"]')
PUBLIC_KEY_PATH = ext.parse('$..value[?tag = "PublicKeyUniqueIdentifier"]')


def create_keypair_request(key_size: int = 2048, tags: list = None) -> str:
    req = CREATE_RSA_KEYPAIR.copy()

    # Set the  key size path
    if key_size != 2048:
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

    return json.dumps(req)


def parse_keypair_response(response: Response) -> Keypair:
    response_json = response.json()
    private_key = PRIVATE_KEY_PATH.find(response_json)[0].value['value']
    public_key = PUBLIC_KEY_PATH.find(response_json)[0].value['value']
    return Keypair(sk=private_key, pk=public_key)


def create_rsa_key_pair(size: int = 2048, tags: List[str] = None, conf_path: str = "~/.cosmian/kms.json") -> Keypair:
    """Create a RSA key pair

    Returns:
        dict: RSA key pair (sk,pk)
    """
    req_str = create_keypair_request(size, tags)
    response = kmip_post(req_str, conf_path)
    keypair = parse_keypair_response(response)
    return keypair
