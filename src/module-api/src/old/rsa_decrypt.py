import json

import requests
from jsonpath_ng import ext

from kmip_post import kmip_post

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
KEY_ID_OR_TAGS_PATH = ext.parse('$..value[?tag = "UniqueIdentifier"]')
DATA_PATH = ext.parse('$..value[?tag = "Data"]')

# response
CIPHERTEXT_PATH = ext.parse('$..value[?tag = "Data"]')


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
    KEY_ID_OR_TAGS_PATH.find(req)[0].value['value'] = key_id

    # set the ciphertext
    DATA_PATH.find(req)[0].value['value'] = ciphertext.hex().upper()

    return req


def parse_decrypt_response(response: requests.Response) -> bytes:
    """
    Parse an RSA decrypt response

    Args:
      response (str): the RSA decrypt response

    Returns:
      bytes: the cleartext data
    """
    return parse_decrypt_response_payload(response.json())


def parse_decrypt_response_payload(payload: dict) -> bytes:
    return bytes.fromhex(CIPHERTEXT_PATH.find(payload)[0].value['value'])


def decrypt_with_rsa(key_id: str, ciphertext: bytes, conf_path: str = "~/.cosmian/kms.json") -> bytes:
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
    response = kmip_post(json.dumps(req), conf_path)
    cleartext = parse_decrypt_response(response)
    return cleartext
