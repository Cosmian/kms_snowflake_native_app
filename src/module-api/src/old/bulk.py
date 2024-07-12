import json
from typing import List

import requests
from jsonpath_ng import ext

from create_key_pair import create_rsa_key_pair
from kmip_post import kmip_post
from rsa_decrypt import create_rsa_decrypt_request, parse_decrypt_response_payload
from rsa_encrypt import create_rsa_encrypt_request, parse_encrypt_response_payload


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


def post_operations(operations: List[dict], conf_path: str = "~/.cosmian/kms.json") -> List[BulkResult]:
    """Post multiple operations

    Returns:
        List[dict]: list of Bulk Results
    """
    req = create_bulk_message(operations)
    response = kmip_post(json.dumps(req), conf_path)
    results = parse_bulk_responses(response)
    return results



