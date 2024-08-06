import json
from concurrent.futures import ThreadPoolExecutor
from typing import List
import requests
from jsonpath_ng import ext
from kmip_post import kmip_post


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
MULTI_THREAD_THRESHOLD = 100
# The default number of threads to use
NUM_THREADS = 5


def post_operations(operations: List[dict], num_threads=NUM_THREADS, threshold=MULTI_THREAD_THRESHOLD,
                    conf_path: str = "~/.cosmian/kms.json") -> List[BulkResult]:
    """
    Post a list of operations to the KMS
    Args:
        operations: the operations to post
        num_threads: the number of threads to use. Defaults to NUM_THREADS
        threshold: the threshold number of operations for multithreading. Defaults to MULTI_THREAD_THRESHOLD
        conf_path: the path to the configuration file. Defaults to "~/.cosmian/kms.json"

    Returns:
        List[BulkResult]: the results of the operations
    """
    num_operations = len(operations)
    # do not multithread for less than threshold operations
    if num_operations < threshold:
        return post_operations_chunk(operations, conf_path)

    # Split the operations into chunks
    k, m = divmod(len(operations), num_threads)
    chunks = [operations[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_threads)]

    # Post the operations in parallel
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(post_operations_chunk, chunks))

    # Flatten the list of results
    combined_results = [item for sublist in results for item in sublist]
    return combined_results


def post_operations_chunk(chunk: List[dict], conf_path: str = "~/.cosmian/kms.json") -> List[BulkResult]:
    req = create_bulk_message(chunk)
    response = kmip_post(json.dumps(req), conf_path)
    results = parse_bulk_responses(response)
    return results
