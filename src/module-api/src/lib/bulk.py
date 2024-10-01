from concurrent.futures import ThreadPoolExecutor
from functools import partial
import orjson
from typing import List
import requests
from jsonpath_ng import ext
from lib.kmip_post import kmip_post
import logging
import time
from lib.client_configuration import ClientConfiguration

logger = logging.getLogger("kms_decrypt")


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
        op = orjson.loads(BATCHED_OPERATION)
        op["value"][0]["value"] = operation['tag']
        op["value"][1]["value"] = operation["value"]
        ops.append(op)

    bulk_message = orjson.loads(BULK_MESSAGE)
    ITEMS_PATH.find(bulk_message)[0].value['value'] = ops
    return bulk_message


def parse_bulk_responses(response: requests.Response) -> List[BulkResult]:
    response_json = response.json()
    res = [BulkResult(RESPONSE_OPERATION.find(item)[0].value['value'],
                      RESPONSE_PAYLOAD_PATH.find(item)[0].value['value'])
           for item in ITEMS_PATH.find(response_json)[0].value['value']]
    return res


# The threshold number of operations for multithreading
MULTI_THREAD_THRESHOLD = 100
# The default number of threads to use
DEFAULT_NUM_THREADS = 5


def post_operations(
        conf: ClientConfiguration,
        operations: List[dict],
        batch_id: int,
        num_threads=DEFAULT_NUM_THREADS,
        threshold=MULTI_THREAD_THRESHOLD) -> List[BulkResult]:
    """
    Post a list of operations to the KMS
    Args:
        conf: the ClientConfiguration to use
        operations: the operations to post
        batch_id: the batch ID (for logging purposes)
        num_threads: the number of threads to use. Defaults to NUM_THREADS
        threshold: the threshold number of operations for multithreading. Default to MULTI_THREAD_THRESHOLD

    Returns:
        List[BulkResult]: the results of the operations
    """
    num_operations = len(operations)
    # do not multithread for less than threshold operations
    if num_operations < threshold:
        return post_operations_chunk(conf, batch_id, operations)
    # Split the operations into chunks
    k, m = divmod(len(operations), num_threads)
    chunks = [operations[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_threads)]
    # Post the operations in parallel
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(partial(post_operations_chunk, batch_id), chunks))

    # returning the flat list of results
    res = [item for sublist in results for item in sublist]
    return res


def post_operations_chunk(conf: ClientConfiguration, batch_id: int, chunk: List[dict]) -> List[BulkResult]:
    t_start = time.perf_counter()
    req = create_bulk_message(chunk)
    t_create_bulk_message = time.perf_counter() - t_start

    t_start = time.perf_counter()
    response = kmip_post(conf, orjson.dumps(req))
    t_kmip_post = time.perf_counter() - t_start

    t_start = time.perf_counter()
    results = parse_bulk_responses(response)
    t_parse_bulk_responses = time.perf_counter() - t_start

    logger.debug(
        "post operations chunk",
        extra={
            "id": batch_id,
            "size": len(chunk),
            "request": t_create_bulk_message,
            "post": t_kmip_post,
            "response": t_parse_bulk_responses,
        }
    )
    return results
