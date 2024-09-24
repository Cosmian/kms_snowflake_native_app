import orjson
from concurrent.futures import ThreadPoolExecutor
from typing import List
import requests
from jsonpath_ng import ext
from kmip_post import kmip_post
import logging
import time
from functools import partial

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


def parse_bulk_responses(response: requests.Response, id : int, dim : int) -> List[BulkResult]:
    start_response_json = time.perf_counter()
    response_json = response.json()
    end_response_json = time.perf_counter()
    logger.debug("response.json()",
                  extra ={"id batch" : id,
                    "order" : 5,
                    "#processed_data" :
                        dim,
                    "time_for_single_exec" :
                        (end_response_json
                            - start_response_json) / dim,
                    "effective_time" : end_response_json -
                        start_response_json,
                    "size snowflake batch" : dim})

    start_loop_bulk_result = time.perf_counter()
    res = [BulkResult(RESPONSE_OPERATION.find(item)[0].value['value'],
                       RESPONSE_PAYLOAD_PATH.find(item)[0].value['value'])
                            for item in ITEMS_PATH.find(response_json)[0].value['value']]
    end_loop_bulk_result = time.perf_counter()
    logger.debug("loop parse_bulk_responses",
                  extra ={"id batch" : id,
                    "order" : 6,
                    "#processed_data" :
                        dim,
                    "time_for_single_exec" :
                        (end_loop_bulk_result
                            - start_loop_bulk_result) / dim,
                    "effective_time" : end_loop_bulk_result -
                        start_loop_bulk_result,
                    "size snowflake batch" : dim})
    return res


# The threshold number of operations for multithreading
MULTI_THREAD_THRESHOLD = 100
# The default number of threads to use
NUM_THREADS = 5


def post_operations(operations: List[dict], id : int, num_threads=NUM_THREADS, threshold=MULTI_THREAD_THRESHOLD,
                    conf_path: str = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}') -> List[BulkResult]:
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
        return post_operations_chunk(id, operations, conf_path)
    # Split the operations into chunks
    k, m = divmod(len(operations), num_threads)
    chunks = [operations[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(num_threads)]
    # Post the operations in parallel
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(partial(post_operations_chunk, id), chunks))

    # returning the flat list of results
    res = [item for sublist in results for item in sublist]
    return res


def post_operations_chunk(id:int, chunk: List[dict], conf_path: str = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}') -> List[BulkResult]:
    start_create_bulk_message = time.perf_counter()
    req = create_bulk_message(chunk)
    end_create_bulk_message = time.perf_counter()
    logger.debug("create_bulk_message",
                  extra ={"id batch" : id,
                    "order" : 2,
                    "#processed_data" :
                        len(chunk),
                    "time_for_single_exec" :
                        (end_create_bulk_message
                            - start_create_bulk_message) / len(chunk),
                    "effective_time" : end_create_bulk_message -
                        start_create_bulk_message,
                    "size snowflake batch" : len(chunk)})

    start_kmip_post = time.perf_counter()
    response = kmip_post(orjson.dumps(req), id, len(chunk), conf_path)
    end_kmip_post = time.perf_counter()
    logger.debug("kmip_post",
                  extra ={"id batch" : id,
                    "order" : 4,
                    "#processed_data" :
                        len(chunk),
                    "time_for_single_exec" :
                        (end_kmip_post
                            - start_kmip_post) / len(chunk),
                    "effective_time" : end_kmip_post -
                        start_kmip_post,
                    "size snowflake batch" : len(chunk)})

    start_parse_bulk_responses = time.perf_counter()
    results = parse_bulk_responses(response, id, len(chunk))
    end_parse_bulk_responses = time.perf_counter()
    logger.debug("parse_bulk_responses",
                  extra ={"id batch" : id,
                    "order" : 7,
                    "#processed_data" :
                        len(chunk),
                    "time_for_single_exec" :
                        (end_parse_bulk_responses
                            - start_parse_bulk_responses) / len(chunk),
                    "effective_time" : end_parse_bulk_responses -
                        start_parse_bulk_responses,
                    "size snowflake batch" : len(chunk)})

    return results
