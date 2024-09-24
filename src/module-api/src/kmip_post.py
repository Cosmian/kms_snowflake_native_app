import json
import requests
import time
import logging

logger = logging.getLogger("kms_decrypt")

def read_kms_configuration(conf: str = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}'):
    """
    Read  the KMS configuration

    Returns:
      dict: KMS configuration
    """
    # Define the file path
    # file_path = os.path.expanduser(conf_path)
    # Open the file and load the JSON
    # with open(file_path, 'r') as f:
    data = json.loads(conf)
    return data


def kmip_post(json_str: str, id : int, dim : int, conf: str = '{"kms_server_url": "https://snowflake-kms.cosmian.dev/indosuez"}') -> requests.Response:
    """
    Post a KMIP request to a KMIP server

    Returns:
      dict: KMIP response
    """
    conf = read_kms_configuration(conf)

    # if "kms_server_url" in conf:
    kms_server_url = conf["kms_server_url"] + "/kmip/2_1"
    # else:
    #    raise Exception("kms_server_url not found in configuration file " + conf)

    headers = {
        "Content-Type": "application/json",
    }

    if "kms_access_token" in conf:
        headers["Authorization"] = "Bearer " + conf["kms_access_token"]
    start_post = time.perf_counter()
    res = requests.post(kms_server_url, headers=headers, data=json_str)
    end_post = time.perf_counter()
    logger.debug("post",
                  extra ={"id batch" : id,
                    "order" : 3,
                    "#processed_data" :
                        dim,
                    "time_for_single_exec" :
                        (end_post
                            - start_post) / dim,
                    "effective_time" : end_post -
                        start_post,
                    "size snowflake batch" : dim})
    return res
