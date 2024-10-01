import json
import requests
from lib.client_configuration import ClientConfiguration
import logging

logger = logging.getLogger("kms_decrypt")


def kmip_post(
        configuration: ClientConfiguration,
        operation: dict) -> dict:
    """
    Post a KMIP request to a KMIP server

    Returns:
      dict: KMIP response
    """

    # if "kms_server_url" in conf:
    kms_server_url = configuration.kms_server_url + "/kmip/2_1"
    # else:
    #    raise Exception("kms_server_url not found in configuration file " + conf)

    headers = {
        "Content-Type": "application/json",
    }

    if configuration.kms_access_token is not None:
        headers["Authorization"] = "Bearer " + configuration.kms_access_token

    res = requests.post(kms_server_url, headers=headers, data=json.dumps(operation), timeout=60)

    if res.status_code != 200:
        logger.error(f"Error {res.status_code} in KMIP POST {res.text}")
        raise Exception(f"Error {res.status_code} in KMIP POST {res.text}")

    return res.json()
