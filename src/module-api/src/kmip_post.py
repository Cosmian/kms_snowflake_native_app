import json
import requests
from client_configuration import ClientConfiguration
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

    # In the snowflake environment, we have to have "Connection": close" in the headers,
    # or we exhaust some resource and get 
    # "Failed to establish a new connection: [Errno 99] Cannot assign requested address"
    # This is bad as it forces re-establishing the SSL connection for each request and slows 
    # the process dowm significantly. 
    kms_server_url = configuration.kms_server_url + "/kmip/2_1"
    headers = {
        "Content-Type": "application/json",
        "Connection": "close",
    }

    if configuration.kms_access_token is not None:
        headers["Authorization"] = "Bearer " + configuration.kms_access_token

    with requests.Session() as session:
        res = session.post(
            kms_server_url,
            headers=headers,
            data=json.dumps(operation),
            timeout=(120, 120),
            stream=True
        )

        if res.status_code != 200:
            logger.error(f"Error {res.status_code} in KMIP POST {res.text}")
            raise Exception(f"Error {res.status_code} in KMIP POST {res.text}")

        return res.json()
