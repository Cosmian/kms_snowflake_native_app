import json
import requests
from client_configuration import ClientConfiguration

from initialize import logger


def kmip_post(
        configuration: ClientConfiguration,
        session: requests.Session,
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
    # the process down significantly. 
    # see this for user facing the same issue:
    # https://snowflake.discourse.group/t/i-have-a-stored-procedure-that-utilizes-a-network-access-rules-to-make-external-calls-that-was-working-flawlessly-for-months-and-without-any-change-in-the-code-im-getting-oserror-errno-99-cannot-assign-requested-address-why/4642
    kms_server_url = configuration.kms_server_url + "/kmip/2_1"
    # headers = {
    #     "Content-Type": "application/json",
    #     "Connection": "close",
    # }
    headers = {}

    if configuration.kms_access_token is not None:
        headers["Authorization"] = "Bearer " + configuration.kms_access_token

    res = session.post(
        kms_server_url,
        headers=headers,
        json=operation,
        timeout=(120, 120),
        stream=True,
    )

    if res.status_code != 200:
        logger.error(f"Error {res.status_code} in KMIP POST {res.text}")
        raise Exception(f"Error {res.status_code} in KMIP POST {res.text}")

    return res.json()
