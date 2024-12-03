import pandas as pd

from client_configuration import ClientConfiguration
from initialize import CONFIGURATION
from operations.common import Algorithm
from operations.encrypt import encrypt
from operations.decrypt import decrypt


# These are the UDFs exposed to snowflake. They are defined as vectorized UDFs.
# Using this form avoids the decorator syntax and importing the _snowflake module
# see https://docs.snowflake.com/en/developer-guide/udf/python/udf-python-batch#getting-started-with-vectorized-python-udfs

configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

def encrypt_aes_gcm(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM, configuration)


encrypt_aes_gcm._sf_vectorized_input = pd.DataFrame


def encrypt_aes_gcm_siv(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM_SIV, configuration)


encrypt_aes_gcm_siv._sf_vectorized_input = pd.DataFrame


def encrypt_aes_xts(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_XTS, configuration)


encrypt_aes_xts._sf_vectorized_input = pd.DataFrame


def encrypt_chacha20_poly1305(data: pd.DataFrame):
    return encrypt(data, Algorithm.CHACHA20_POLY1305, configuration)


encrypt_chacha20_poly1305._sf_vectorized_input = pd.DataFrame


def decrypt_aes_gcm(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM, configuration)


decrypt_aes_gcm._sf_vectorized_input = pd.DataFrame


# decrypt_aes_gcm._sf_max_batch_size = 5000000

def decrypt_aes_gcm_siv(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM_SIV, configuration)


decrypt_aes_gcm_siv._sf_vectorized_input = pd.DataFrame


def decrypt_aes_xts(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_XTS, configuration)


decrypt_aes_xts._sf_vectorized_input = pd.DataFrame


def decrypt_chacha20_poly1305(data: pd.DataFrame):
    return decrypt(data, Algorithm.CHACHA20_POLY1305, configuration)


decrypt_chacha20_poly1305._sf_vectorized_input = pd.DataFrame
