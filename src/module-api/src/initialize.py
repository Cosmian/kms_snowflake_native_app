# TODO: These values need to be de-hardcoded via configuration
import logging

from lru_cache import LRUCache

# CONFIGURATION = '{"kms_server_url": "http://localhost:9998"}'
CONFIGURATION = '{"kms_server_url": "https://kms-snowflake-test.cosmian.dev"}'
# CONFIGURATION = '{"kms_server_url": "https://kms.ca-indosuez.com"}'

# snowflake Dataframes have no more than 4096 rows so multi-threading is never used.
# The multi-threading code id left here in case snowflake adds support for larger dataframes.
# The heuristic is that the number of threads should be about 5 times the number of available cores
NUM_THREADS = 40
THRESHOLD = 100000

# Cache for the encrypt and decrypt operations when using AES GCM SIV
LRU_CACHE_SIZE = 100
LRU_CACHE_ENCRYPT = LRUCache(LRU_CACHE_SIZE)
LRU_CACHE_DECRYPT = LRUCache(LRU_CACHE_SIZE)

# Initialize the logger
logger = logging.getLogger("cosmian_kms")
slog = logging.LoggerAdapter(
    logger,
    {
        "thread_id": -1,
    },
)


def set_configuration(conf: str):
    global CONFIGURATION
    CONFIGURATION = conf
