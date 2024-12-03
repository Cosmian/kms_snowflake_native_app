import logging
from collections import deque
import threading
from xxhash import xxh64

snowflake_logger = logging.getLogger("kms_decrypt")
logger = snowflake_logger
slog = logging.LoggerAdapter(snowflake_logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def key_hash(key: bytes | list[bytes]) -> int:
    """
    Compute the hash of the key

    This function computes the hash of the key using the xxh64 algorithm.
    The hash is computed as the digest of the concatenation of the bytes
    in the key if the key is a list of bytes, or as the digest of the
    key bytes if the key is a single bytes object.

    Args:
        key: the key to hash

    Returns:
        the hash of the key
    """
    h = xxh64()
    if isinstance(key, list):
        for k in key:
            h.update(k)
    else:
        h.update(key)
    return h.intdigest()

###
# The LRUCache is a least recently used cache. It is used to store the result of the
# encrypt and decrypt operations in the KMS proxy. The cache is implemented as a
# dictionary with a limited size (the capacity). The cache is protected by a lock
# to prevent concurrent access from multiple threads. The cache is cleared when
# the cache size reaches the capacity.
###    
class LRUCache:

    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = dict()
        # The access list is used to track the order of access of the cache
        # entries. The most recently accessed entry is at the end of the list        
        self.access = deque(maxlen=capacity)
        self.lock = threading.Lock()

    def get(self, key: bytes | list[bytes]) -> bytes | None:
        """
        Get the value associated with the key from the cache

        Args:
            key: the key to get the value for

        Returns:
            the value associated with the key if the key is in the cache
            None otherwise
        """
        key = key_hash(key)
        if key not in self.cache:
            # The key is not in the cache, return None
            return None
        else:
            # The key is in the cache, return the value associated with the key
            # The access list is used to track the order of access of the cache
            # entries. The most recently accessed entry is at the end of the list
            # When we get an entry, we remove it from the list and add it to
            # the end of the list
            with self.lock:
                if self.access[-1] != key:
                    # The key is not the most recently accessed, remove it from
                    # the list and add it to the end of the list
                    self.access.remove(key)
                    self.access.append(key)
                # Return the value associated with the key
                return self.cache[key]

    def put(self, key: bytes | list[bytes], value: bytes):
        """
        Put a key/value pair in the cache

        Args:
            key: the key to put in the cache
            value: the value to associate with the key

        Notes:
            When the cache reaches its capacity, the least recently used entry
            is removed from the cache
        """
        key = key_hash(key)
        with self.lock:
            # If the key is already in the cache, remove it from the access list
            if key in self.cache:
                self.access.remove(key)
            # If the cache is full, remove the least recently used entry
            elif len(self.cache) == self.capacity:
                oldest = self.access.popleft()
                del self.cache[oldest]
            # Put the key/value pair in the cache and add it to the end of the
            # access list
            self.cache[key] = value
            self.access.append(key)

    def print(self):
        """
        Print the content of the cache

        This method is useful for debugging purposes. It prints the content of
        the cache to the console. The cache is printed as a sequence of key/value
        pairs, with the most recently accessed entry last.
        """
        # Iterate over the access list in reverse order to get the most recently
        # accessed entry last
        for key in reversed(self.access):
            print(f"{key}: {self.cache[key]}")
