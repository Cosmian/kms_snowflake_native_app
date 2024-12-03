import unittest
from lru_cache import LRUCache, key_hash


class TestLRUCacheGet(unittest.TestCase):
    def setUp(self):
        self.cache = LRUCache(10)  # Create an instance of the cache with a capacity of 10

    def test_get_none(self):
        self.assertIsNone(self.cache.get(b'nonexistent_key'))

    def test_get_value(self):
        self.cache.put(b'key', b'value')
        self.assertEqual(self.cache.get(b'key'), b'value')

    def test_get_updates_access_list(self):
        self.cache.put(b'key1', b'value1')
        self.cache.put(b'key2', b'value2')
        self.cache.get(b'key1')
        self.assertEqual(self.cache.access[-1], key_hash(b'key1'))

    def test_get_list_key(self):
        self.cache.put([b'key1', b'key2'], b'value')
        self.assertEqual(self.cache.get([b'key1', b'key2']), b'value')

    def test_get_bytes_key(self):
        self.cache.put(b'key', b'value')
        self.assertEqual(self.cache.get(b'key'), b'value')

    def test_lru_cache_eviction(self):
        cache = LRUCache(3)
        cache.put(b"key1", b'1')
        cache.put(b"key2", b'2')
        cache.put(b"key3", b'3')
        cache.put(b"key4", b'4')
        self.assertEqual(cache.get(b"key1"), None)
        self.assertEqual(cache.get(b"key2"), b'2')
        self.assertEqual(cache.get(b"key3"), b'3')
        self.assertEqual(cache.get(b"key4"), b'4')

    def test_lru_cache_array(self):
        cache = LRUCache(3)
        cache.put([b"key1", b"key2", b"key3"], b'1')
        self.assertEqual(cache.get([b"key1", b"key2", b"key3"]), b'1')
        cache.put([b"key1", b"key2"], b'2')
        assert cache.get([b"key1", b"key2"]) == b'2'
        assert cache.get([b"key1", b"key2", b"key3"]) == b'1'
        assert cache.get([b"key2", b"key3"]) is None


if __name__ == '__main__':
    unittest.main()
