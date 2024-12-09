import numpy as np
import numpy.testing as npt
import logging
import time
import random
import unittest
from bulk_data import BulkData
from initialize import slog


def benchmark_bulk_data(bulk_data) -> BulkData:
    t_start = time.perf_counter()
    serialized = bulk_data.serialize()
    t_serialize = time.perf_counter() - t_start
    slog.info(f"Serialize: {t_serialize}s")

    t_start = time.perf_counter()
    deserialized = BulkData.deserialize(serialized)
    t_deserialize = time.perf_counter() - t_start
    slog.info(f"deserialize: {t_deserialize}s")
    return deserialized


def random_bytes() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(64))


class TestBulkDataDeserialize(unittest.TestCase):
    def test_valid_serialization_one_item(self):
        serialized = b'\x87\x87\x01\x03abc'
        expected = BulkData([b'abc'])
        self.assertEqual(BulkData.deserialize(serialized), expected)

    def test_valid_serialization_multiple_items(self):
        serialized = b'\x87\x87\x02\x03abc\x03def'
        expected = BulkData([b'abc', b'def'])
        self.assertEqual(BulkData.deserialize(serialized), expected)

    def test_invalid_serialization_incorrect_header(self):
        serialized = b'\x88\x87\x01\x03abc'
        with self.assertRaises(AssertionError):
            BulkData.deserialize(serialized)

    def test_invalid_serialization_incorrect_item_length(self):
        serialized = b'\x87\x87\x01\x04abc'
        with self.assertRaises(AssertionError):
            BulkData.deserialize(serialized)

    def test_invalid_serialization_truncated_data(self):
        serialized = b'\x87\x87\x01\x03ab'
        with self.assertRaises(AssertionError):
            BulkData.deserialize(serialized)

    def test_invalid_serialization_empty_data(self):
        serialized = b''
        with self.assertRaises(AssertionError):
            BulkData.deserialize(serialized)

    def test_bulk_data_test_vector(self):
        data = np.array([
            bytes([0x01, 0x02, 0x03]),
            bytes([0x04, 0x05, 0x06]),
            bytes([0x07] * 10)
        ])
        bulk_data = BulkData(data.tolist())
        serialized = bulk_data.serialize()
        assert list(serialized) == [
            0x87, 0x87, 0x03, 0x03, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x07, 0x07,
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
        ]
        deserialized = BulkData.deserialize(serialized)
        npt.assert_array_equal(data, deserialized.data)

    def test_bulk_data_benchmark(self):
        num_samples = 1000000
        slog.info(f"Testing performance with bulk data of {num_samples} samples")
        t_start = time.perf_counter()
        data = np.array([
            random.randbytes(64) for _ in range(num_samples)
        ], dtype=np.object_)
        # check all samples have 64 bytes
        for item in data:
            assert len(item) == 64
        bulk_data = BulkData(data.tolist())
        t_generate = time.perf_counter() - t_start
        slog.info(f"Generate: {t_generate}s")
        # serialize+deserialize
        t_start = time.perf_counter()
        recovered = benchmark_bulk_data(bulk_data)
        t_all = time.perf_counter() - t_start
        slog.info(f"serialize+deserialize: {t_all}s, i.e. {t_all / num_samples * 1000000:.6f}µs per item")
        self.assertEqual(len(bulk_data.data), len(recovered.data))
        # sample 100 random data from both arrays and check they are equal
        for _ in range(100):
            i = random.randint(0, len(bulk_data.data) - 1)
            assert np.array_equal(bulk_data.data[i], recovered.data[i])


if __name__ == '__main__':
    unittest.main()
