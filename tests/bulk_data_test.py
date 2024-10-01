from lib.bulk_data import BulkData
import logging
import time

logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "id": "",
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def test_bulk_data():
    data = [
        bytearray([0x01, 0x02, 0x03]),
        bytearray([0x04, 0x05, 0x06]),
        bytearray([0x07] * 10)
    ]
    bulk_data = BulkData(data)
    serialized = bulk_data.serialize()
    assert list(serialized) == [
        0x87, 0x87, 0x03, 0x03, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
    ]
    deserialized = BulkData.deserialize(serialized)
    assert data == deserialized.data


def benchmark_bulk_data(bulk_data):
    t_start = time.perf_counter()
    serialized = bulk_data.serialize()
    t_serialize = time.perf_counter() - t_start
    slog.info(f"Serialize: {t_serialize}s")

    t_start = time.perf_counter()
    _deserialized = BulkData.deserialize(serialized)
    t_deserialize = time.perf_counter() - t_start
    slog.info(f"deserialize: {t_deserialize}s")


def test_bulk_data_benchmark():
    num_samples = 5000000
    slog.info(f"Testing performance with bulk data of { num_samples } samples")
    t_start = time.perf_counter()
    data = [
        bytearray([0x01] * 64) * num_samples
    ]
    bulk_data = BulkData(data)
    t_generate = time.perf_counter() - t_start
    slog.info(f"Generate: {t_generate}s")

    t_start = time.perf_counter()
    benchmark_bulk_data(bulk_data)
    t_all = time.perf_counter() - t_start
    slog.info(f"serialize+deserialize: {t_all}s, i.e. {t_all / num_samples * 1000000:.6f}µs per item")
