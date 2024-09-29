from lib.bulk_data import BulkData
import timeit


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
    serialized = bulk_data.serialize()
    _deserialized = BulkData.deserialize(serialized)
    # assert bulk_data == deserialized


def test_bulk_data_benchmark():
    data = [
        bytearray([0x01] * 64) * 100000
    ]
    bulk_data = BulkData(data)
    l = lambda : benchmark_bulk_data(bulk_data)
    time_taken = timeit.timeit(l, number=1000)
    print(f"Time taken for 1000 iterations: {time_taken:.6f} seconds")

