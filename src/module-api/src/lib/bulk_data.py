from dataclasses import dataclass
from typing import List
from leb128 import u
import io


@dataclass
class BulkData:
    data: List[bytes]

    def __init__(self, data: List[bytes]):
        self.data = data

    @staticmethod
    def is_serialized_bulk_data(serialized: bytes) -> bool:
        return len(serialized) > 2 and serialized[0] == 0x87 and serialized[1] == 0x87

    def serialize(self) -> bytes:
        # result = bytearray()
        # # Write the header
        # result.extend([0x87, 0x87])
        # # Write the number of items using leb128 encoding
        # result.extend(u.encode(len(self.data)))
        # for item in self.data:
        #     result.extend(u.encode(len(item)))
        #     result.extend(item)
        # return result
        result = io.BytesIO()
        # Write the header  
        result.write(bytes([0x87, 0x87]))
        # Write the number of items using leb128 encoding        
        result.write(u.encode(len(self.data)))
        for item in self.data:
            result.write(u.encode(len(item)))
            result.write(item)
        return result.getvalue()

    @classmethod
    def deserialize(cls, serialized: bytes) -> 'BulkData':
        data = io.BytesIO(serialized)
        # read the first two bytes 0x87
        _header = data.read(2)
        # read the number of items
        num_items, _num_bytes = u.decode_reader(data)
        result = []
        for _ in range(num_items):
            item_length, _num_bytes = u.decode_reader(data)
            item = bytes(data.read(item_length))
            result.append(item)
        return cls(result)
