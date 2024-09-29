from dataclasses import dataclass
from typing import List
from leb128 import u
import io

class KmipError(Exception):
    pass

class ErrorReason:
    ILLEGAL_OBJECT_TYPE = "Illegal_Object_Type"

@dataclass
class BulkData:
    data: List[bytearray]

    @staticmethod
    def is_serialized_bulk_data(serialized: bytearray) -> bool:
        return len(serialized) > 2 and serialized[0] == 0x87 and serialized[1] == 0x87

    def serialize(self) -> bytearray:
        result = bytearray()
        result.extend([0x87, 0x87])
        # Write the length of the data using leb128 encoding
        result.extend(u.encode(len(self.data)))
        for item in self.data:
            # Length-prefixed data
            # result.extend(struct.pack('>I', len(item)))
            result.extend(u.encode(len(item)))
            result.extend(item)
        return result

    @classmethod
    def deserialize(cls, serialized: bytearray) -> 'BulkData':
        if not cls.is_serialized_bulk_data(serialized):
            raise KmipError(ErrorReason.ILLEGAL_OBJECT_TYPE)
        data = io.BytesIO(serialized[2:])
                          
        length, _num_bytes = u.decode_reader(data)        
        result = []
        for _ in range(length):
            item_length, _num_bytes = u.decode_reader(data)
            item =  bytearray(data.read(item_length))
            result.append(item)
        return cls(result)

