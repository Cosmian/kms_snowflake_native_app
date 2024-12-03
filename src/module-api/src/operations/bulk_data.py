from dataclasses import dataclass
from leb128 import u
import io


@dataclass
class BulkData:
    # BulkData List of byte arrays
    data: list[bytes]

    def __init__(self, data: list[bytes]):
        self.data = data

    @staticmethod
    def is_serialized_bulk_data(serialized: bytes) -> bool:
        """
        Check if the serialized byte array is a serialized BulkData

        A BulkData is serialized as a list of bytes with a header and a footer.
        The header is 0x87 followed by the number of items in the list.
        The footer is the number of items in the list and each item is a byte
        string followed by the length of the byte string.

        :param serialized: the serialized byte array
        :return: True if the byte array is a serialized BulkData, False otherwise
        """
        return len(serialized) > 2 and serialized[0] == 0x87 and serialized[1] == 0x87

    def serialize(self) -> bytes:
        """
        Serialize the BulkData to a byte array.

        A BulkData is serialized as a list of bytes with a header and a footer.
        The header is 0x87 followed by the number of items in the list.
        The footer is the number of items in the list and each item is a byte
        string followed by the length of the byte string.

        :return: the serialized byte array
        """
        result = io.BytesIO()
        # Write the header  
        result.write(bytes([0x87, 0x87]))
        # Write the number of items using leb128 encoding        
        result.write(u.encode(len(self.data)))
        # Gather all encoded items
        encoded_items = [u.encode(len(item)) + item for item in self.data]
        # Write all items at once
        result.write(b''.join(encoded_items))
        return result.getvalue()

    @classmethod
    def deserialize(cls, serialized: bytes) -> 'BulkData':
        """
        Deserialize a serialized BulkData to a BulkData object

        The serialized byte array is expected to be a list of bytes with a header and a footer.
        The header is 0x87 followed by the number of items in the list.
        The footer is the number of items in the list, and each item is a byte
        string followed by the length of the byte string.

        :param serialized: the serialized byte arrays
        :return: the deserialized BulkData object
        """
        data = io.BytesIO(serialized)
        # read the first two bytes 0x87
        header = data.read(2)
        # assert the first two bytes are 0x87
        assert header == bytes([0x87, 0x87])
        # read the number of items
        num_items, _num_bytes = u.decode_reader(data)
        # Preallocate the list for the result
        result: list[bytes] = [b'' for _ in range(num_items)]
        for i in  range(num_items):
            item_length, _ = u.decode_reader(data)
            b = data.read(item_length)
            assert len(b) == item_length, f"Item {i} has length {len(b)}, Expected {item_length} bytes"
            result[i] = b
        return cls(result)
