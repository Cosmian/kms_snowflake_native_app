import pandas as pd
import random
import string
import logging

from cosmian_kms import encrypt_aes, decrypt_aes

logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "id": "",
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def generate_random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def generate_random_bytearray(length) -> bytearray:
    return bytearray(random.getrandbits(8) for _ in range(length))


def test_performance():
    key_id = '0d319307-f766-4869-b90a-02096edb9431'
    batch_size = 5000000
    slog.info(f"Testing performance with batch size {batch_size}")

    # Generate a random batch of data
    keys: list[str] = []
    for i in range(batch_size):
        keys.append(key_id)
    plaintexts: list[bytearray] = []
    for i in range(batch_size):
        plaintexts.append(generate_random_bytearray(64))
    data_frame = pd.DataFrame({0: keys, 1: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes(data_frame, logger)
    assert len(encryptions) == batch_size
    for v in encryptions.values:
        assert len(v) == 64 + 12 + 16

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: encryptions.values})
    decryptions = decrypt_aes(data_frame, logger)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == decryptions[i]


if __name__ == '__main__':
    test_performance()
