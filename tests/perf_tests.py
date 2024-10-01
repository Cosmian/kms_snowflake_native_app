import pandas as pd
import random
import logging

from cosmian_kms import encrypt_aes, decrypt_aes

logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def test_performance():
    plaintext_size = 64
    batch_size = 5000000
    slog.info(f"Testing performance with batch size {batch_size}")
    key_id = '0d319307-f766-4869-b90a-02096edb9431'

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes(data_frame, logger)
    # do some verifications
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
