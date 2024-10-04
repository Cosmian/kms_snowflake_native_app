import pandas as pd
import random
import logging

from cosmian_kms import encrypt_aes, decrypt_aes, DecryptAES

# 
logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def test_performance_udf():
    plaintext_size = 64
    batch_size = 400000
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
    encryptions = encrypt_aes(data_frame)
    # do some verifications
    assert len(encryptions) == batch_size
    for v in encryptions.values:
        assert len(v) == 64 + 12 + 16

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: encryptions.values})
    decryptions = decrypt_aes(data_frame)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == decryptions[i]

def test_performance_udf_t():
    plaintext_size = 64
    batch_size = 1000000
    slog.info(f"Testing performance with batch size {batch_size}")
    key_id = '0d319307-f766-4869-b90a-02096edb9431'

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    data_frame = pd.DataFrame({0: keys, 1: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions_1 = encrypt_aes(data_frame)
    encryptions_2 = encryptions_1.copy()

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: encryptions_1.values, 2:encryptions_2.values})
    decrypter = DecryptAES()
    decryptions = decrypter.end_partition(data_frame)
    
    # print(decryptions)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == decryptions[0][i]
        assert plaintexts[i] == decryptions[1][i]


if __name__ == '__main__':
    test_performance_udf()
