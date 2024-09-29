import pandas as pd
import random
import string
import logging

from cosmian_kms import encrypt_aes, decrypt_aes, snowflake_logger

# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def test_performance():
    """
    Test the performance of the encrypting and decrypting UDF
    The perf stats will be written to the log
    """
    key_id = '0d319307-f766-4869-b90a-02096edb9431'
    batch_size = 100000
    snowflake_logger.info(f"Testing performance with batch size {batch_size}")

    # Generate a random batch of data
    keys: list[str] = []
    for i in range(batch_size):
        keys.append(key_id)
    cleartexts: list[str] = []
    for i in range(batch_size):
        cleartexts.append(generate_random_string(64))
    data_frame = pd.DataFrame({0: keys, 1: cleartexts})

    # Encrypt the data
    encryptions = encrypt_aes(data_frame,logger)
    
    # decrypt the data
    data_frame = pd.DataFrame({0:keys, 1:encryptions.values})
    decryptions = decrypt_aes(data_frame,logger)
    
    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert cleartexts[i] == decryptions[i]
        

if __name__ == '__main__':
    test_performance()