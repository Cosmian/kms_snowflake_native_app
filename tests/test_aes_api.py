import random
import string
import time
from typing import List

__author__ = "Bruno Grieder"
__copyright__ = "Bruno Grieder"
__license__ = "MIT"

from kms_encrypt_python.bulk import post_operations

from kms_encrypt_python.create_aes_key import create_aes_key
from kms_encrypt_python.aes_gcm_decrypt import decrypt_with_aes_gcm, create_aes_gcm_decrypt_request, \
    parse_decrypt_response_payload
from kms_encrypt_python.aes_gcm_encrypt import encrypt_with_aes_gcm, create_aes_gcm_encrypt_request, \
    parse_encrypt_response_payload


def _test_single():
    # Crate an AES key
    key_id = create_aes_key(size=256, tags=["tag1", "tag2"])
    print("The AES GCM key is: " + key_id)

    # Encrypt and decrypt a message
    message = "Hello, World!".encode("utf-8")
    ciphertext = encrypt_with_aes_gcm(key_id=key_id, cleartext=message)
    cleartext = decrypt_with_aes_gcm(key_id=key_id, ciphertext=ciphertext)

    # Check if the decrypted message is the same as the original message
    assert cleartext == message
    print("Single AES GCM Message encrypted and decrypted successfully")


def _generate_random_string(length=100):
    """Generate a random string of fixed length."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


def _test_bulk():
    # The number of messages
    num_messages = 5012
    num_threads = 5
    print(f"AES GCM Encrypting and decrypting {num_messages} messages over {num_threads} threads")

    # Crate an AES key
    key_id = create_aes_key(size=256, tags=["tag1", "tag2"])
    print("The AES GCM key is: " + key_id)

    # Encrypt a set of messages
    messages = [_generate_random_string(10) for _ in range(num_messages)]
    start_time = time.perf_counter()
    encryptions = []
    for message in messages:
        enc = create_aes_gcm_encrypt_request(key_id=key_id, data=message.encode('utf-8'))
        encryptions.append(enc)
    bulk = post_operations(encryptions, num_threads=num_threads)
    end_time = time.perf_counter()
    print(
        f"Average time taken to encrypt a message: {round((end_time - start_time) * 1000 / num_messages, 3)} milliseconds"
    )

    # Decrypt the messages
    ciphertexts = [parse_encrypt_response_payload(result.to_dict()) for result in bulk]
    start_time = time.perf_counter()
    decryptions = []
    for ciphertext in ciphertexts:
        dec = create_aes_gcm_decrypt_request(key_id=key_id, ciphertext=ciphertext)
        decryptions.append(dec)
    bulk = post_operations(decryptions)
    end_time = time.perf_counter()
    print(
        f"Average time taken to decrypt a message: {round((end_time - start_time) * 1000 / num_messages, 3)} milliseconds"
    )

    # Check if the decrypted messages are the same as the original messages
    cleartexts: List[str] = []
    for result in bulk:
        assert result.operation == 'Decrypt'
        cleartext = parse_decrypt_response_payload(result.to_dict())
        cleartexts.append(cleartext.decode('utf-8'))
    assert cleartexts == messages
    print("Bulk AES GCM messages encrypted and decrypted successfully")


def test_main():
    print()
    print("Running this program will verify that the KMS can create a AES key, encrypt and decrypt a message with AES "
          "GCM.")
    print("It uses the configuration file in ~/.cosmian/kms.json")
    print()
    _test_single()
    _test_bulk()
