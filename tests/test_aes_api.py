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


def _test_bulk():
    # Crate an AES key
    key_id = create_aes_key(size=256, tags=["tag1", "tag2"])
    print("The AES GCM key is: " + key_id)

    messages = ["hello", "world"]
    encryptions = []
    for message in messages:
        enc = create_aes_gcm_encrypt_request(key_id=key_id, data=message.encode('utf-8'))
        encryptions.append(enc)
    bulk = post_operations(encryptions)

    decryptions = []
    for result in bulk:
        assert result.operation == 'Encrypt'
        ciphertext = parse_encrypt_response_payload(result.to_dict())
        dec = create_aes_gcm_decrypt_request(key_id=key_id, ciphertext=ciphertext)
        decryptions.append(dec)
    bulk = post_operations(decryptions)

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
