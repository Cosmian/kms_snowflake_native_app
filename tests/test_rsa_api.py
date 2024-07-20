from typing import List

__author__ = "Bruno Grieder"
__copyright__ = "Bruno Grieder"
__license__ = "MIT"

from kms_encrypt_python.bulk import post_operations

from kms_encrypt_python.create_key_pair import create_rsa_key_pair
from kms_encrypt_python.rsa_decrypt import decrypt_with_rsa, create_rsa_decrypt_request, parse_decrypt_response_payload
from kms_encrypt_python.rsa_encrypt import encrypt_with_rsa, create_rsa_encrypt_request, parse_encrypt_response_payload


def _test_single():
    # Crate an RSA keypair
    keypair = create_rsa_key_pair(size=4096, tags=["tag1", "tag2"])
    print("RSA keypair, sk: " + keypair.sk + ", pk: " + keypair.pk)

    # Encrypt and decrypt a message
    message = "Hello, World!".encode("utf-8")
    ciphertext = encrypt_with_rsa(key_id=keypair.pk, cleartext=message)
    cleartext = decrypt_with_rsa(key_id=keypair.sk, ciphertext=ciphertext)

    # Check if the decrypted message is the same as the original message
    assert cleartext == message
    print("Single RSA Message encrypted and decrypted successfully")


def _test_bulk():
    keypair = create_rsa_key_pair(size=4096, tags=["tag1", "tag2"])
    print("RSA keypair, sk: " + keypair.sk + ", pk: " + keypair.pk)
    messages = ["hello", "world"]

    encryptions = []
    for message in messages:
        enc = create_rsa_encrypt_request(key_id=keypair.pk, data=message.encode('utf-8'))
        encryptions.append(enc)
    bulk = post_operations(encryptions)

    decryptions = []
    for result in bulk:
        assert result.operation == 'Encrypt'
        ciphertext = parse_encrypt_response_payload(result.to_dict())
        dec = create_rsa_decrypt_request(key_id=keypair.sk, ciphertext=ciphertext)
        decryptions.append(dec)
    bulk = post_operations(decryptions)

    cleartexts: List[str] = []
    for result in bulk:
        assert result.operation == 'Decrypt'
        cleartext = parse_decrypt_response_payload(result.to_dict())
        cleartexts.append(cleartext.decode('utf-8'))

    assert cleartexts == messages
    print("Bulk messages encrypted and decrypted successfully")


def test_main():
    print("Running this program will verify that the KMS can create a RSA key, encrypt and decrypt a message.")
    print("It uses the configuration file in ~/.cosmian/kms.json")
    print()
    _test_single()
    _test_bulk()
