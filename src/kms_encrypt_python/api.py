"""
This is the main entry point for the KMS Encrypt Python package
that demonstrates how to create an RSA key pair, encrypt and decrypt a message
"""

import logging
from typing import List

from create_key_pair import create_rsa_key_pair
from kms_encrypt_python.rsa_decrypt import decrypt_with_rsa
from kms_encrypt_python.rsa_encrypt import encrypt_with_rsa

__author__ = "Bruno Grieder"
__copyright__ = "Bruno Grieder"
__license__ = "MIT"

_logger = logging.getLogger(__name__)


