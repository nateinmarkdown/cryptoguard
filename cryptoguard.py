import argparse
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


backend = default_backend()


def encrypt_file(key, filename):
    # Check that key is the correct length for AES
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")

    # Generate a random initializing vector (IV)
    iv = os.urandom(16)

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).encryptor()

    # Read the contents of the file to be encrypted
    with open(filename, "rb") as f:
        plaintext = f.read()

    # Pad the plaintext to a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the encrypted data to a file
    with open(filename + ".encrypted", "wb") as f:
        f.write(iv + ciphertext)


def decrypt_file(key, filename):
    # Check that key is the correct length for AES
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")

    # Read the IV and ciphertext from the encrypted file
    with open(filename, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).decryptor()

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the plaintext
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    # Write the decrypted data to a file
    with open(filename[:-10], "wb") as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file using AES CBC mode.')
    parser.add_argument('command', choices=['encrypt', 'decrypt'], help='Whether to encrypt or decrypt the file.')
    parser.add_argument('key', help='The encryption key.')
    parser.add_argument('filename', help='The name of the file to encrypt or decrypt.')
    args = parser.parse_args()

    key = args.key.encode("utf-8")

    if args.command == "encrypt":
        encrypt_file(key, args.filename)
    elif args.command == "decrypt":
        decrypt_file(key, args.filename)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error:", e)
