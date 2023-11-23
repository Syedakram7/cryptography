from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def cbc_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    plaintext_padded = padder.update(plaintext) + padder.finalize()

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    return plaintext

# Example usage:
key = os.urandom(16)  # 128-bit key
iv = os.urandom(16)   # Initialization Vector (IV)

plaintext = b'This is a secret message.'

# Encryption
ciphertext = cbc_encrypt(plaintext, key, iv)
print(f'Encrypted Text: {ciphertext.hex()}')

# Decryption
decrypted_text = cbc_decrypt(ciphertext, key, iv)
print(f'Decrypted Text: {decrypted_text.decode("utf-8")}')
