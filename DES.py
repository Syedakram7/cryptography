from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def pad(text):

    while len(text) % 8 != 0:
        text += ' '
    return text

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext)
    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))
    return ciphertext

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = cipher.decrypt(ciphertext).decode('utf-8').rstrip()
    return decrypted_text

def main():
    key = get_random_bytes(8)  
    plaintext = "Hello, DES!" 

    print(f"Key: {key.hex()}")
    print(f"Plaintext: {plaintext}")

    # Encryption
    ciphertext = des_encrypt(key, plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decryption
    decrypted_text = des_decrypt(key, ciphertext)
    print(f"Decrypted Text: {decrypted_text}")

if _name_ == "_main_":
    main()
