from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Encryption function
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

# Decryption function
def decrypt_data(key, enc_data):
    raw_data = base64.b64decode(enc_data)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# Example usage
key = get_random_bytes(16)  # AES key
data = "Sensitive customer data"
encrypted = encrypt_data(key, data)
decrypted = decrypt_data(key, encrypted)
def print(param):
    pass

print(f"Encrypted: {encrypted}")




print(f"Decrypted: {decrypted}")
