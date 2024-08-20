import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256 as CryptoSHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(ciphertext, key):
    data = b64decode(ciphertext)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# RSA Encryption
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return b64encode(cipher.encrypt(plaintext.encode())).decode()

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(b64decode(ciphertext)).decode()

# SHA-256 Hashing
def hash_sha256(data):
    hasher = SHA256.new()
    hasher.update(data.encode())
    return hasher.hexdigest()

# Example Usage
if __name__ == "__main__":
    # AES Example
    aes_key = get_random_bytes(16)  # AES-128 key
    aes_plaintext = "This is a secret message"
    aes_ciphertext = aes_encrypt(aes_plaintext, aes_key)
    aes_decrypted = aes_decrypt(aes_ciphertext, aes_key)

    print("AES Encryption:")
    print(f"Ciphertext: {aes_ciphertext}")
    print(f"Decrypted Text: {aes_decrypted}\n")

    # RSA Example
    rsa_private_key, rsa_public_key = rsa_generate_keys()
    rsa_plaintext = "Encrypt me with RSA"
    rsa_ciphertext = rsa_encrypt(rsa_plaintext, rsa_public_key)
    rsa_decrypted = rsa_decrypt(rsa_ciphertext, rsa_private_key)

    print("RSA Encryption:")
    print(f"Ciphertext: {rsa_ciphertext}")
    print(f"Decrypted Text: {rsa_decrypted}\n")

    # SHA-256 Hashing Example
    data = "Data to hash"
    hashed_value = hash_sha256(data)
    print("SHA-256 Hashing:")
    print(f"Hashed Value: {hashed_value}")
