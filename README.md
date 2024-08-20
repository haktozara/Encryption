# Encryption Software

This project is a simple encryption software that demonstrates the use of various cryptographic algorithms, including AES (Advanced Encryption Standard), RSA (Rivest–Shamir–Adleman), and SHA-256 hashing. The software allows for symmetric and asymmetric encryption and decryption of data as well as hashing for data integrity.

## Features

- **AES Encryption (Symmetric)**: Encrypt and decrypt data using the AES-128 GCM algorithm.
- **RSA Encryption (Asymmetric)**: Generate RSA public and private key pairs, encrypt data with the public key, and decrypt it with the private key.
- **SHA-256 Hashing**: Hash data using the SHA-256 algorithm for integrity checking.

## Requirements

To run this software, you will need to install the following Python packages:

- `pycryptodome`
- `cryptography`

You can install the dependencies using `pip`:

```bash
pip install pycryptodome cryptography
```

## Usage

### AES Encryption & Decryption

1. Generate a 128-bit AES key.
2. Encrypt a plaintext string.
3. Decrypt the ciphertext back into plaintext.

```python
from your_module import aes_encrypt, aes_decrypt
from Crypto.Random import get_random_bytes

# Generate a random 128-bit key for AES
aes_key = get_random_bytes(16)

# Encrypt the plaintext
plaintext = "This is a secret message"
ciphertext = aes_encrypt(plaintext, aes_key)

# Decrypt the ciphertext
decrypted_text = aes_decrypt(ciphertext, aes_key)

print(f"Ciphertext: {ciphertext}")
print(f"Decrypted Text: {decrypted_text}")
```

### RSA Encryption & Decryption

1. Generate RSA public/private key pairs.
2. Encrypt a plaintext string with the public key.
3. Decrypt the ciphertext with the private key.

```python
from your_module import rsa_generate_keys, rsa_encrypt, rsa_decrypt

# Generate RSA keys
private_key, public_key = rsa_generate_keys()

# Encrypt the plaintext
plaintext = "Encrypt me with RSA"
ciphertext = rsa_encrypt(plaintext, public_key)

# Decrypt the ciphertext
decrypted_text = rsa_decrypt(ciphertext, private_key)

print(f"Ciphertext: {ciphertext}")
print(f"Decrypted Text: {decrypted_text}")
```

### SHA-256 Hashing

1. Hash a plaintext string using the SHA-256 algorithm.

```python
from your_module import hash_sha256

# Hash the plaintext
data = "Data to hash"
hashed_value = hash_sha256(data)

print(f"Hashed Value: {hashed_value}")
```

## Example Output

### AES Encryption
```
Ciphertext: Gmh1VTBPtOZkTWZqT10vTHjLklBkh0cPug==
Decrypted Text: This is a secret message
```

### RSA Encryption
```
Ciphertext: Vv2JkOaVkK0Vvv3q1E2eFw==
Decrypted Text: Encrypt me with RSA
```

### SHA-256 Hashing
```
Hashed Value: 6c7ae3a162f9bbacb24cd16d7322b6aeb7b73e75bb845f780b282003bb22d7fa
```

## Customization

Feel free to modify the code for more advanced encryption schemes or to extend support for additional algorithms such as Blowfish, ChaCha20, etc.

### Important Notes

- **AES (Symmetric)**: This encryption is suitable for large amounts of data.
- **RSA (Asymmetric)**: Typically used to encrypt small pieces of data like keys.
- **SHA-256 (Hashing)**: A one-way cryptographic function used to verify data integrity.
