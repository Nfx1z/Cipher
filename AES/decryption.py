from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

def aes_encrypt(plaintext, key):
    """Encrypts a plaintext string using AES-128 in ECB mode with PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_ECB)  # AES with ECB mode
    padded_plaintext = pad(plaintext, AES.block_size)  # Apply PKCS7 padding correctly
    ciphertext = cipher.encrypt(padded_plaintext)  # Encrypt
    return ciphertext  # Return raw ciphertext

plaintext = b"thisisasecretmsg"  # 16-byte plaintext (already in bytes)
key = b"thisisakey123456"        # 16-byte key

ciphertext = aes_encrypt(plaintext, key)
print(ciphertext.hex())  # Convert to hex and print
