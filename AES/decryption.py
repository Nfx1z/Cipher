from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# AES Encryption Function
def aes_encrypt(plaintext, key):
    """Encrypts a plaintext string using AES-128 in ECB mode with PKCS7 padding."""
    cipher = AES.new(bytes(key), AES.MODE_ECB)  # AES with ECB mode
    padded_plaintext = pad(plaintext.encode(), AES.block_size)  # Apply PKCS7 padding
    ciphertext = cipher.encrypt(padded_plaintext)  # Encrypt
    return binascii.hexlify(ciphertext).decode()  # Convert to hex string

# AES Decryption Function
def aes_decrypt(ciphertext_hex, key):
    """Decrypts a hex-encoded AES-128 ciphertext using ECB mode."""
    cipher = AES.new(bytes(key), AES.MODE_ECB)  # AES with ECB mode
    ciphertext = binascii.unhexlify(ciphertext_hex)  # Convert hex to bytes
    decrypted_bytes = cipher.decrypt(ciphertext)  # Decrypt
    plaintext = unpad(decrypted_bytes, AES.block_size)  # Remove padding
    return plaintext.decode()  # Convert to string

# Define Key (16 bytes for AES-128)
plaintext = "thisisasecretmsg"  # 16-byte plaintext
key = b"thisisakey123456" 

# Encrypt
ciphertext_hex = aes_encrypt(plaintext, key)
print("🔐 Encrypted (Hex):", ciphertext_hex)

# Decrypt
decrypted_text = aes_decrypt(ciphertext_hex, key)
print("🔓 Decrypted Text:", decrypted_text)
