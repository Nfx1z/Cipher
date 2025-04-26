""" explanation:

for encryption, we add the key to the plaintext character's ASCII value and subtract 26 if the result is negative.
for decryption, we subtract the key from the ciphertext character's ASCII value.

we use the ASCII values of a-z to encrypt and decrypt the text.

we convert the key and plaintext to lowercase to make it case-insensitive.

 a  b  c  d   e   f   g   h   i   j   k   l   m   n   o   p   q   r   s   t   u   v   w   x   y   z
97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122

for example (encrryption):

plaintext = "Hello World"
key = "zEY"
key = [ord(i) for i in key] -> [122, 101, 121]
plaintext = [ord(i) for i in plaintext] -> [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]

range(len(plaintext)) -> [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
temp(h) = (104 + 122 - 2*97) % 26 -> 32 % 26 = 6 -> 6 + 97 = 103 = g
temp(e) = (101 + 101 - 2*97) % 26 -> 8 % 26 = 8 -> 8 + 97 = 105 = i

(decryption):

ciphertext = "gi"
key = "zEY"
key = [ord(i) for i in key] -> [122, 101, 121]
ciphertext = [ord(i) for i in ciphertext] -> [103, 105]

range(len(ciphertext)) -> [0, 1]
temp(g) = (103 - 122) % 26 -> 7 + 97 -> 104 = h
temp(i) = (105 - 101) % 26 -> 4 + 97 -> 101 = e
"""
def encrypt(plaintext, key):
    """Encrypts text using Vigenere cipher with given key"""
    ciphertext = ""     # to store encrypted text
    key = key.lower()   # lowecase key because we are using a-z only
    key_length = len(key)
    key_as_int = [ord(i) for i in key]    # convert key to integer
    
    plaintext = plaintext.lower()   # lowercase plaintext because we are using a-z only
    plaintext_int = [ord(i) for i in plaintext]    # convert plaintext to integer
    
    # loop through each character in plaintext
    for i in range(len(plaintext_int)):
        if plaintext[i].isalpha():  # if character is a letter
            value = (plaintext_int[i] + key_as_int[i % key_length] - 2*ord('a')) % 26
            ciphertext += chr(value + ord('a'))
        else:
            ciphertext += plaintext[i]
            
    return ciphertext

def decrypt(ciphertext, key):
    """Decrypts text using Vigenere cipher with given key"""
    plaintext = ""
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    
    ciphertext = ciphertext.lower()
    ciphertext_int = [ord(i) for i in ciphertext]
    
    for i in range(len(ciphertext_int)):
        if ciphertext[i].isalpha():
            value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
            plaintext += chr(value + ord('a'))
        else:
            plaintext += ciphertext[i]
            
    return plaintext

if __name__ == '__main__':
    text = "Hello World"
    key = "zEy"
    
    encrypted = encrypt(text, key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")
