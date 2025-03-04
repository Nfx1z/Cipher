# AES S-box (SubBytes step) - Full 16x16 Table
# The S-Box is always the same except for Modified AES
# For decryption, the S-Box is inverse
S_BOX = [
    #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],   # 0
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],   # 1
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],   # 2
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],   # 3
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],   # 4
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],   # 5
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],   # 6
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],   # 7
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],   # 8
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],   # 9
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],   # A
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],   # B 
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],   # C
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],   # D
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],   # E
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]    # F
]

# Rcon array for AES-128 (10 rounds)
RCON = [
    [0x00, 0x00, 0x00, 0x00],  # Not used (index starts from 1)
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

# AES MixColumns transformation
def add_round_key(state, round_key):
    """XORs each byte of the state with the round key."""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]  # XOR with round key
    return state

#  SubBytes : Uses the S-box to replace each byte
def sub_bytes(state):
    """
    In AES, row first, col second
    0x53 -> row 5, col 3
    eg: 0x74 -> 0x74 >> 4 = 0x07, 0x74 & 0x0F = 0x04
        0111 0100 (0x74)
        >> 4 , shift right 4 bits
        0000 0111 (0x07)
      & 0000 1111 (0x0F)
     -------------
        0000 0111 (0x07) -> row index

        0111 0100 (0x74)
      & 0000 1111 (0x0F)
      ------------
        0000 0100 (0x04) ->  col index
    """
    for i in range(4):
        for j in range(4):
            # just to make sure there is only 4 bits left
            # & 0x0F to get the last 4 bits, but not using it is also fine
            row = (state[i][j] >> 4) & 0x0F
            col = state[i][j] & 0x0F
            # Transform the byte using the S-box
            state[i][j] = S_BOX[row][col]
    return state

def shift_rows(state):
    """Performs the ShiftRows transformation.
    eg: 
           -> BEFORE SHIFT
    [0x32, 0x88, 0x31, 0xE0]  # Row 0 (No shift)
    [0x43, 0x5A, 0x31, 0x37]  # Row 1 (Shift left by 1)
    [0xF6, 0x30, 0x98, 0x07]  # Row 2 (Shift left by 2)
    [0xA8, 0x8D, 0xA2, 0x34]  # Row 3 (Shift left by 3)

           -> AFTER SHIFT
    [0x32, 0x88, 0x31, 0xE0]  # Row 0 (No shift)
    [0x5A, 0x31, 0x37, 0x43]  # Row 1 (Shift left by 1)
    [0x98, 0x07, 0xF6, 0x30]  # Row 2 (Shift left by 2)
    [0x34, 0xA8, 0x8D, 0xA2]  # Row 3 (Shift left by 3)

    """
    state[1] = state[1][1:] + state[1][:1]  # Shift row 1 left by 1
    state[2] = state[2][2:] + state[2][:2]  # Shift row 2 left by 2
    state[3] = state[3][3:] + state[3][:3]  # Shift row 3 left by 3
    return state

# Galois Field multiplication
def gmul(num_I, num_II):
    """Galois Field multiplication of a and b in GF(2^8)
    0x1b = 0001 1011
    0x80 = 1000 0000
    """
    result = 0
    for _ in range(8):
        # Check for LSB (least significant bit)
        if num_II & 1:
            result ^= num_I # XOR result wiht num 1
        # Check for MSB (most significant bit)
        MSB = num_I & 0x80
        # Shift left by 1 for num 1
        num_I <<= 1
        if MSB:
            num_I ^= 0x1b  # Reduce modulo AES irreducible polynomial
        # Shift right by 1 for num 2
        num_II >>= 1
    # & 0xFF is for keep 8 bits only
    return result & 0xFF

# AES MixColumns transformation
def mix_single_column(column):
    """Applies MixColumns to a single column"""
    a = column[:]  # Copy original column
    return [
        gmul(a[0], 2) ^ gmul(a[1], 3) ^ gmul(a[2], 1) ^ gmul(a[3], 1),
        gmul(a[0], 1) ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ gmul(a[3], 1),
        gmul(a[0], 1) ^ gmul(a[1], 1) ^ gmul(a[2], 2) ^ gmul(a[3], 3),
        gmul(a[0], 3) ^ gmul(a[1], 1) ^ gmul(a[2], 1) ^ gmul(a[3], 2),
    ]

# AES MixColumns on the state
def mix_columns(state):
    """Applies MixColumns to the entire state, ensuring the correct shape."""
    mixed = [mix_single_column(col) for col in zip(*state)]  # Mix each column
    return [list(row) for row in zip(*mixed)]  # Transpose back

# SubWord transformation in AES.
def sub_words(word):
    """
    SubWord transformation in AES.
    Similar to sub_bytes, but for a single word
    eg: 0x19 -> 0x19 >> 4 = 0x01, 0x19 & 0x0F = 0x09
    word = [0x77, 0x19, 0x8c, 0xac]
    result = [0xF2, 0xD4, 0x64, 0x91]
    """
    return [S_BOX[byte >> 4][byte & 0x0F] for byte in word]

# Rotate the words in the key schedule
def rot_words(word):
    """
    Rotate the words in the key schedule

    Before rotation: [0x1A, 0x2B, 0x3C, 0x4D]
    After rotation:  [0x2B, 0x3C, 0x4D, 0x1A]

    """
    return word[1:] + word[:1]

def key_expansion(key):
    """Generate 44 words (176 bytes) from a 16-byte key (AES-128)"""
    Nk = 4  # AES-128 has a 16-byte key (4 words)
    Nb = 4  # AES block size (4 words)
    Nr = 10  # AES-128 has 10 rounds

    assert len(key) == 16  # Ensure 16-byte key

    # Initialize the key schedule with the key
    """ eg:     
    key_schedule = [
            [0x2b, 0x7e, 0x15, 0x16],  # W0
            [0x28, 0xae, 0xd2, 0xa6],  # W1
            [0xab, 0xf7, 0x1d, 0x5f],  # W2
            [0xac, 0x77, 0x19, 0x8c]   # W3
            ]
    """
    key_schedule = []  # Initialize an empty array
    # Extract 4 bytes from the key
    for i in range(0, 16, 4):
        key_schedule.append(list(key[i:i+4]))  # Convert to words
        
    # Generate the remaining words (176 bytes)
    # temp is used for RotWord and SubWord transformations
    for i in range(Nk, Nb * (Nr + 1)):
        """ eg:
            W0 = [0x2b, 0x7e, 0x15, 0x16]
            W1 = [0x28, 0xae, 0xd2, 0xa6]
            W2 = [0xab, 0xf7, 0x1d, 0x5f]
            W3 = [0xac, 0x77, 0x19, 0x8c]
            temp = key_schedule[i - 1]  # i = 4 → key_schedule[3]
            temp = [0xac, 0x77, 0x19, 0x8c]
        """
        temp = key_schedule[i - 1]
        if i % Nk == 0:  # Every Nk-th word
            """ eg:
            temp = [0xac, 0x77, 0x19, 0x8c]
            rot_words(temp) = [0x77, 0x19, 0x8c, 0xac]
            sub_words(rot_words(temp)) = [0xF2, 0xD4, 0x64, 0x91]
            """
            temp = sub_words(rot_words(temp))  # RotWord + SubWord
            
            """ eg: i = 4
            temp = temp[0] ^ RCON[1][0]
            temp = [0xF2 ^ 0x01]
            temp = [0xF3] 
            """
            for j in range(4):
                temp[j] = temp[j] ^ RCON[i//Nk][j]  # XOR with Rcon
        """ eg:
        temp = [0xf2, 0xd4, 0x64, 0x91]
        key_schedule[i - Nk] = key_schedule[0] = [0x2b, 0x7e, 0x15, 0x16]
        [ 0x2b ^ 0xf2, 0x7e ^ 0xd4, 0x15 ^ 0x64, 0x16 ^ 0x91]
        [ 0xd9, 0xaa, 0x71, 0x87 ] -> new word
        """
        key_schedule.append([temp[j] ^ key_schedule[i - Nk][j] for j in range(4)])
        
    return key_schedule

# AES Encryption
def aes_encrypt(plaintext, key):
    """Encrypts a 16-byte plaintext using AES-128."""
    assert len(plaintext) == 16 and len(key) == 16, "Plaintext and key must be 16 bytes each."
    
    # Convert plaintext into a 4x4 state matrix
    state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
    
    # Generate round keys
    round_keys = key_expansion(key)
    
    # Initial round: AddRoundKey
    state = add_round_key(state, round_keys[:4])
    
    # Main rounds (9 rounds for AES-128)
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num*4:(round_num+1)*4])
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[40:])
    
    # Convert state back to a single byte array
    ciphertext = bytes(sum(state, []))
    return ciphertext

# Example usage:
plaintext = b"thisisasecretmsg"  # 16-byte plaintext
key = b"thisisakey123456"        # 16-byte key
ciphertext = aes_encrypt(plaintext, key)
print(ciphertext.hex())


# # AES Decryption Implementation

# # AES Inverse S-Box (InvSubBytes step) - Full 16x16 Table
# INV_S_BOX = [[0] * 16 for _ in range(16)]

# # Generate inverse S-Box by reversing the mapping of S-Box
# for i in range(16):
#     for j in range(16):
#         val = S_BOX[i][j]
#         row, col = val >> 4, val & 0x0F
#         INV_S_BOX[row][col] = (i << 4) | j

# # Inverse SubBytes transformation
# def inv_sub_bytes(state):
#     return [[INV_S_BOX[(byte >> 4) & 0x0F][byte & 0x0F] for byte in row] for row in state]

# # Inverse ShiftRows transformation
# def inv_shift_rows(state):
#     state[1] = [state[1][-1]] + state[1][:-1]  # Shift row 1 right by 1
#     state[2] = state[2][-2:] + state[2][:-2]  # Shift row 2 right by 2
#     state[3] = state[3][-3:] + state[3][:-3]  # Shift row 3 right by 3
#     return state

# # Galois multiplication
# def gmul(a, b):
#     p = 0
#     for _ in range(8):
#         if b & 1:
#             p ^= a
#         hi_bit_set = a & 0x80
#         a = (a << 1) & 0xFF
#         if hi_bit_set:
#             a ^= 0x1B
#         b >>= 1
#     return p

# # Inverse MixColumns transformation using Galois multiplication
# def inv_mix_columns(state):
#     def inv_mix_single_column(column):
#         a = column[:]
#         return [
#             gmul(a[0], 0x0E) ^ gmul(a[1], 0x0B) ^ gmul(a[2], 0x0D) ^ gmul(a[3], 0x09),
#             gmul(a[0], 0x09) ^ gmul(a[1], 0x0E) ^ gmul(a[2], 0x0B) ^ gmul(a[3], 0x0D),
#             gmul(a[0], 0x0D) ^ gmul(a[1], 0x09) ^ gmul(a[2], 0x0E) ^ gmul(a[3], 0x0B),
#             gmul(a[0], 0x0B) ^ gmul(a[1], 0x0D) ^ gmul(a[2], 0x09) ^ gmul(a[3], 0x0E),
#         ]
#     mixed = [inv_mix_single_column(col) for col in zip(*state)]
#     return [list(row) for row in zip(*mixed)]

# # XOR state with round key
# def add_round_key(state, round_key):
#     return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

# # AES Decryption function


# from Crypto.Cipher import AES
# from Crypto.Util.Padding import unpad
# import base64

# def aes_decrypt(ciphertext: str, key: str) -> str:
#     # Ensure key is 16, 24, or 32 bytes long
#     if isinstance(key, str):
#         key = key.encode('utf-8')  # Convert string key to bytes only if needed

#     key = key.ljust(32, b' ')[:32]  # Pad or truncate key to 32 bytes
    
#     # Decode base64 encoded ciphertext
#     encrypted_data = base64.b64decode(ciphertext)
    
#     # Extract IV (first 16 bytes) and actual encrypted data
#     iv, encrypted_text = encrypted_data[:16], encrypted_data[16:]
    
#     # Initialize AES cipher in CBC mode
#     cipher = AES.new(key, AES.MODE_CBC, iv)
    
#     # Decrypt and remove padding
#     decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    
#     return decrypted_text.decode('utf-8')

# # Example usage
# ciphertext = aes_encrypt(plaintext, key)

# decrypted_text = aes_decrypt(ciphertext, key)
# print("Decrypted text:", decrypted_text)