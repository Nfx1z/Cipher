import random

# AES S-box (SubBytes step) - Full 16x16 Table
# The S-Box is always the same except for Modified AES
# For decryption, the S-Box is inverse
S_BOX = [
    #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
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
# Multiply by 2 is equal to shift left by 1
def gmul_2(num_bits):
    """
    Multiplication by 2 in the GF(2^8) finite field.
    We need to shift left by 1 and check if the MSB is 1
        MSB is the most significant bit (leftmost bit)
    But if we shift left by 1, the MSB will be lost
    Instead we do & 0x80 ( 1000 0000 ) to know if the MSB is 1
    """
    # if the MSB is 1, we need to XOR with 0x1B (0001 1011)
    # & 0xFF is for keep 8 bits only
    # eg. ((0x80 << 1) ^ 0x1B) & 0xFF   (0x80 << 1) ^ 0x1B
    # -> (0x100 ^ 0x1B) & 0xFF          0x100 ^ 0x1B
    # -> 0x11B & 0xFF                X  0x11B wrong result
    # -> 0x1B  ✓ correct result
    if(num_bits & 0x80):
        return ((num_bits << 1) ^ 0x1B) & 0xFF
    # if the MSB is 0, we can just shift left by 1
    else:
        return (num_bits << 1) & 0xFF
    
# Multiply by 3 is equal to multiply by 2 and then XOR with the original number
def gmul_3(num_bits):
    """
    Multiplication by 3 in the GF(2^8) finite field.
    gmul_3(num_bits) = gmul_2(num_bits) ^ num_bits
    """
    return gmul_2(num_bits) ^ num_bits

# MixColumns for each column in the state
def mix_single_columns(columns):
    """
    MixColumns transformation in AES.
    # This matrix never changes regardless of the key size
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    """
    # Create a copy of the columns
    t = columns[:]

    columns[0] = gmul_2(t[0]) ^ gmul_3(t[1]) ^ t[2] ^ t[3]
    columns[1] = t[0] ^ gmul_2(t[1]) ^ gmul_3(t[2]) ^ t[3]
    columns[2] = t[0] ^ t[1] ^ gmul_2(t[2]) ^ gmul_3(t[3])
    columns[3] = gmul_3(t[0]) ^ t[1] ^ t[2] ^ gmul_2(t[3])

    return columns

# MixColumns for the entire state
def mix_columns(state):
    """
    MixColumns transformation in AES.
    """
    for i in range(4):
        state[i] = mix_single_columns(state[i])
    return state

# SubWord transformation in AES.
def sub_words(word):
    """
    SubWord transformation in AES.
    Similar to sub_bytes, but for a single word
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

    """
    eg:     key_schedule = [
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

    """
    eg:
        W0 = [0x2b, 0x7e, 0x15, 0x16]
        W1 = [0x28, 0xae, 0xd2, 0xa6]
        W2 = [0xab, 0xf7, 0x1d, 0x5f]
        W3 = [0xac, 0x77, 0x19, 0x8c]
        temp = key_schedule[i - 1]  # i = 4 → key_schedule[3]
        temp = [0xac, 0x77, 0x19, 0x8c]
    """
    # temp is used for RotWord and SubWord transformations
    for i in range(Nk, Nb * (Nr + 1)):
        temp = key_schedule[i - 1]

        if i % Nk == 0:  # Every Nk-th word
            temp = sub_words(rot_words(temp))  # RotWord + SubWord
            temp = [temp[j] ^ RCON[i//Nk][j] for j in range(4)]  # XOR with Rcon

        key_schedule.append([key_schedule[i - Nk][j] ^ temp[j] for j in range(4)])

    return key_schedule

# Generate a 16-byte key (128 bits)
import os
aes_key = os.urandom(16)  # 32-byte (AES-256)

# aes_key = [random.randint(0, 255) for _ in range(32)]
# print(aes_key.hex())  # Prints hex string (e.g., "f23a9c...b8d5")
# print(bytes(aes_key))  # Prints bytes (e.g., b'\xf2\x3a\x9c...\xb8\xd5')
# print(bytes(aes_key).hex())
# Print the key in hex format
# hex_key = " ".join(f"{byte:02X}" for byte in aes_key)
# Fixed Key (User-Defined)
# fixed_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # 16 bytes
# print("AES Key (Hex):", hex_key)
# print(f"fixed_key: {fixed_key}")

# key_schedule = [list(aes_key[i:i+4]) for i in range(0, 16, 4)]
# print (key_schedule)
# Generate a random 16-byte AES key
# random_key = os.urandom(16)  # 16 bytes = 128 bits
# print(random_key.hex())  # Print as hex

def key_expansion(key):
    """Generate 44 words (176 bytes) from a 16-byte key (AES-128)"""
    assert len(key) == 16  # Ensure 16-byte key

    key_schedule = [list(key[i:i+4]) for i in range(0, 16, 4)]  # Convert to 4-word list

    for i in range(4, 44):
        temp = key_schedule[i - 1]

        if i % 4 == 0:  # Every 4th word
            temp = sub_words(rot_words(temp))  # Apply RotWord + SubWord
            temp = [temp[j] ^ RCON[i//4][j] for j in range(4)]  # XOR with Rcon

        key_schedule.append([key_schedule[i - 4][j] ^ temp[j] for j in range(4)])

    return key_schedule

print(key_expansion(bytes(aes_key)))