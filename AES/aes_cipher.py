# AES S-box (SubBytes step)
S_BOX = [
    #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], # 0
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0], # 1
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], # 2
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75], # 3
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84], # 4
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf], # 5
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8], # 6
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2], # 7
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73], # 8
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb], # 9
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79], # A
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08], # B
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], # C
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e], # D
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], # E
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]  # F
]

# Inverse S-box for decryption
INV_S_BOX = [
    #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb], # 0
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb], # 1
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e], # 2
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25], # 3
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92], # 4
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84], # 5
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06], # 6
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b], # 7
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73], # 8
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e], # 9
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b], # A
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4], # B
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f], # C
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef], # D
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61], # E
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]  # F
]

# Rcon array for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

def get_key_params(key_size):
    """Returns Nk (number of 32-bit words in key) and Nr (number of rounds) based on key size."""
    if key_size == 16:  # 128-bit key
        return 4, 10
    elif key_size == 24:  # 192-bit key
        return 6, 12
    elif key_size == 32:  # 256-bit key
        return 8, 14
    else:
        raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)")

def sub_bytes(state):
    """Applies the S-box substitution to each byte in the state.
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
            row = (state[i][j] >> 4) & 0x0F
            col = state[i][j] & 0x0F
            state[i][j] = S_BOX[row][col]
    return state

def inv_sub_bytes(state):
    """Applies the inverse S-box substitution to each byte in the state."""
    for i in range(4):
        for j in range(4):
            row = (state[i][j] >> 4) & 0x0F
            col = state[i][j] & 0x0F
            state[i][j] = INV_S_BOX[row][col]
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

def inv_shift_rows(state):
    """Inverse of shift_rows operation."""
    state[1] = state[1][-1:] + state[1][:-1]  # Shift row 1 right by 1
    state[2] = state[2][-2:] + state[2][:-2]  # Shift row 2 right by 2
    state[3] = state[3][-3:] + state[3][:-3]  # Shift row 3 right by 3
    return state

def gmul(num_I, num_II):
    """Galois Field multiplication of a and b in GF(2^8)
    0x1b = 0001 1011
    0x80 = 1000 0000
    """
    result = 0
    for _ in range(8):
        if num_II == 0: break
        # Check for LSB (least significant bit)
        if num_II & 1: result ^= num_I
        # Check for MSB (most significant bit)
        MSB = num_I & 0x80
        num_I <<= 1     # Shift left by 1 for num 1
        # Reduce modulo AES irreducible polynomial
        if MSB: num_I ^= 0x1b  
        num_II >>= 1    # Shift right by 1 for num 2
    # & 0xFF is for keep 8 bits only
    return result & 0xFF

def mix_columns(state):
    """Mixes each column of the state.
    2 3 1 1
    1 2 3 1
    1 1 2 3
    3 1 1 2
    """
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        
        # Save original values
        s0, s1, s2, s3 = column

        # Calculate new values using Galois Field multiplication
        state[0][i] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3
        state[1][i] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3
        state[2][i] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3)
        state[3][i] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2)
    
    return state

def inv_mix_columns(state):
    """Inverse of mix_columns operation.
    14 11 13 9
    9 14 11 13
    13 9 14 11
    11 13 9 14
    """
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        
        # Save original values
        s0, s1, s2, s3 = column

        # Calculate new values using Galois Field multiplication
        state[0][i] = gmul(s0, 0x0E) ^ gmul(s1, 0x0B) ^ gmul(s2, 0x0D) ^ gmul(s3, 0x09)
        state[1][i] = gmul(s0, 0x09) ^ gmul(s1, 0x0E) ^ gmul(s2, 0x0B) ^ gmul(s3, 0x0D)
        state[2][i] = gmul(s0, 0x0D) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0E) ^ gmul(s3, 0x0B)
        state[3][i] = gmul(s0, 0x0B) ^ gmul(s1, 0x0D) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0E)
    
    return state

def add_round_key(state, round_key):
    """XORs each byte of the state with the round key."""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def sub_word(word):
    """Applies S-box to each byte in a word."""
    return [S_BOX[(b >> 4) & 0x0F][b & 0x0F] for b in word]

def rot_word(word):
    """Rotates a word to the left by 1 byte."""
    return word[1:] + word[:1]

def key_expansion(key):
    """Expands the key into round keys."""
    # Determine parameters based on key size
    Nk, Nr = get_key_params(len(key))
    Nb = 4  # AES block size is always 4 words (128 bits)
    
    key_schedule = []
    # Convert key to words (4 bytes each)
    for i in range(0, len(key), 4):
        key_schedule.append(list(key[i:i+4]))
    
    # Generate additional words
    for i in range(Nk, Nb * (Nr + 1)):
        """ eg:
        W0 = [0x2b, 0x7e, 0x15, 0x16]
        W1 = [0x28, 0xae, 0xd2, 0xa6]
        W2 = [0xab, 0xf7, 0x1d, 0x5f]
        W3 = [0xac, 0x77, 0x19, 0x8c]
        temp = key_schedule[i - 1]  # i = 4 → key_schedule[3]
        temp = [0xac, 0x77, 0x19, 0x8c]
        """
        temp = key_schedule[i-1][:]
        
        if i % Nk == 0:
            """ eg:
            temp = [0xac, 0x77, 0x19, 0x8c]
            rot_words(temp) = [0x77, 0x19, 0x8c, 0xac]
            sub_words(rot_words(temp)) = [0xF2, 0xD4, 0x64, 0x91]
            """
            temp = sub_word(rot_word(temp))
            
            """ eg: i = 4
            temp[0] = temp[0] ^ RCON[0]
            temp[0] = [0xF2 ^ 0x01]
            temp[0] = [0xF3]
            """
            temp[0] ^= RCON[(i // Nk) - 1]
        # Additional S-box for AES-256 because it has large gaps in the key schedule
        # so to avoid the gaps, we apply S-box to the word every 4th word
        elif Nk > 6 and i % Nk == 4:  
            temp = sub_word(temp)
            
        """ eg: i = 4, Nk = 4
        temp = [0xF2, 0xD4, 0x64, 0x91]
        key_schedule[i - Nk] = key_schedule[0] = [0x2b, 0x7e, 0x15, 0x16]
        [ 0xf2 ^ 0x2b, 0xd4 ^ 0x7e, 0x64 ^ 0x15, 0x91 ^ 0x16 ]
        [ 0xd9, 0xaa, 0x71, 0x87 ] -> new word
        """
        key_schedule.append([temp[j] ^ key_schedule[i-Nk][j] for j in range(4)])
    
    # Convert to 4x4 round keys
    round_keys = []
    for i in range(0, len(key_schedule), 4):
        # Transpose to get proper layout for add_round_key
        rk = [[0 for _ in range(4)] for _ in range(4)] # generate blank 4x4 matrix
        for r in range(4):
            for c in range(4):
                # row becomes column and column becomes row
                rk[r][c] = key_schedule[i+c][r]  
        round_keys.append(rk)
    
    return round_keys, Nr

def create_state_matrix(data):
    """Creates a 4x4 state matrix from a 16-byte array."""
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = data[i + 4*j]
    return state

def state_to_bytes(state):
    """Converts a state matrix back to a byte array."""
    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[i + 4*j] = state[i][j]
    return bytes(result)

def encrypt(plaintext, key):
    """Encrypts a 16-byte plaintext block using AES."""
    assert len(plaintext) == 16, "Plaintext must be 16 bytes"
    assert len(key) in [16, 24, 32], "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
    
    # Create state matrix from plaintext
    state = create_state_matrix(plaintext)
    
    # Expand the key and get number of rounds
    round_keys, Nr = key_expansion(key)
    
    # Initial round
    state = add_round_key(state, round_keys[0])
    
    # Main rounds
    for round_num in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    
    # Convert state back to bytes
    return state_to_bytes(state)

def decrypt(ciphertext, key):
    """Decrypts a 16-byte ciphertext block using AES."""
    assert len(ciphertext) == 16, "Ciphertext must be 16 bytes"
    assert len(key) in [16, 24, 32], "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
    
    # Create state matrix from ciphertext
    state = create_state_matrix(ciphertext)
    
    # Expand the key and get number of rounds
    round_keys, Nr = key_expansion(key)
    
    # Initial round
    state = add_round_key(state, round_keys[Nr])
    
    # Main rounds (in reverse)
    for round_num in range(Nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    # Convert state back to bytes
    return state_to_bytes(state)

# PKCS#7 is choosen because it solves the problem of padding
def pad_pkcs7(data, block_size=16):
    """Adds PKCS#7 padding to data.
    Padding for adding bytes to the plaintext to make it a multiple of the block size.
    for example, if the block size is 16 bytes and the plaintext is 10 bytes long,
    the padding will be 6 bytes: 0x06 0x06 0x06 0x06 0x06 0x06
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_pkcs7(data):
    """Removes PKCS#7 padding from data."""
    padding_length = data[-1]
    # for extra security
    if padding_length > len(data): # to prevent the string being remove completely
        raise ValueError("Invalid padding")
    for i in range(1, padding_length + 1):  # + 1 to include the last byte
        if data[-i] != padding_length: # to check if there is any invalid padding
            raise ValueError("Invalid padding")
    return data[:-padding_length]

def aes_encrypt(plaintext, key, mode='ECB', key_size=None):
    """
    Encrypts plaintext using AES with specified mode and key size.
    
    Args:
        plaintext: The text to encrypt (bytes or string)
        key: The encryption key (bytes or string)
        mode: Encryption mode (currently only 'ECB' supported)
        key_size: Optional key size (128, 192, or 256 bits). If None, determined from key length.
    
    Returns:
        bytes: The encrypted ciphertext
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Process key size
    if key_size is None:
        # Auto-determine based on key length
        if len(key) <= 16:
            key_size = 16  # 128 bits
        elif len(key) <= 24:
            key_size = 24  # 192 bits
        else:
            key_size = 32  # 256 bits
    else:
        # Convert from bits to bytes if needed
        if key_size in [128, 192, 256]:
            key_size = key_size // 8
        
        if key_size not in [16, 24, 32]:
            raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
    
    # Adjust key to match desired key size
    if len(key) < key_size:
        key = key + b'\x00' * (key_size - len(key))
    elif len(key) > key_size:
        key = key[:key_size]
    
    # Apply PKCS#7 padding
    padded_plaintext = pad_pkcs7(plaintext)
    
    ciphertext = bytearray()
    
    if mode == 'ECB':  # Electronic Codebook Mode
        # Process each block
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_block = encrypt(block, key)
            ciphertext.extend(encrypted_block)
    else:
        raise ValueError(f"Mode {mode} not implemented")
    
    return bytes(ciphertext)

def aes_decrypt(ciphertext, key, mode='ECB', key_size=None):
    """
    Decrypts ciphertext using AES with specified mode and key size.
    
    Args:
        ciphertext: The encrypted data (bytes)
        key: The encryption key (bytes or string)
        mode: Encryption mode (currently only 'ECB' supported)
        key_size: Optional key size (128, 192, or 256 bits). If None, determined from key length.
    
    Returns:
        bytes: The decrypted plaintext
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Process key size
    if key_size is None:
        # Auto-determine based on key length
        if len(key) <= 16:
            key_size = 16  # 128 bits
        elif len(key) <= 24:
            key_size = 24  # 192 bits
        else:
            key_size = 32  # 256 bits
    else:
        # Convert from bits to bytes if needed
        if key_size in [128, 192, 256]:
            key_size = key_size // 8
        
        if key_size not in [16, 24, 32]:
            raise ValueError("Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
    
    # Adjust key to match desired key size
    if len(key) < key_size:
        key = key + b'\x00' * (key_size - len(key))
    elif len(key) > key_size:
        key = key[:key_size]
    
    plaintext = bytearray()
    
    if mode == 'ECB':  # Electronic Codebook Mode
        # Process each block
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = decrypt(block, key)
            plaintext.extend(decrypted_block)
    else:
        raise ValueError(f"Mode {mode} not implemented")
    
    # Remove padding
    try:
        unpadded_plaintext = unpad_pkcs7(plaintext)
        return unpadded_plaintext
    except ValueError:
        # If unpadding fails, return plaintext as is
        return bytes(plaintext)

# Example usage
if __name__ == "__main__":
    # Test different key sizes
    plaintext = "This is a secret message that needs to be encrypted properly."
    
    # Test with different key sizes - auto detection
    test_keys = {
        "AES-128": "key-128bits-here",              # Will use AES-128
        "AES-192": "key-192bits-longer-key-here",   # Will use AES-192
        "AES-256": "key-256bits-even-longer-key-here-for-testing" # Will use AES-256
    }
    
    print("Testing automatic key size detection:\n")
    for key_name, key in test_keys.items():
        print(f"Testing {key_name}:")
        
        # Encrypt using auto-detected key size
        ciphertext = aes_encrypt(plaintext, key)
        print(f"  Ciphertext (hex): {ciphertext.hex()}...")
        
        # Decrypt using auto-detected key size
        decrypted = aes_decrypt(ciphertext, key)
        print(f"  Decrypted: {decrypted.decode('utf-8')}")
        print()
    
    # Test with explicit key size selection
    print("Testing explicit key size selection:\n")
    short_key = "short_key"
    
    for key_size in [128, 192, 256]:
        print(f"Using key size: {key_size} bits")
        
        # Encrypt with specified key size
        ciphertext = aes_encrypt(plaintext, short_key, key_size=key_size)
        print(f"  Ciphertext (hex): {ciphertext.hex()}...")
        
        # Decrypt with specified key size
        decrypted = aes_decrypt(ciphertext, short_key, key_size=key_size)
        print(f"  Decrypted: {decrypted.decode('utf-8')}")
        print()