# AES S-box (SubBytes step) - Full 16x16 Table
# The S-Box is always the same except for Modified AES
# For decryption, the S-Box is inverse
S_BOX = [
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
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]  # Store only the first byte

# AES MixColumns transformation
def add_round_key(state, round_key):
    """XORs each byte of the state with the round key."""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]  # XOR with round key
    return state

#  SubBytes : Uses the S-box to replace each byte
def sub_bytes(state):
    """ In AES, row first, col second
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
        # just to make sure there is only 4 bits left
        for j in range(4):
            # Transform the byte using the S-box
            # & 0x0F to get the last 4 bits, but not using it is also fine
            state[i][j] = S_BOX[(state[i][j] >> 4) & 0x0F][state[i][j] & 0x0F]
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
        # if num_II == 0: break
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
    """ SubWord transformation in AES.
    Similar to sub_bytes, but for a single word
    eg: 0x19 -> 0x19 >> 4 = 0x01, 0x19 & 0x0F = 0x09
    word = [0x77, 0x19, 0x8c, 0xac]
    result = [0xF2, 0xD4, 0x64, 0x91]
    """
    return [S_BOX[byte >> 4][byte & 0x0F] for byte in word]

# Rotate the words in the key schedule
def rot_words(word):
    """ Rotate the words in the key schedule
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
            temp[0] = temp[0] ^ RCON[0]
            temp[0] = [0xF2 ^ 0x01]
            temp[0] = [0xF3] 
            """
            temp[0] ^= RCON[(i//Nk) - 1] # XOR with Rcon
        """ eg:
        temp = [0xf2, 0xd4, 0x64, 0x91]
        key_schedule[i - Nk] = key_schedule[0] = [0x2b, 0x7e, 0x15, 0x16]
        [ 0x2b ^ 0xf2, 0x7e ^ 0xd4, 0x15 ^ 0x64, 0x16 ^ 0x91]
        [ 0xd9, 0xaa, 0x71, 0x87 ] -> new word
        """
        key_schedule.append([temp[j] ^ key_schedule[i - Nk][j] for j in range(4)])
        
    return key_schedule

# def encrypt(plaintext, key):
#     """
#     Encrypt a 16-byte plaintext using AES-128
    
#     Args:
#     - plaintext: 16-byte input block
#     - key: 16-byte encryption key
    
#     Returns:
#     - Encrypted 16-byte block
#     """
#     # Ensure inputs are correct length
#     assert len(plaintext) == 16, "Plaintext must be 16 bytes"
#     assert len(key) == 16, "Key must be 16 bytes"
    
#     # Convert input to 4x4 state matrix
#     state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
    
#     # Expand the key
#     round_keys = key_expansion(key)
    
#     # Initial round: AddRoundKey
#     state = add_round_key(state, round_keys[:4])
    
#     # Main rounds (9 rounds for AES-128)
#     for round_num in range(1, 10):
#         # SubBytes
#         state = sub_bytes(state)
        
#         # ShiftRows
#         state = shift_rows(state)
        
#         # MixColumns
#         state = mix_columns(state)
        
#         # AddRoundKey
#         state = add_round_key(state, round_keys[round_num*4:(round_num+1)*4])
    
#     # Final round (no MixColumns)
#     state = sub_bytes(state)
#     state = shift_rows(state)
#     state = add_round_key(state, round_keys[40:])
    
#     # Flatten the state back to a 16-byte list
#     return bytes([byte for row in state for byte in row])
def verify_sbox():
    """Verify S-box characteristics"""
    # Check S-box dimensions
    assert len(S_BOX) == 16, "S-box should have 16 rows"
    assert all(len(row) == 16 for row in S_BOX), "Each S-box row should have 16 columns"
    
    # Verify some known S-box values
    test_cases = [
        (0x00, 0x63),  # 0x00 always maps to 0x63
        (0x01, 0x7c),  # 0x01 maps to 0x7c
        (0xff, 0x16),  # 0xff maps to 0x16
    ]
    
    for input_val, expected_output in test_cases:
        row = input_val >> 4
        col = input_val & 0x0F
        actual_output = S_BOX[row][col]
        assert actual_output == expected_output, f"S-box lookup failed for {input_val:02x}"
    
    print("S-box verification passed!")

def verify_gmul():
    """Verify Galois Field multiplication"""
    # Some known test cases for gmul
    test_cases = [
        (0x57, 0x13, 0xfe),  # Known test vector
        (0x01, 0x02, 0x02),  # Multiplication by 2
        (0x03, 0x02, 0x06),  # Another multiplication test
    ]
    
    for a, b, expected in test_cases:
        result = gmul(a, b)
        assert result == expected, f"Galois multiplication failed: {a} * {b} != {expected}"
    
    print("Galois Field multiplication verification passed!")

def verify_key_expansion():
    """Verify key expansion with a known test vector"""
    key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
    
    expanded_key = key_expansion(key)
    
    # Verify key schedule length (44 words for AES-128)
    assert len(expanded_key) == 44, "Key schedule should have 44 words"
    
    # Check first round key (should be the original key)
    first_round_key = [expanded_key[i][:4] for i in range(4)]
    expected_first_key = [
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ]
    assert first_round_key == expected_first_key, "First round key incorrect"
    
    print("Key expansion verification passed!")

def verify_transformations():
    """Verify individual AES transformations"""
    # Test SubBytes
    test_state = [
        [0x00, 0x11, 0x22, 0x33],
        [0x44, 0x55, 0x66, 0x77],
        [0x88, 0x99, 0xaa, 0xbb],
        [0xcc, 0xdd, 0xee, 0xff]
    ]
    
    # SubBytes should replace each byte with its S-box equivalent
    sub_state = sub_bytes([row[:] for row in test_state])
    
    # Verify that each byte has been substituted
    for i in range(4):
        for j in range(4):
            row = test_state[i][j] >> 4
            col = test_state[i][j] & 0x0F
            assert sub_state[i][j] == S_BOX[row][col], f"SubBytes failed at [{i}][{j}]"
    
    print("Transformation verifications passed!")

# Run all verifications
verify_sbox()
verify_gmul()
verify_key_expansion()
verify_transformations()

print("All AES component verifications completed!")

def detailed_gmul_verification():
    """
    Comprehensive verification of Galois Field multiplication
    Includes detailed test cases and edge cases
    """
    print("Detailed Galois Field Multiplication Verification:")
    
    # Comprehensive test cases
    test_cases = [
        # Basic multiplication cases
        (0x02, 0x03, 0x06),  # Standard AES multiplication
        (0x01, 0x02, 0x02),  # Multiplication by 1 and 2
        (0x03, 0x02, 0x06),  # More complex case
        
        # Edge cases
        (0x00, 0x00, 0x00),  # Zero multiplication
        (0x01, 0xFF, 0xFF),  # Multiplication by 1
        (0x02, 0x80, 0x1B),  # Involves reduction by irreducible polynomial
        
        # Some specific AES test vectors
        (0x57, 0x13, 0xFE),  # Known test vector
        (0xCA, 0x02, 0x8F)   # Another complex case
    ]
    
    for a, b, expected in test_cases:
        result = gmul(a, b)
        print(f"gmul({a:02x}, {b:02x}): Expected {expected:02x}, Got {result:02x}")
        assert result == expected, f"Galois multiplication failed: {a:02x} * {b:02x} != {expected:02x}"
    
    print("Galois Field Multiplication Verification Passed!\n")

def detailed_mix_single_column_verification():
    """
    Detailed verification of MixColumns for a single column
    Includes step-by-step calculation and comparison
    """
    print("Detailed MixColumns Single Column Verification:")
    
    # Test cases with known results
    test_cases = [
        # Sample column from AES specification
        {
            'input': [0x63, 0x4f, 0xa5, 0xb8],
            'expected': [0xba, 0x75, 0x14, 0x53]
        },
        # Another test vector
        {
            'input': [0x00, 0x01, 0x02, 0x03],
            'expected': [0x02, 0x03, 0x01, 0x01]
        }
    ]
    
    for case in test_cases:
        input_column = case['input']
        expected_output = case['expected']
        
        # Perform MixColumns on the single column
        mixed_column = mix_single_column(input_column)
        
        print("Input Column:  ", ' '.join(f'{x:02x}' for x in input_column))
        print("Expected:      ", ' '.join(f'{x:02x}' for x in expected_output))
        print("Actual Result: ", ' '.join(f'{x:02x}' for x in mixed_column))
        
        # Detailed step verification
        for i in range(4):
            print(f"\nColumn {i} Calculation:")
            # Breakdown of Galois Field multiplications
            a = input_column
            print(f"  {gmul(a[0], 2):02x} ^ {gmul(a[1], 3):02x} ^ {gmul(a[2], 1):02x} ^ {gmul(a[3], 1):02x}")
        
        # Assert the result
        assert mixed_column == expected_output, "MixColumns calculation incorrect"
        print("Column MixColumns Verification Passed!\n")

def detailed_mix_columns_verification():
    """
    Comprehensive verification of MixColumns transformation
    """
    print("Detailed MixColumns Matrix Verification:")
    
    # Test matrices
    test_matrices = [
        # Identity matrix (no change)
        [
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [0, 0, 0, 1]
        ],
        
        # Random test matrix
        [
            [0x32, 0x88, 0x31, 0xE0],
            [0x43, 0x5A, 0x31, 0x37],
            [0xF6, 0x30, 0x98, 0x07],
            [0xA8, 0x8D, 0xA2, 0x34]
        ]
    ]
    
    for matrix in test_matrices:
        print("Input Matrix:")
        for row in matrix:
            print(' '.join(f'{x:02x}' for x in row))
        
        # Transpose matrix to column-major order
        columns = list(zip(*matrix))
        
        # Mix each column
        mixed_columns = [mix_single_column(list(col)) for col in columns]
        
        # Transpose back
        result = list(zip(*mixed_columns))
        
        print("\nMixed Matrix:")
        for row in result:
            print(' '.join(f'{x:02x}' for x in row))
        print("\n")

# Run all verifications
detailed_gmul_verification()
detailed_mix_single_column_verification()
detailed_mix_columns_verification()

print("MixColumns and Galois Field Comprehensive Verification Complete!")