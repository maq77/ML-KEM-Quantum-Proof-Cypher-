import struct

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation Table (Inverse of Initial Permutation)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table (E-box)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation Table (P-box)
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# S-boxes (Substitution boxes)
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Key permutation tables
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

# Shift schedule for key generation
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def str_to_bit_array(text):
    """Convert string to bit array"""
    array = []
    for char in text:
        binval = bin(char)[2:].zfill(8) if isinstance(char, int) else bin(ord(char))[2:].zfill(8)
        array.extend([int(x) for x in list(binval)])
    return array

def bit_array_to_str(array):
    """Convert bit array to string"""
    res = []
    for i in range(0, len(array), 8):
        byte = array[i:i+8]
        res.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(res)

def bit_array_to_hex(array):
    """Convert bit array to hex string"""
    res = []
    for i in range(0, len(array), 8):
        byte = array[i:i+8]
        hex_val = hex(int(''.join([str(bit) for bit in byte]), 2))[2:].zfill(2)
        res.append(hex_val)
    return ''.join(res)

def permute(block, table):
    """Permute the input block using specified table"""
    return [block[x-1] for x in table]

def shift_left(key_part, shifts):
    """Left circular shift"""
    return key_part[shifts:] + key_part[:shifts]

def generate_keys(key):
    """Generate 16 round keys"""
    # Convert key to bit array
    key = str_to_bit_array(key)
    
    # Apply PC1 permutation (64 bits to 56 bits)
    key = permute(key, PC1)
    
    # Split key into left and right halves
    left = key[:28]
    right = key[28:]
    
    round_keys = []
    
    # Generate 16 round keys
    for i in range(16):
        # Apply shift schedule
        left = shift_left(left, SHIFT[i])
        right = shift_left(right, SHIFT[i])
        
        # Combine left and right
        combined = left + right
        
        # Apply PC2 permutation (56 bits to 48 bits)
        round_key = permute(combined, PC2)
        round_keys.append(round_key)
    
    return round_keys

def xor(arr1, arr2):
    """XOR two bit arrays"""
    return [a ^ b for a, b in zip(arr1, arr2)]

def f_function(right, round_key):
    """F-function used in each round"""
    # Expansion (32 bits to 48 bits)
    expanded = permute(right, E)
    
    # XOR with round key
    xored = xor(expanded, round_key)
    
    # S-box substitution
    result = []
    for i in range(8):
        # Get 6-bit block
        block = xored[i*6:(i+1)*6]
        
        # Get row and column indices
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        
        # Get S-box value (4 bits)
        s_val = S_BOX[i][row][col]
        
        # Convert to binary
        result.extend([int(x) for x in format(s_val, '04b')])
    
    # Permutation using P-box
    result = permute(result, P)
    
    return result

def des_encrypt_block(block, round_keys):
    """Encrypt a single 64-bit block"""
    # Initial permutation
    block = permute(block, IP)
    
    # Split block into left and right halves
    left = block[:32]
    right = block[32:]
    
    # 16 rounds
    for i in range(16):
        # Save previous left
        temp_left = left
        
        # New left is previous right
        left = right
        
        # New right = previous left XOR F(previous right, round_key)
        right = xor(temp_left, f_function(right, round_keys[i]))
    
    # Final swap (not really needed as last round already swapped)
    # But we need to combine as right + left after 16 rounds
    combined = right + left
    
    # Final permutation
    cipher_block = permute(combined, FP)
    
    return cipher_block

def des_decrypt_block(block, round_keys):
    """Decrypt a single 64-bit block"""
    # Initial permutation
    block = permute(block, IP)
    
    # Split block into left and right halves
    left = block[:32]
    right = block[32:]
    
    # 16 rounds in reverse order
    for i in range(15, -1, -1):
        # Save previous left
        temp_left = left
        
        # New left is previous right
        left = right
        
        # New right = previous left XOR F(previous right, round_key)
        right = xor(temp_left, f_function(right, round_keys[i]))
    
    # Final swap
    combined = right + left
    
    # Final permutation
    plain_block = permute(combined, FP)
    
    return plain_block

def pad_data(data):
    """PKCS#7 padding"""
    pad_len = 8 - (len(data) % 8)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def unpad_data(data):
    """Remove PKCS#7 padding"""
    pad_len = data[-1]
    return data[:-pad_len]

def des_encrypt(plaintext, key, mode='ECB'):
    """DES encryption"""
    # Validate key length (8 bytes for DES)
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes (64 bits)")
    
    # Generate round keys
    round_keys = generate_keys(key)
    
    # Convert plaintext to bytes if it's a string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Pad the data
    plaintext = pad_data(plaintext)
    
    # Encrypt block by block
    ciphertext = []
    
    if mode == 'ECB':
        # Electronic Codebook mode (basic mode)
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8]
            block_bits = str_to_bit_array(block)
            encrypted_bits = des_encrypt_block(block_bits, round_keys)
            ciphertext.extend(encrypted_bits)
    
    elif mode == 'CBC':
        # Cipher Block Chaining mode (more secure)
        iv = b'\x00' * 8  # Initialization Vector
        previous = str_to_bit_array(iv)
        
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8]
            block_bits = str_to_bit_array(block)
            
            # XOR with previous ciphertext (or IV for first block)
            xored_bits = xor(block_bits, previous)
            
            # Encrypt
            encrypted_bits = des_encrypt_block(xored_bits, round_keys)
            ciphertext.extend(encrypted_bits)
            previous = encrypted_bits
    
    else:
        raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'")
    
    # Convert to bytes
    result_bytes = []
    for i in range(0, len(ciphertext), 8):
        byte_bits = ciphertext[i:i+8]
        byte_val = int(''.join(str(bit) for bit in byte_bits), 2)
        result_bytes.append(byte_val)
    
    return bytes(result_bytes)

def des_decrypt(ciphertext, key, mode='ECB'):
    """DES decryption"""
    # Validate key length
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes (64 bits)")
    
    # Generate round keys
    round_keys = generate_keys(key)
    
    # Decrypt block by block
    plaintext_bits = []
    
    if mode == 'ECB':
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            block_bits = str_to_bit_array(block)
            decrypted_bits = des_decrypt_block(block_bits, round_keys)
            plaintext_bits.extend(decrypted_bits)
    
    elif mode == 'CBC':
        iv = b'\x00' * 8  # Same IV as encryption
        previous = str_to_bit_array(iv)
        
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            block_bits = str_to_bit_array(block)
            
            # Decrypt
            decrypted_bits = des_decrypt_block(block_bits, round_keys)
            
            # XOR with previous ciphertext (or IV for first block)
            xored_bits = xor(decrypted_bits, previous)
            plaintext_bits.extend(xored_bits)
            previous = block_bits
    
    else:
        raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'")
    
    # Convert to bytes
    result_bytes = []
    for i in range(0, len(plaintext_bits), 8):
        byte_bits = plaintext_bits[i:i+8]
        byte_val = int(''.join(str(bit) for bit in byte_bits), 2)
        result_bytes.append(byte_val)
    
    result_bytes = bytes(result_bytes)
    
    # Remove padding
    return unpad_data(result_bytes)

# Example usage and testing
def test_des():
    """Test the DES implementation"""
    print("DES Encryption/Decryption Test")
    print("=" * 40)
    
    # Test key and plaintext
    key = b'8bytekey'  # 8 bytes key
    plaintext = "Hello DES! This is a test message."
    
    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")
    print()
    
    # Test ECB mode
    print("ECB Mode:")
    ciphertext_ecb = des_encrypt(plaintext, key, mode='ECB')
    print(f"Ciphertext (hex): {ciphertext_ecb.hex()}")
    
    decrypted_ecb = des_decrypt(ciphertext_ecb, key, mode='ECB')
    print(f"Decrypted: {decrypted_ecb.decode('utf-8')}")
    print()
    
    # Test CBC mode
    print("CBC Mode:")
    ciphertext_cbc = des_encrypt(plaintext, key, mode='CBC')
    print(f"Ciphertext (hex): {ciphertext_cbc.hex()}")
    
    decrypted_cbc = des_decrypt(ciphertext_cbc, key, mode='CBC')
    print(f"Decrypted: {decrypted_cbc.decode('utf-8')}")
    
    # Verify
    print()
    print("Verification:")
    print(f"ECB decryption matches original: {decrypted_ecb.decode('utf-8') == plaintext}")
    print(f"CBC decryption matches original: {decrypted_cbc.decode('utf-8') == plaintext}")

# Main execution
if __name__ == "__main__":
    # Run the test
    test_des()
    
    # Simple example
    print("\n" + "=" * 40)
    print("Simple Example:")
    
    key = b'8bytekey'  # 8 character key
    message = "Secret message"
    
    print(f"Message: {message}")
        
    # Encrypt
    encrypted = des_encrypt(message, key, mode='CBC')
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    # Decrypt
    decrypted = des_decrypt(encrypted, key, mode='CBC')
    print(f"Decrypted: {decrypted.decode('utf-8')}")