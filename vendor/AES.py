import os
from typing import List, Tuple

class AES:
    """
    Advanced Encryption Standard (AES) Implementation
    Supports 128-bit, 192-bit, and 256-bit keys
    """
    
    # AES S-box (Substitution box)
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # Inverse S-box
    INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    # Rijndael Rcon (Round Constant)
    RCON = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
        0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
    ]
    
    # MixColumns matrix
    MIX_MATRIX = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]
    
    # Inverse MixColumns matrix
    INV_MIX_MATRIX = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ]
    
    def __init__(self, key: bytes):
        """
        Initialize AES with a key
        
        Args:
            key: AES key (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256)
        """
        self.key = key
        self.key_size = len(key)  # 16, 24, or 32 bytes
        self.n_rounds = {16: 10, 24: 12, 32: 14}[self.key_size]
        self.round_keys = self._key_expansion()
    
    @staticmethod
    def _pad(data: bytes) -> bytes:
        """PKCS#7 padding"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove PKCS#7 padding"""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")
        return data[:-pad_len]
    
    @staticmethod
    def _bytes_to_matrix(text: bytes) -> List[List[int]]:
        """Convert 16 bytes to a 4x4 matrix (column-major order)"""
        if len(text) != 16:
            raise ValueError("Input must be 16 bytes")
        
        matrix = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                matrix[j][i] = text[i * 4 + j]
        return matrix
    
    @staticmethod
    def _matrix_to_bytes(matrix: List[List[int]]) -> bytes:
        """Convert a 4x4 matrix to 16 bytes"""
        bytes_array = bytearray(16)
        for i in range(4):
            for j in range(4):
                bytes_array[i * 4 + j] = matrix[j][i]
        return bytes(bytes_array)
    
    def _sub_bytes(self, state: List[List[int]], inverse: bool = False) -> None:
        """Substitute bytes using S-box"""
        sbox = self.INV_SBOX if inverse else self.SBOX
        for i in range(4):
            for j in range(4):
                state[i][j] = sbox[state[i][j]]
    
    @staticmethod
    def _shift_rows(state: List[List[int]], inverse: bool = False) -> None:
        """Shift rows of the state matrix"""
        if inverse:
            # Inverse shift rows
            # Row 0: no shift
            # Row 1: right shift by 1
            state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
            # Row 2: right shift by 2
            state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
            # Row 3: right shift by 3
            state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
        else:
            # Forward shift rows
            # Row 0: no shift
            # Row 1: left shift by 1
            state[1] = state[1][1:] + state[1][:1]
            # Row 2: left shift by 2
            state[2] = state[2][2:] + state[2][:2]
            # Row 3: left shift by 3
            state[3] = state[3][3:] + state[3][:3]
    
    @staticmethod
    def _gf_multiply(a: int, b: int) -> int:
        """Multiplication in GF(2^8)"""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1B  # AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return result
    
    def _mix_columns(self, state: List[List[int]], inverse: bool = False) -> None:
        """Mix columns transformation"""
        matrix = self.INV_MIX_MATRIX if inverse else self.MIX_MATRIX
        new_state = [[0] * 4 for _ in range(4)]
        
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    new_state[i][j] ^= self._gf_multiply(matrix[i][k], state[k][j])
                new_state[i][j] &= 0xFF
        
        for i in range(4):
            state[i] = new_state[i][:]
    
    def _add_round_key(self, state: List[List[int]], round_key: List[List[int]]) -> None:
        """Add round key to state"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
    
    def _key_expansion(self) -> List[List[List[int]]]:
        """Expand the key into round keys"""
        # Key schedule constants
        n = self.key_size  # Key length in bytes
        r = self.n_rounds  # Number of rounds
        
        # Convert key to 4-byte words
        key_words = [self.key[i:i+4] for i in range(0, n, 4)]
        
        # Number of 32-bit words in the key
        nk = n // 4
        
        # Generate round keys
        round_keys = []
        
        for i in range(4 * (r + 1)):
            if i < nk:
                word = list(key_words[i])
            else:
                temp = round_keys[i-1][:]
                
                if i % nk == 0:
                    # Rotate word
                    temp = temp[1:] + temp[:1]
                    
                    # Substitute bytes
                    temp = [self.SBOX[b] for b in temp]
                    
                    # XOR with Rcon
                    temp[0] ^= self.RCON[i // nk - 1]
                elif nk > 6 and i % nk == 4:
                    # Substitute bytes for 256-bit key
                    temp = [self.SBOX[b] for b in temp]
                
                # XOR with word nk positions back
                word = [round_keys[i-nk][j] ^ temp[j] for j in range(4)]
            
            round_keys.append(word)
        
        # Convert to 4x4 matrices
        round_key_matrices = []
        for i in range(0, len(round_keys), 4):
            matrix = [[0] * 4 for _ in range(4)]
            for j in range(4):
                for k in range(4):
                    matrix[k][j] = round_keys[i + j][k]
            round_key_matrices.append(matrix)
        
        return round_key_matrices
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single 16-byte block"""
        if len(plaintext) != 16:
            raise ValueError("Block must be 16 bytes")
        
        # Convert to state matrix
        state = self._bytes_to_matrix(plaintext)
        
        # Initial round
        self._add_round_key(state, self.round_keys[0])
        
        # Main rounds
        for round_num in range(1, self.n_rounds):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round_num])
        
        # Final round (no MixColumns)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[self.n_rounds])
        
        # Convert back to bytes
        return self._matrix_to_bytes(state)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single 16-byte block"""
        if len(ciphertext) != 16:
            raise ValueError("Block must be 16 bytes")
        
        # Convert to state matrix
        state = self._bytes_to_matrix(ciphertext)
        
        # Initial round (inverse)
        self._add_round_key(state, self.round_keys[self.n_rounds])
        
        # Main rounds (inverse)
        for round_num in range(self.n_rounds - 1, 0, -1):
            self._shift_rows(state, inverse=True)
            self._sub_bytes(state, inverse=True)
            self._add_round_key(state, self.round_keys[round_num])
            self._mix_columns(state, inverse=True)
        
        # Final round (inverse)
        self._shift_rows(state, inverse=True)
        self._sub_bytes(state, inverse=True)
        self._add_round_key(state, self.round_keys[0])
        
        # Convert back to bytes
        return self._matrix_to_bytes(state)
    
    def encrypt(self, plaintext: bytes, mode: str = 'ECB', iv: bytes = None) -> bytes:
        """
        Encrypt data using AES
        
        Args:
            plaintext: Data to encrypt
            mode: Encryption mode ('ECB', 'CBC', 'CTR')
            iv: Initialization vector (required for CBC and CTR modes)
            
        Returns:
            Encrypted ciphertext
        """
        if mode not in ['ECB', 'CBC', 'CTR']:
            raise ValueError("Mode must be 'ECB', 'CBC', or 'CTR'")
        
        if mode in ['CBC', 'CTR'] and iv is None:
            raise ValueError(f"IV is required for {mode} mode")
        
        if mode in ['CBC', 'CTR'] and len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        
        # Pad the plaintext
        padded_data = self._pad(plaintext)
        ciphertext = bytearray()
        
        if mode == 'ECB':
            # Electronic Codebook mode
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                encrypted_block = self.encrypt_block(block)
                ciphertext.extend(encrypted_block)
        
        elif mode == 'CBC':
            # Cipher Block Chaining mode
            previous_block = iv
            
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                
                # XOR with previous ciphertext block (or IV for first block)
                xored_block = bytes([a ^ b for a, b in zip(block, previous_block)])
                
                # Encrypt
                encrypted_block = self.encrypt_block(xored_block)
                ciphertext.extend(encrypted_block)
                
                # Update previous block
                previous_block = encrypted_block
        
        elif mode == 'CTR':
            # Counter mode
            counter = int.from_bytes(iv, 'big')
            
            for i in range(0, len(plaintext), 16):
                # Encrypt the counter
                counter_block = counter.to_bytes(16, 'big')
                encrypted_counter = self.encrypt_block(counter_block)
                
                # XOR with plaintext block
                block = plaintext[i:i+16]
                encrypted_block = bytes([a ^ b for a, b in zip(block, encrypted_counter[:len(block)])])
                ciphertext.extend(encrypted_block)
                
                # Increment counter
                counter = (counter + 1) & ((1 << 128) - 1)
            
            # No padding needed for CTR mode
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes, mode: str = 'ECB', iv: bytes = None) -> bytes:
        """
        Decrypt data using AES
        
        Args:
            ciphertext: Data to decrypt
            mode: Decryption mode ('ECB', 'CBC', 'CTR')
            iv: Initialization vector (required for CBC and CTR modes)
            
        Returns:
            Decrypted plaintext
        """
        if mode not in ['ECB', 'CBC', 'CTR']:
            raise ValueError("Mode must be 'ECB', 'CBC', or 'CTR'")
        
        if mode in ['CBC', 'CTR'] and iv is None:
            raise ValueError(f"IV is required for {mode} mode")
        
        if mode in ['CBC', 'CTR'] and len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        
        plaintext = bytearray()
        
        if mode == 'ECB':
            # Electronic Codebook mode
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                decrypted_block = self.decrypt_block(block)
                plaintext.extend(decrypted_block)
            
            # Remove padding
            plaintext = self._unpad(bytes(plaintext))
        
        elif mode == 'CBC':
            # Cipher Block Chaining mode
            previous_block = iv
            
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                
                # Decrypt
                decrypted_block = self.decrypt_block(block)
                
                # XOR with previous ciphertext block (or IV for first block)
                xored_block = bytes([a ^ b for a, b in zip(decrypted_block, previous_block)])
                plaintext.extend(xored_block)
                
                # Update previous block
                previous_block = block
            
            # Remove padding
            plaintext = self._unpad(bytes(plaintext))
        
        elif mode == 'CTR':
            # Counter mode (symmetric with encryption)
            counter = int.from_bytes(iv, 'big')
            
            for i in range(0, len(ciphertext), 16):
                # Encrypt the counter
                counter_block = counter.to_bytes(16, 'big')
                encrypted_counter = self.encrypt_block(counter_block)
                
                # XOR with ciphertext block
                block = ciphertext[i:i+16]
                decrypted_block = bytes([a ^ b for a, b in zip(block, encrypted_counter[:len(block)])])
                plaintext.extend(decrypted_block)
                
                # Increment counter
                counter = (counter + 1) & ((1 << 128) - 1)
            
            # No padding in CTR mode
        
        return bytes(plaintext)


# Utility functions
def generate_key(key_size: int = 256) -> bytes:
    """Generate a random AES key"""
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    
    return os.urandom(key_size // 8)

def generate_iv() -> bytes:
    """Generate a random initialization vector"""
    return os.urandom(16)


# Example usage and testing
def test_aes():
    """Test the AES implementation"""
    print("AES Encryption/Decryption Test")
    print("=" * 50)
    
    # Test with different key sizes
    test_cases = [
        ("AES-128", generate_key(128)),
        ("AES-192", generate_key(192)),
        ("AES-256", generate_key(256))
    ]
    
    plaintext = b"Hello AES! This is a test message for AES encryption."
    
    for name, key in test_cases:
        print(f"\n{name}:")
        print(f"Key: {key.hex()}")
        print(f"Plaintext: {plaintext}")
        
        # Test ECB mode
        aes = AES(key)
        ciphertext_ecb = aes.encrypt(plaintext, mode='ECB')
        decrypted_ecb = aes.decrypt(ciphertext_ecb, mode='ECB')
        print(f"\nECB Mode:")
        print(f"Ciphertext (first 32 chars): {ciphertext_ecb[:32].hex()}...")
        print(f"Decrypted matches: {decrypted_ecb == plaintext}")
        
        # Test CBC mode
        iv = generate_iv()
        ciphertext_cbc = aes.encrypt(plaintext, mode='CBC', iv=iv)
        decrypted_cbc = aes.decrypt(ciphertext_cbc, mode='CBC', iv=iv)
        print(f"\nCBC Mode:")
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext (first 32 chars): {ciphertext_cbc[:32].hex()}...")
        print(f"Decrypted matches: {decrypted_cbc == plaintext}")
        
        # Test CTR mode
        ciphertext_ctr = aes.encrypt(plaintext, mode='CTR', iv=iv)
        decrypted_ctr = aes.decrypt(ciphertext_ctr, mode='CTR', iv=iv)
        print(f"\nCTR Mode:")
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext (first 32 chars): {ciphertext_ctr[:32].hex()}...")
        print(f"Decrypted matches: {decrypted_ctr == plaintext}")


def example_usage():
    """Simple example of using AES"""
    print("\n" + "=" * 50)
    print("Simple Example:")
    
    # Generate a random 256-bit key
    key = generate_key(256)
    print(f"AES-256 Key: {key.hex()}")
    
    # Create AES instance
    aes = AES(key)
    
    # Message to encrypt
    message = b"Secret message that needs encryption!"
    print(f"Original message: {message.decode()}")
    
    # Generate IV for CBC mode
    iv = generate_iv()
    print(f"IV: {iv.hex()}")
    
    # Encrypt
    encrypted = aes.encrypt(message, mode='CBC', iv=iv)
    print(f"Encrypted: {encrypted.hex()[:32]}...")
    
    # Decrypt
    decrypted = aes.decrypt(encrypted, mode='CBC', iv=iv)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Verify
    print(f"Decryption successful: {decrypted == message}")


# Performance test
def performance_test():
    """Test encryption/decryption performance"""
    print("\n" + "=" * 50)
    print("Performance Test:")
    
    import time
    
    # Generate test data (1 MB)
    test_data = os.urandom(1024 * 1024)  # 1 MB
    key = generate_key(256)
    iv = generate_iv()
    
    aes = AES(key)
    
    # Time encryption
    start = time.time()
    encrypted = aes.encrypt(test_data, mode='CBC', iv=iv)
    encrypt_time = time.time() - start
    
    # Time decryption
    start = time.time()
    decrypted = aes.decrypt(encrypted, mode='CBC', iv=iv)
    decrypt_time = time.time() - start
    
    print(f"Data size: {len(test_data) / 1024:.2f} KB")
    print(f"Encryption time: {encrypt_time:.4f} seconds")
    print(f"Decryption time: {decrypt_time:.4f} seconds")
    print(f"Throughput: {len(test_data) / encrypt_time / 1024 / 1024:.2f} MB/s")
    print(f"Verification: {decrypted == test_data}")


# File encryption example
def encrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC'):
    """Encrypt a file using AES"""
    iv = generate_iv()
    aes = AES(key)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted = aes.encrypt(data, mode=mode, iv=iv)
    
    # Write IV followed by encrypted data
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(encrypted)
    
    print(f"File encrypted: {input_file} -> {output_file}")
    print(f"IV stored with file: {iv.hex()}")

def decrypt_file(input_file: str, output_file: str, key: bytes, mode: str = 'CBC'):
    """Decrypt a file using AES"""
    aes = AES(key)
    
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()
    
    decrypted = aes.decrypt(encrypted, mode=mode, iv=iv)
    
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    
    print(f"File decrypted: {input_file} -> {output_file}")


if __name__ == "__main__":
    # Run tests
    test_aes()
    example_usage()
    performance_test()
    
    # Example of file encryption (uncomment to use)
    # key = generate_key(256)
    # encrypt_file("test.txt", "test.enc", key)
    # decrypt_file("test.enc", "test_decrypted.txt", key)