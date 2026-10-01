"""
des.py
Manual (from-scratch) implementation of the DES block cipher in CBC mode.
No cryptography libraries are used anywhere in this file, per project
requirements -- every table, permutation, substitution and XOR is done by
hand on plain Python lists of 0/1 bits.

Sections (matching the project task outline):
  2.1  Constants        - fixed DES tables
  2.2  Bit utilities    - bit-list <-> bytes conversions, generic helpers
  2.3  Key schedule     - derive 16 round subkeys from a 64-bit key
  2.4  Round function F - expansion, XOR, S-box substitution, permutation
  2.5  Block cipher     - single 64-bit block encrypt/decrypt
  2.6  Padding          - PKCS#7
  2.7  Mode of operation- CBC
  2.8  Public API       - des_encrypt / des_decrypt
"""

import os

# ============================================================
# 2.1  CONSTANTS
# ============================================================

# Initial Permutation - applied to the plaintext block before round 1
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation (Final Permutation) - applied after round 16
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table: 32 -> 48 bits (used inside the round function F)
E = [32, 1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9,  10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# P permutation (applied after the S-boxes): 32 -> 32
P = [16, 7,  20, 21,
     29, 12, 28, 17,
     1,  15, 23, 26,
     5,  18, 31, 10,
     2,  8,  24, 14,
     32, 27, 3,  9,
     19, 13, 30, 6,
     22, 11, 4,  25]

# PC-1: 64 -> 56 (drops the 8 parity bits from the raw key)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1,  58, 50, 42, 34, 26, 18,
       10, 2,  59, 51, 43, 35, 27,
       19, 11, 3,  60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7,  62, 54, 46, 38, 30, 22,
       14, 6,  61, 53, 45, 37, 29,
       21, 13, 5,  28, 20, 12, 4]

# PC-2: 56 -> 48 (produces each round's subkey)
PC2 = [14, 17, 11, 24, 1,  5,
       3,  28, 15, 6,  21, 10,
       23, 19, 12, 4,  26, 8,
       16, 7,  27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Per-round left-shift amount applied to each 28-bit key half
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# The 8 S-boxes: each is 4 rows x 16 columns, maps 6 input bits -> 4 output bits
S_BOXES = [
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
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

BLOCK_SIZE = 8  # bytes (64 bits)


# ============================================================
# 2.2  BIT-LEVEL UTILITIES
# ============================================================

def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of 0/1 ints, most-significant-bit first."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of 0/1 ints (length must be a multiple of 8) to bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("bit list length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def permute(bits: list, table: list) -> list:
    """Generic permutation/selection. `table` holds 1-indexed positions into
    `bits`. Reused for IP, IP_INV, E, P, PC1 and PC2."""
    return [bits[i - 1] for i in table]


def xor(bits_a: list, bits_b: list) -> list:
    """Bitwise XOR of two equal-length bit lists."""
    return [a ^ b for a, b in zip(bits_a, bits_b)]


def left_rotate(bits: list, n: int) -> list:
    """Circular left shift of a bit list by n positions."""
    n = n % len(bits)
    return bits[n:] + bits[:n]


# ============================================================
# 2.3  KEY SCHEDULE
# ============================================================

def generate_subkeys(key_bytes: bytes) -> list:
    """Derive the 16 round subkeys (each a 48-bit list) from a 64-bit key.
    subkeys[0] is round 1's key, subkeys[15] is round 16's key."""
    if len(key_bytes) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")

    key_bits = bytes_to_bits(key_bytes)     # 64 bits
    key_56 = permute(key_bits, PC1)          # 56 bits, parity bits dropped

    c, d = key_56[:28], key_56[28:]

    subkeys = []
    for shift in SHIFT_SCHEDULE:
        c = left_rotate(c, shift)
        d = left_rotate(d, shift)
        subkeys.append(permute(c + d, PC2))  # 56 -> 48 bits
    return subkeys


# ============================================================
# 2.4  ROUND FUNCTION F
# ============================================================

def _substitute(bits_48: list) -> list:
    """Apply the 8 S-boxes to a 48-bit input, producing 32 bits."""
    output = []
    for i in range(8):
        chunk = bits_48[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]                                   # outer 2 bits
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]  # inner 4 bits
        value = S_BOXES[i][row][col]
        output.extend([(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1])
    return output


def feistel_function(right_32: list, subkey_48: list) -> list:
    """The DES round function F: expand -> XOR with subkey -> S-boxes -> P."""
    expanded = permute(right_32, E)      # 32 -> 48
    mixed = xor(expanded, subkey_48)     # mix in the round key
    substituted = _substitute(mixed)     # 48 -> 32 via S-boxes (the non-linear step)
    return permute(substituted, P)       # final 32-bit permutation


# ============================================================
# 2.5  SINGLE-BLOCK ENCRYPT / DECRYPT
# ============================================================

def _des_block(block_bits: list, subkeys: list) -> list:
    """Run the 16-round Feistel network on one 64-bit block. Passing subkeys
    in forward order (1..16) encrypts; passing them reversed (16..1) decrypts."""
    permuted = permute(block_bits, IP)
    left, right = permuted[:32], permuted[32:]

    for subkey in subkeys:
        left, right = right, xor(left, feistel_function(right, subkey))

    pre_output = right + left  # undo the last round's swap before the final permutation
    return permute(pre_output, IP_INV)


def encrypt_block(plaintext_block: bytes, subkeys: list) -> bytes:
    """Encrypt a single 8-byte (64-bit) block."""
    if len(plaintext_block) != BLOCK_SIZE:
        raise ValueError(f"DES block must be exactly {BLOCK_SIZE} bytes")
    return bits_to_bytes(_des_block(bytes_to_bits(plaintext_block), subkeys))


def decrypt_block(ciphertext_block: bytes, subkeys: list) -> bytes:
    """Decrypt a single 8-byte (64-bit) block. Same algorithm, subkeys reversed."""
    if len(ciphertext_block) != BLOCK_SIZE:
        raise ValueError(f"DES block must be exactly {BLOCK_SIZE} bytes")
    return bits_to_bytes(_des_block(bytes_to_bits(ciphertext_block), list(reversed(subkeys))))


# ============================================================
# 2.6  PADDING (PKCS#7)
# ============================================================

def pad(data: bytes) -> bytes:
    """PKCS#7 pad `data` out to a multiple of BLOCK_SIZE bytes. If `data` is
    already block-aligned, a full extra block of padding is still added, so
    unpad() can always unambiguously tell padding apart from real data."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    """Validate and remove PKCS#7 padding. Raises ValueError on anything
    that doesn't look like well-formed padding (used as a basic tamper check)."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("invalid padding value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]


# ============================================================
# 2.7  MODE OF OPERATION: CBC
# ============================================================

def generate_iv() -> bytes:
    """Generate a fresh random 8-byte initialization vector."""
    return os.urandom(BLOCK_SIZE)


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    """CBC-mode encryption. Returns IV || ciphertext.
    `iv` can be supplied explicitly (e.g. for reproducible tests); otherwise
    a fresh random IV is generated per call."""
    if iv is None:
        iv = generate_iv()
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes")

    subkeys = generate_subkeys(key)
    padded = pad(plaintext)

    ciphertext = b""
    previous = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, previous))
        encrypted = encrypt_block(xored, subkeys)
        ciphertext += encrypted
        previous = encrypted

    return iv + ciphertext


def cbc_decrypt(iv_and_ciphertext: bytes, key: bytes) -> bytes:
    """CBC-mode decryption. Expects IV || ciphertext, as produced by cbc_encrypt."""
    if len(iv_and_ciphertext) < BLOCK_SIZE or len(iv_and_ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("invalid ciphertext length")

    iv, ciphertext = iv_and_ciphertext[:BLOCK_SIZE], iv_and_ciphertext[BLOCK_SIZE:]
    subkeys = generate_subkeys(key)

    plaintext_padded = b""
    previous = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = decrypt_block(block, subkeys)
        plaintext_padded += bytes(a ^ b for a, b in zip(decrypted, previous))
        previous = block

    return unpad(plaintext_padded)


# ============================================================
# 2.8  PUBLIC API
# ============================================================

def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt arbitrary-length plaintext with manual DES in CBC mode.
    Returns IV || ciphertext, ready to hand to the transmission layer."""
    return cbc_encrypt(plaintext, key)


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt IV || ciphertext (as produced by des_encrypt) back to the
    original plaintext."""
    return cbc_decrypt(ciphertext, key)


if __name__ == "__main__":
    # Quick manual smoke test when running this file directly
    key = bytes.fromhex("133457799BBCDFF1")
    message = b"Hello, this is a DES-CBC test message!"
    ct = des_encrypt(message, key)
    pt = des_decrypt(ct, key)
    print("Plaintext :", message)
    print("Ciphertext:", ct.hex())
    print("Decrypted :", pt)
    assert pt == message, "round-trip failed!"
    print("Round-trip OK")