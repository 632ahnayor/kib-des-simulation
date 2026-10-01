"""
test_des.py
Test suite for the manual DES-CBC implementation in des.py (section 2.9).

Covers:
  - Bit utility round-trips
  - Key schedule sanity checks
  - Single-block encrypt/decrypt against the classic published DES test vector
  - PKCS#7 padding edge cases
  - End-to-end CBC round-trip for various message lengths
  - Negative cases: wrong key, tampered ciphertext
"""

import unittest

from des import (
    bytes_to_bits, bits_to_bytes, permute, xor, left_rotate,
    generate_subkeys, encrypt_block, decrypt_block,
    pad, unpad, des_encrypt, des_decrypt, cbc_encrypt,
    IP, IP_INV,
)


class TestBitUtilities(unittest.TestCase):
    def test_bytes_bits_roundtrip(self):
        data = b"\x00\xff\x0f\xf0\xab\xcd"
        self.assertEqual(bits_to_bytes(bytes_to_bits(data)), data)

    def test_ip_and_ip_inv_are_true_inverses(self):
        bits = bytes_to_bits(b"\x01\x23\x45\x67\x89\xab\xcd\xef")
        self.assertEqual(permute(permute(bits, IP), IP_INV), bits)

    def test_xor_is_its_own_inverse(self):
        a = [1, 0, 1, 1, 0]
        b = [0, 1, 1, 0, 1]
        self.assertEqual(xor(xor(a, b), b), a)

    def test_left_rotate(self):
        self.assertEqual(left_rotate([1, 2, 3, 4, 5], 2), [3, 4, 5, 1, 2])
        self.assertEqual(left_rotate([1, 2, 3, 4, 5], 5), [1, 2, 3, 4, 5])


class TestKeySchedule(unittest.TestCase):
    def test_subkey_count_and_length(self):
        key = bytes.fromhex("133457799BBCDFF1")
        subkeys = generate_subkeys(key)
        self.assertEqual(len(subkeys), 16)
        for sk in subkeys:
            self.assertEqual(len(sk), 48)

    def test_rejects_wrong_length_key(self):
        with self.assertRaises(ValueError):
            generate_subkeys(b"short")  # 5 bytes, not 8


class TestSingleBlock(unittest.TestCase):
    def test_published_des_test_vector(self):
        # Well-known DES test vector (e.g. Stallings, "Cryptography and
        # Network Security"): confirms the implementation matches the
        # official specification bit-for-bit.
        key = bytes.fromhex("133457799BBCDFF1")
        plaintext = bytes.fromhex("0123456789ABCDEF")
        expected_ciphertext = bytes.fromhex("85E813540F0AB405")

        subkeys = generate_subkeys(key)
        ciphertext = encrypt_block(plaintext, subkeys)
        self.assertEqual(ciphertext, expected_ciphertext)

        decrypted = decrypt_block(ciphertext, subkeys)
        self.assertEqual(decrypted, plaintext)

    def test_block_roundtrip_arbitrary_key(self):
        key = bytes.fromhex("0E329232EA6D0D73")
        subkeys = generate_subkeys(key)
        block = b"ABCDEFGH"
        self.assertEqual(decrypt_block(encrypt_block(block, subkeys), subkeys), block)


class TestPadding(unittest.TestCase):
    def test_pad_unpad_roundtrip(self):
        for length in [0, 1, 7, 8, 9, 15, 16, 20]:
            data = bytes(range(length))
            self.assertEqual(unpad(pad(data)), data)

    def test_full_extra_block_added_when_already_aligned(self):
        data = b"12345678"  # exactly 8 bytes already
        self.assertEqual(len(pad(data)), 16)

    def test_unpad_rejects_corrupted_padding(self):
        corrupted = pad(b"hello")[:-1] + bytes([0x99])
        with self.assertRaises(ValueError):
            unpad(corrupted)


class TestCBCEndToEnd(unittest.TestCase):
    def setUp(self):
        self.key = bytes.fromhex("133457799BBCDFF1")

    def test_roundtrip_various_message_lengths(self):
        messages = [
            b"",
            b"A",
            b"12345678",                                           # exactly one block
            b"This is a longer message spanning multiple blocks.",
        ]
        for msg in messages:
            with self.subTest(msg=msg):
                self.assertEqual(des_decrypt(des_encrypt(msg, self.key), self.key), msg)

    def test_random_iv_gives_different_ciphertext_each_time(self):
        msg = b"repeat me"
        ct1 = des_encrypt(msg, self.key)
        ct2 = des_encrypt(msg, self.key)
        self.assertNotEqual(ct1, ct2)  # different random IV each call

    def test_fixed_iv_is_reproducible(self):
        msg = b"deterministic test"
        iv = bytes(range(8))
        self.assertEqual(
            cbc_encrypt(msg, self.key, iv=iv),
            cbc_encrypt(msg, self.key, iv=iv),
        )

    def test_wrong_key_fails_to_recover_plaintext(self):
        msg = b"a secret message"
        ct = des_encrypt(msg, self.key)
        wrong_key = bytes.fromhex("0000000000000000")
        try:
            recovered = des_decrypt(ct, wrong_key)
            # if it didn't raise, it must NOT have recovered the real message
            self.assertNotEqual(recovered, msg)
        except ValueError:
            pass  # padding validation correctly rejected the garbage

    def test_tampered_ciphertext_is_caught_or_garbled(self):
        msg = b"integrity check please"
        ct = bytearray(des_encrypt(msg, self.key))
        ct[-1] ^= 0xFF  # flip bits in the last transmitted byte
        try:
            recovered = des_decrypt(bytes(ct), self.key)
            self.assertNotEqual(recovered, msg)
        except ValueError:
            pass  # padding check caught the tampering


if __name__ == "__main__":
    unittest.main(verbosity=2)