"""Tests for PyCiphers library

Tests all ciphers in the library
First ensures that they perform a valid encryption and decryption
Then ensures that all the right Exceptions occur when methods are misscalled
"""

import unittest
import Caesar
import Vigenere
import OneTimePad as OTP
import Playfair
import Skytale


ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


class TestCaesar(unittest.TestCase):
    """Caesar cipher unittest
    """
    def test_encrypt(self):
        """Tests encrypt function for Caesar cipher"""
        self.assertEqual(
                Caesar.encrypt(ALPHABET, 10), ALPHABET[10:] + ALPHABET[:10])
        self.assertEqual(
                Caesar.encrypt(ALPHABET, 10, 5), 'KPUZEJOTYDINSXCHMRWBGLQVAF')
        with self.assertRaises(Caesar.CaesarError):
            Caesar.encrypt(5, 5)
        with self.assertRaises(Caesar.CaesarError):
            Caesar.encrypt(ALPHABET, 1, 39)
        with self.assertRaises(Caesar.CaesarError):
            Caesar.encrypt(ALPHABET, 1, 20)

    def test_decrypt(self):
        """Tests decrypt function for Caesar cipher"""
        self.assertEqual(
                Caesar.decrypt(ALPHABET[10:] + ALPHABET[:10], 10), ALPHABET)
        self.assertEqual(
                Caesar.decrypt('KPUZEJOTYDINSXCHMRWBGLQVAF', 10, 5), ALPHABET)
        with self.assertRaises(Caesar.CaesarError):
            Caesar.decrypt(5, 5)
        with self.assertRaises(Caesar.CaesarError):
            Caesar.decrypt(ALPHABET, 1, 39)
        with self.assertRaises(Caesar.CaesarError):
            Caesar.decrypt(ALPHABET, 1, 20)


class TestVigenere(unittest.TestCase):
    """Vigenere cipher unittest
    """
    def test_encrypt(self):
        """Tests encrypt function for Vigenere cipher"""
        self.assertEqual(
                Vigenere.encrypt('A' * 26, ALPHABET), ALPHABET)
        self.assertEqual(
                Vigenere.encrypt('A' * 26, ALPHABET[:13]), ALPHABET[:13] * 2)
        self.assertEqual(
                Vigenere.encrypt(ALPHABET, ALPHABET), ALPHABET[::2] * 2)
        with self.assertRaises(Vigenere.VigenereError):
            Vigenere.encrypt(5, ALPHABET)
        with self.assertRaises(Vigenere.VigenereError):
            Vigenere.encrypt(ALPHABET, range(5))


    def test_decrypt(self):
        """Tests decrypt function for Caesar cipher"""
        self.assertEqual(
                Vigenere.decrypt(ALPHABET, ALPHABET), 'A' * 26)
        self.assertEqual(
                Vigenere.decrypt(ALPHABET[:13] * 2, ALPHABET[:13]), 'A' * 26)
        self.assertEqual(
                Vigenere.decrypt(ALPHABET[::2] * 2, ALPHABET), ALPHABET)
        with self.assertRaises(Vigenere.VigenereError):
            Vigenere.decrypt(5, ALPHABET)
        with self.assertRaises(Vigenere.VigenereError):
            Vigenere.decrypt(ALPHABET, range(5))


class TestOneTimePad(unittest.TestCase):
    """One Time Pad cipher unittest
    """
    def test_encrypt(self):
        """Tests encrypt function for One Time Pad cipher"""
        self.assertEqual(
                ALPHABET, OTP.decrypt(OTP.encrypt(ALPHABET, OTP), OTP))
        with self.assertRaises(OTP.OneTimePadError):
            OTP.encrypt(521, OTP)
        with self.assertRaises(OTP.OneTimePadError):
            OTP.encrypt(ALPHABET, range(5))

    def test_decrypt(self):
        """Tests decrypt function for One Time Pad cipher"""
        self.assertEqual(
                ALPHABET, OTP.decrypt(OTP.encrypt(ALPHABET, OTP), OTP))
        with self.assertRaises(OTP.OneTimePadError):
            OTP.decrypt(521, OTP)
        with self.assertRaises(OTP.OneTimePadError):
            OTP.decrypt(ALPHABET, range(5))


class TestPlayfair(unittest.TestCase):
    """Playfair cipher unittest
    """
    def test_generate_grid(self):
        """Tests grid generation for Playfair Cipher
        """
        monarchy_grid = {
    'A': (0, 3), 'B': (1, 3), 'C': (1, 0), 'D': (1, 4), 'E': (2, 0),
    'F': (2, 1), 'G': (2, 2), 'H': (1, 1), 'I': (2, 3), 'K': (2, 4),
    'L': (3, 0), 'M': (0, 0), 'N': (0, 2), 'O': (0, 1), 'P': (3, 1),
    'Q': (3, 2), 'R': (0, 4), 'S': (3, 3), 'T': (3, 4), 'U': (4, 0),
    'V': (4, 1), 'W': (4, 2), 'X': (4, 3), 'Y': (1, 2), 'Z': (4, 4)}
        self.assertEqual(Playfair.generate_grid('monarchy')[0], monarchy_grid)
        grid, rev_grid = Playfair.generate_grid('monarchy')
        self.assertEqual([rev_grid[value] == key for key, value
                 in grid.iteritems()], [True] * 25)


    def test_encrypt(self):
        """Tests encrypt function for Playfair cipher"""
        password = 'monarchy'
        self.assertEqual(Playfair.encrypt(ALPHABET, password),
                'BIHCFGFYSAKEUCANQSATLZWXWBUZ')
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.encrypt(521, password)
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.encrypt(ALPHABET, range(5))

    def test_decrypt(self):
        """Tests decrypt function for Playfair cipher
        """
        password = 'monarchy'
        self.assertEqual(Playfair.decrypt(Playfair.encrypt(ALPHABET, password),
             password), ALPHABET[:9] + 'XI' + ALPHABET[10:] + 'X')
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.decrypt(521, password)
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.decrypt(ALPHABET, range(5))

    def test_check_padding(self):
        """Tests check_padding function for Playfair cipher
        """
        self.assertEqual(Playfair.check_padding('i', 'double'), 'I')
        self.assertEqual(Playfair.check_padding('j', 'double'), 'I')
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.check_padding(5, 'end')
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.check_padding('ab', 'end')
        with self.assertRaises(Playfair.PlayfairError):
            Playfair.check_padding('5', 'end')


class TestSkytale(unittest.TestCase):
    """Skytale cipher unittest
    """
    def test_encrypt(self):
        """Tests encrypt function for Skytale cipher
        """
        self.assertEqual(Skytale.encrypt('Help me, I am under Attack', 5),
                'HENTEIDTLAEAPMRCMUAK')
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.encrypt(42, 5)
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.encrypt('Help', 'Help')
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.encrypt('Help', 5.0)
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.encrypt('short', 5)

    def test_decrypt(self):
        """Tests encrypt function for Skytale cipher
        """
        self.assertEqual(Skytale.decrypt('HENTEIDTLAEAPMRCMUAK', 5),
                'HELPMEIAMUNDERATTACK')
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.decrypt(42, 5)
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.decrypt('Help', 'Help')
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.decrypt('Help', 5.0)
        with self.assertRaises(Skytale.SkytaleError):
            Skytale.decrypt('short', 5)


unittest.main()
