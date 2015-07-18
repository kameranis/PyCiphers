"""Title:       PyCiphers
Version:        1.0
Date:           2015-07-13
Description:    A Python implementation of various classic ciphers.
Author:         Konstantinos Ameranis
Licensing:      MIT Licence
"""


import re
import utils


class CipherError(Exception):
    """Cipher Error:
    Base Error for the PyCipher Library
    """
    def __init__(self, message):
        super(CipherError, self).__init__(message)
        print message


class Cipher(object):
    """Base Class for ciphers"""
    def __init__(self):
        """Initializes Cipher Class"""
        raise NotImplementedError

    def encrypt(self, text):
        """Encrypts text
        Input: text as a stringi
        """
        raise NotImplementedError

    def decrypt(self, text):
        """Decrypts text
        This is a dummy method"""
        raise NotImplementedError


class CaesarError(CipherError):
    """Ceasar Exception Class"""
    def __init__(self, message):
        super(CaesarError, self).__init__(message)


class Caesar(Cipher):
    """Caesar Cipher Class

    Public Api:
        Caesar(b, a)
        set_parameters(**kwargs)
        encrypt(text)
        decrypt(text)
    """
    def __init__(self, offset, factor=1):
        """Each letter is encrypted to (factor * L + offset) % 26

        offset : int
        factor : int
        In the classic caesar cipher, a is set to 1
        """
        self.offset = offset % 26
        if factor % 2 == 0 or factor % 13 == 0:
            raise CaesarError("factor value must not be divisible by 2 or 13.")
        self.factor = factor % 26
        self.factor_inv = utils.modinv(factor, 26)

    def encrypt(self, text):
        """Encrypts text

        letter : character
        """
        def encrypt_letter(letter):
            """Encypts a sinlge letter

            letter : character
            """
            if len(letter) != 1:
                raise CaesarError("Only a sigle character must be given.")
            if not ord('A') <= ord(letter) <= ord('Z'):
                raise CaesarError("""`letter` must be a capital letter.
""" + letter + " is not a capital letter.")

            A = ord('A')
            return chr((self.factor *
                        (ord(letter) - A) + self.offset) % 26 + A)

        return ''.join([encrypt_letter(letter)
                        for letter in utils.fix_text(text)])

    def decrypt(self, text):
        """Decrypts text

        letter : character
        """
        def decrypt_letter(letter):
            """Decrypts a single letter

            letter : character
            """
            if len(letter) != 1:
                raise CaesarError("Only a sigle character must be given.")
            if not ord('A') <= ord(letter) <= ord('Z'):
                raise CaesarError("`letter` must be a capital letter.")

            A = ord('A')
            return chr((self.factor_inv *
                        (ord(letter) - A - self.offset)) % 26 + A)

        return ''.join([decrypt_letter(letter)
                        for letter in utils.fix_text(text)])


class VigenereError(CipherError):
    """Vigenere Exception Class"""
    def __init__(self, message):
        super(VigenereError, self).__init__(message)


class Vigenere(Cipher):
    """Vigenere cipher class
    Public Api:
        set_parameters(**kwargs): sets password
        encrypt(text)
        decrypt(text)
    """
    def __init__(self, password):
        """Vigenere Cipher

        password : string
        Non-Alpha characters are ignored
        Case insensitive
        """
        self.password = utils.fix_text(password)
        self.encryption_table = [
            Caesar(ord(i) - ord('A')) for i in self.password]

    def encrypt(self, text):
        """Encrypts text

        text : string
        """
        length = len(self.encryption_table)

        def encrypt_letter(letter, index):
            """Encrypts a single letter relative to its position

            letter : single character
            index : integer between 0 and length
            """
            if len(letter) != 1:
                raise CaesarError("Only a sigle character must be given.")
            if not ord('A') <= letter <= ord('Z'):
                raise CaesarError("`letter` must be a capital letter.")

            return self.encryption_table[index % length].encrypt(letter)

        return [encrypt_letter(letter, index) for
                index, letter in enumerate(utils.fix_text(text))]

    def decrypt(self, text):
        """Decrypts text

        text : string
        """
        length = len(self.encryption_table)

        def decrypt_letter(letter, index):
            """Encrypts a single letter relative to its position

            letter : single character
            index : integer between 0 and length
            """
            if len(letter) != 1:
                raise CaesarError("Only a sigle character must be given.")
            if not ord('A') <= letter <= ord('Z'):
                raise CaesarError("`letter` must be a capital letter.")

            return self.encryption_table[index % length].decrypt(letter)

        return [decrypt_letter(letter, index) for
                index, letter in enumerate(utils.fix_text(text))]


class PlayfairError(CipherError):
    """Playfair Exception Class"""
    def __init__(self, message):
        super(PlayfairError, self).__init__(message)


class Playfair(Cipher):
    """Playfair Cipher Class
    Public Api:
        Playfair(password[, ommision_rule, double_padding, end_padding])
        set_paramaters(**kwargs)
        encrypt(text)
        decrypt(text)
    """
    omission_rules = [
        'Merge J into I',
        'Omit Q',
        'Merge I into J',
    ]

    def __init__(self, password, omission_rule=0, double_padding='X',
                 end_padding='Z'):
        """omission_rule determines which omission rule you want to use.
        See the list at the beginning of the constructor

        double_padding determines what letter you would like to use to pad
        a digraph that is double letters

        end_padding determines what letter you would like to use to pad
        the end of an text containing an odd number of letters
        """
        if omission_rule >= 0 and omission_rule < len(self.omission_rules):
            self.omission_rule = omission_rule
        else:
            raise PlayfairError('omission_rule values must be \
between 0 and ' + (len(self.omission_rules) - 1) + '.')
        self.password = utils.fix_text(password)
        self.grid = self._generate_grid()
        self.double_padding = self._check_padding(double_padding, 'double')
        self.end_padding = self._check_padding(end_padding, 'end')

    def _check_padding(self, padding, which_pad):
        """Makes sure the text for the padding character is valid

        padding : character
        which_pad : str used for debugging reasons"""
        if len(padding) != 1:
            raise PlayfairError('The ' + which_pad + ' padding \
must be a single character.')
        elif not padding.isalpha():
            raise PlayfairError('The ' + which_pad + ' padding must \
be a letter of the alphabet.')
        padding = padding.upper()
        if padding not in self.grid:
            raise PlayfairError('The ' + which_pad + ' padding character \
must not be omitted by the omission rule.')
        return padding

    def _convert_letter(self, letter):
        """returns None if the letter should be discarded,
        else returns the converted letter"""
        if self.omission_rule == 0:
            if letter == 'J':
                letter = 'I'
            return letter
        elif self.omission_rule == 1:
            if letter == 'Q':
                letter = None
            return letter
        elif self.omission_rule == 2:
            if letter == 'I':
                letter = 'J'
            return letter
        else:
            raise PlayfairError('The omission rule provided has not \
been configured properly.')

    def _get_alphabet(self):
        """Returns the alphabet used by the cipher
        (takes into account the omission rule)"""
        full_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        alphabet = ''

        for letter in full_alphabet:
            letter = self._convert_letter(letter)
            if letter is not None and letter not in alphabet:
                alphabet += letter

        return alphabet

    def _generate_grid(self):
        """Generates the 25 character grid based on the omission rule
        and the given password
        """
        grid = ''
        alphabet = self._get_alphabet()

        for letter in self.password:
            if letter not in grid and letter in alphabet:
                grid += letter

        for letter in alphabet:
            if letter not in grid:
                grid += letter

        return grid

    def _generate_digraphs(self, text):
        """Splits the text `text` into digraphs

        text : str
        """
        text = re.sub('[^A-Z]', '', text.upper())
        text_fixed = ''

        for i in text:
            letter = self._convert_letter(i)
            if letter is not None:
                text_fixed += letter

        counter = 0
        while counter < len(text_fixed):
            if counter + 1 == len(text_fixed):
                # we have reached the end of the text_fixed
                yield text_fixed[counter] + self.end_padding
                break
            elif text_fixed[counter] != text_fixed[counter + 1]:
                # we just need to create a normal digraph
                yield text_fixed[counter] + text_fixed[counter + 1]
                counter += 2
            else:
                # we have a double letter digraph, so we add the double padding
                yield text_fixed[counter] + self.double_padding
                counter += 1

    def _encrypt_digraph(self, text):
        """encrypts a digraph using the defined grid"""
        if len(text) != 2:
            raise PlayfairError('The digraph to be encrypted must \
be exactly 2 characters long.')
        elif not text.isupper():
            raise PlayfairError('The digraph to be encrypted must contain \
only uppercase letters of the alphabet.')

        fir_letter = text[0]
        sec_letter = text[1]

        fir_letter_pos = self.grid.find(fir_letter)
        sec_letter_pos = self.grid.find(sec_letter)

        fir_letter_coords = (fir_letter_pos % 5, fir_letter_pos / 5)
        sec_letter_coords = (sec_letter_pos % 5, sec_letter_pos / 5)

        if fir_letter_coords[0] == sec_letter_coords[0]:
            # letters are in the same column
            fir_encrypted = self.grid[
                (fir_letter_coords[1] + 1) % 5 * 5 + fir_letter_coords[0]]
            sec_encrypted = self.grid[
                (sec_letter_coords[1] + 1) % 5 * 5 + sec_letter_coords[0]]

        elif fir_letter_coords[1] == sec_letter_coords[1]:
            # letters are in the same row
            fir_encrypted = self.grid[
                fir_letter_coords[1] * 5 + (fir_letter_coords[0] + 1) % 5]
            sec_encrypted = self.grid[
                sec_letter_coords[1] * 5 + (sec_letter_coords[0] + 1) % 5]
        else:
            # letters are not in the same row or column
            fir_encrypted = self.grid[
                fir_letter_coords[1] * 5 + sec_letter_coords[0]]
            sec_encrypted = self.grid[
                sec_letter_coords[1] * 5 + fir_letter_coords[0]]

        return fir_encrypted + sec_encrypted

    def _decrypt_digraph(self, text):
        """decrypts a digraph using the defined grid"""
        if len(text) != 2:
            raise PlayfairError('The digraph to be encrypted \
must be exactly 2 characters long.')
        elif not text.isupper():
            raise PlayfairError('The digraph to be encrypted must contain \
only uppercase letters of the alphabet.')

        first_encrypted = text[0]
        second_encrypted = text[1]

        first_encrypted_pos = self.grid.find(first_encrypted)
        second_encrypted_pos = self.grid.find(second_encrypted)

        first_encrypted_coords = \
            (first_encrypted_pos % 5, first_encrypted_pos / 5)
        second_encrypted_coords = \
            (second_encrypted_pos % 5, second_encrypted_pos / 5)

        if first_encrypted_coords[0] == second_encrypted_coords[0]:
            # letters are in the same column
            first_letter = self.grid[
                (first_encrypted_coords[1] - 1) % 5 * 5 +
                first_encrypted_coords[0]]
            second_letter = self.grid[
                (second_encrypted_coords[1] - 1) % 5 * 5 +
                second_encrypted_coords[0]]
        elif first_encrypted_coords[1] == second_encrypted_coords[1]:
            # letters are in the same row
            first_letter = self.grid[
                first_encrypted_coords[1] * 5 +
                (first_encrypted_coords[0] - 1) % 5]
            second_letter = self.grid[
                second_encrypted_coords[1] * 5 +
                (second_encrypted_coords[0] - 1) % 5]
        else:
            # letters are not in the same row or column
            first_letter = self.grid[
                first_encrypted_coords[1] * 5 + second_encrypted_coords[0]]
            second_letter = self.grid[
                second_encrypted_coords[1] * 5 + first_encrypted_coords[0]]

        return first_letter + second_letter

    def encrypt(self, text):
        """Encrypts text

        text : str"""
        return ''.join([self._encrypt_digraph(digraph) for digraph in
                       self._generate_digraphs(utils.fix_text(text))])

    def decrypt(self, text):
        """Decrypts text

        text : str
        """
        return ''.join([self._decrypt_digraph(digraph) for digraph in
                       self._generate_digraphs(utils.fix_text(text))])
