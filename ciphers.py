"""Title:       PyCiphers
Version:        1.0
Date:           2015-07-13
Description:    A Python implementation of various classic ciphers.
Author:         Konstantinos Ameranis
Licensing:      GPLv3.0
"""


import re


class CipherError(Exception):
    """Cipher Error:
    Base Error for the PyCipher Library
    """
    def __init__(self, message):
        super(CipherError, self).__init__(message)
        print message


class Cipher(object):
    """Base Class for ciphers"""
    def __init__(self, password):
        """Initializes Cipher Class"""
        pass

    def encrypt(self, text):
        """Encrypts text
        This is a dummy method"""
        pass

    def decrypt(self, text):
        """Decrypts text
        This is a dummy method"""
        pass

    def set_parameters(self, password, **kwargs):
        """Sets parameters for each cipher
        This is a dummy method"""
        pass


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
    def __init__(self, b=0, a=1):
        """Each letter is encrypted to (b * L + a) % 26
        In the classic caesar cipher, a is set to 0
        """
        super(Caesar, self).__init__((a, b))
        self.a = None
        self.b = None
        self.a_inv = None
        self.set_parameters(b=b, a=a)

    def _extended_gcd(self, aa, bb):
        """Extended Euclidean Algorithm"""
        lastremainder, remainder = abs(aa), abs(bb)
        x, lastx, y, lasty = 0, 1, 1, 0
        while remainder:
            lastremainder, (quotient, remainder) = \
                remainder, divmod(lastremainder, remainder)
            x, lastx = lastx - quotient*x, x
            y, lasty = lasty - quotient*y, y
        return lastremainder, lastx * (-1 if aa < 0 else 1), \
            lasty * (-1 if bb < 0 else 1)

    def _modinv(self, a, m):
        """Computes the modular inverse of a mod m"""
        g, x, _ = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError
        return x % m

    def set_parameters(self, **kwargs):
        """Possible parameters: a, b"""
        for key, value in kwargs.iteritems():
            if key == 'b':
                self.b = value % 26
            elif key == 'a':
                if value % 2 == 0 or value % 13 == 0:
                    raise CaesarError("'a' value must not be \
divisible by 2 or 13")
                self.a = value % 26
                self.a_inv = self._modinv(value, 26)
            else:
                raise CaesarError('Unknown parameter ' + key + ' with value '
                                  + value)

    def encrypt(self, text):
        """Encrypts text"""
        fixed_text = re.sub('[^A-Z]', '', text.upper())
        encrypted = []
        A = ord('A')

        for letter in fixed_text:
            encrypted.append(chr((self.a * (ord(letter) - A)
                             + self.b) % 26 + A))

        return ''.join(encrypted)

    def decrypt(self, text):
        """Decrypts text"""
        fixed_text = re.sub('[^A-Z]', '', text.upper())
        decrypted = []
        A = ord('A')

        for letter in fixed_text:
            decrypted.append(chr((self.a_inv * (ord(letter) - A
                             - self.b)) % 26 + A))

        return ''.join(decrypted)


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
                 end_padding='X'):
        """omission_rule determines which omission rule you want to use
        (go figure). See the list at the beginning of the constructor
        double_padding determines what letter you would like to use to pad
        a digraph that is double letters
        end_padding determines what letter you would like to use to pad
        the end of an text containing an odd number of letters"""
        super(Playfair, self).__init__(password)

        self.password = None
        self.grid = None
        self.omission_rule = None
        self.double_padding = None
        self.end_padding = None

        self.set_parameters(
            omission_rule=omission_rule, password=password,
            double_padding=double_padding, end_padding=end_padding
            )

    def _check_padding(self, padding, which_pad):
        """make sure the text for the padding character is valid"""
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
        """returns the alphabet used by the cipher
        (takes into account the omission rule)"""
        full_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        alphabet = ''

        for letter in full_alphabet:
            letter = self._convert_letter(letter)
            if letter is not None and letter not in alphabet:
                alphabet += letter

        return alphabet

    def _generate_grid(self):
        """generates the 25 character grid based on the omission rule
        and the given password"""
        if self.password is None:
            raise PlayfairError("""No password set. Do not use this function.
Instead use set_password(password)""")
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
        """splits the text text into digraphs"""
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
        """encrypts text"""
        if self.grid is None:
            raise PlayfairError("No password has been specified")
        encrypted_digraphs = []

        for digraph in self._generate_digraphs(text):
            encrypted_digraphs.append(self._encrypt_digraph(digraph))

        return ''.join(encrypted_digraphs)

    def decrypt(self, text):
        """decrypts text"""
        if self.grid is None:
            raise PlayfairError("No password has been specified")
        decrypted_digraphs = []

        for digraph in self._generate_digraphs(text):
            decrypted_digraphs.append(self._decrypt_digraph(digraph))

        return ''.join(decrypted_digraphs)

    def set_parameters(self, **kwargs):
        """sets the parameters for upcoming encryptions and decryptions"""
        for key, value in kwargs.iteritems():
            if key == 'password':
                self.password = re.sub('[^A-Z]', '', value.upper())
                self.grid = self._generate_grid()
            elif key == 'double_padding':
                self.double_padding = self._check_padding(value, 'double')
            elif key == 'end_padding':
                self.end_padding = self._check_padding(value, 'end')
            elif key == 'omission_rule':
                if value >= 0 and value < len(self.omission_rules):
                    self.omission_rule = value
                else:
                    raise PlayfairError('omission_rule values must be \
between 0 and ' + (len(self.omission_rules) - 1))
            else:
                raise PlayfairError('Unknown parameter ' + key + ' with value '
                                    + value)
