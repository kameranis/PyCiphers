"""Caesar Cipher

encrypt(text, offset[, factor]):
    Encrypts text using the Affine Caesar cipher

    E(x) = (factor * x + offset) % 26

    text : string
    offset : int
    factor : int

decrypt(text, offset[, factor]):
    Decrypts text using the Affine Caesar cipher

    D(x) = factor^-1 * (x - offset) % 26

    text : string
    offset : int
    factor : int
"""


import utils


class CaesarError(Exception):
    """Ceasar Exception Class"""
    def __init__(self, message):
        super(CaesarError, self).__init__(message)
        print message


def encrypt(text, offset, factor=1):
    """Encrypts text

    letter : character
    """
    if type(text) is not str:
        raise CaesarError('Can only encrypt strings.')
    offset = offset % 26
    if factor % 2 == 0 or factor % 13 == 0:
        raise CaesarError("factor value must not be divisible by 2 or 13.")
    factor = factor % 26

    def encrypt_letter(letter):
        """Encypts a sinlge letter

        letter : character
        """
        if not utils.is_letter(letter):
            raise CaesarError("`letter` must be a single English \
capital letter.")

        A = ord('A')
        return chr((factor * (ord(letter) - A) + offset) % 26 + A)

    return ''.join([encrypt_letter(letter) for letter in utils.fix_text(text)])


def decrypt(text, offset, factor=1):
    """Decrypts text

    letter : character
    """
    if type(text) is not str:
        raise CaesarError('Can only decrypt strings.')
    offset = offset % 26
    if factor % 2 == 0 or factor % 13 == 0:
        raise CaesarError("factor value must not be divisible by 2 or 13.")
    factor = factor % 26
    factor_inv = utils.modinv(factor, 26)

    def decrypt_letter(letter):
        """Decrypts a single letter

        letter : character
        """
        if not utils.is_letter(letter):
            raise CaesarError("`letter` must be a single English \
capital letter.")

        A = ord('A')
        return chr((factor_inv * (ord(letter) - A - offset)) % 26 + A)

    return ''.join([decrypt_letter(letter) for letter in utils.fix_text(text)])
