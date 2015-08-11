"""Vigenere Cipher

encrypt(text, password):
    Encrypts text using the Vigenere cipher

    E(text[i]) = (text[i] + password[i]) % 26

    text : string
    password : string

decrypt(text, offset[, factor]):
    Decrypts text using the Vigenere cipher

    D(text[i]) = (text[i] - password[i]) % 26

    text : string
    password : string
"""


import utils
import Caesar


class VigenereError(Exception):
    """Vigenere Exception Class"""
    def __init__(self, message):
        super(VigenereError, self).__init__(message)
        print message


def encrypt(text, password):
    """Encrypts text using the Vigenere cipher

    E(text[i]) = (text[i] + password[i]) % 26

    text : string
    password : string
    """
    if type(text) is not str:
        raise VigenereError('Can only encrypt strings.')
    if type(password) is not str:
        raise VigenereError('Password must be a string.')

    password = utils.fix_text(password)

    length = len(password)
    A = ord('A')

    return ''.join([Caesar.encrypt(letter, ord(password[index % length])
                    - A) for index, letter in enumerate(utils.fix_text(text))])


def decrypt(text, password):
    """Decrypts text using the Vigenere cipher

    D(text[i]) = (text[i] - password[i]) % 26

    text, password : string
    """
    if type(text) is not str:
        raise VigenereError('Can only decrypt strings.')
    if type(password) is not str:
        raise VigenereError('Password must be a string.')

    password = utils.fix_text(password)

    length = len(password)
    A = ord('A')

    return ''.join([Caesar.decrypt(letter, ord(password[index % length])
                    - A) for index, letter in enumerate(utils.fix_text(text))])
