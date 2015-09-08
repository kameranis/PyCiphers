"""One-Time Pad cipher

encrypt(text, key):
    Encrypts text using the One-Time Pad cipher

    E(x) = Vigenere.encrypt(text, key)

    text : string
    key : string

decrypt(text, key):
    Decrypts text using the One-Time Pad cipher

    D(x) = Vigenere.decrypt(text, key)

    text : string
    key : string
"""


import utils
import Vigenere


class OneTimePadError(Exception):
    """One Time Pad Exception Class"""
    def __init__(self, message):
        super(OneTimePadError, self).__init__(message)
        print message


def encrypt(text, key):
    """Encrypts text using the One-Time Pad cipher

    E(x) = Vigenere.encrypt(text, key)

    text : string
    key : string
    """
    if type(text) is not str:
        raise OneTimePadError('Can only encrypt strings.')
    if type(key) is not str:
        raise OneTimePadError('key must be a string.')
    if len(key) < len(text):
        raise OneTimePadError('key must be at least the same length as text.')

    return Vigenere.encrypt(utils.fix_text(text), utils.fix_text(key))


def decrypt(text, key):
    """Decrypts text using the One-Time Pad cipher

    D(x) = Vigenere.decrypt(text, key)

    text : string
    key : string
    """
    if type(text) is not str:
        raise OneTimePadError('Can only encrypt strings.')
    if type(key) is not str:
        raise OneTimePadError('key must be a string.')
    if len(key) < len(text):
        raise OneTimePadError('key must be at least the same length as text.')

    return Vigenere.decrypt(utils.fix_text(text), utils.fix_text(key))
