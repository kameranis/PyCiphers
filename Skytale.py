"""Skytale Cipher

encrypt(text, size):
    Encrypts text using the Scytale cipher

    text : string
    size : int < len(text)

decrypt(text, size):
    Decrypts text using the Scytale cipher

    text : string
    size : int < len(text)
"""


import utils
import numpy as np
import math


class SkytaleError(Exception):
    """Skytale Exception Class"""
    def __init__(self, message):
        super(SkytaleError, self).__init__(message)
        print message


def encrypt(text, size):
    """Encrypts text using the Scytale cipher

    text : string
    size : int < len(text)
    """
    if type(text) is not str:
        raise SkytaleError('Can only encrypt strings.')
    if type(size) is not int:
        raise SkytaleError('size must be int.')
    if not size < len(text):
        raise SkytaleError("the size of each collumn must be less than the \
length of the text to be encrypted")

    text = utils.fix_text(text)
    width = int(math.ceil(len(text) / float(size)))
    skytale = np.array(['0'] * width * size).reshape(size, width)
    for i, letter in enumerate(text):
        skytale[i % size, i / size] = letter

    skytale.flatten()
    cipher_text = ''.join(str(skytale))
    cipher_text = utils.fix_text(cipher_text)
    return cipher_text


def decrypt(text, size):
    """Decrypts text using the Scytale cipher

    text : string
    size : int < len(text)
    """
    if type(text) is not str:
        raise SkytaleError('Can only decrypt strings.')
    if type(size) is not int:
        raise SkytaleError('size must be int.')
    if not size < len(text):
        raise SkytaleError("the size of each collumn must be less than the \
length of the text to be encrypted")

    text = utils.fix_text(text)
    width = int(math.ceil(len(text) / size))
    skytale = np.array(['0'] * width * size).reshape(width, size)
    for i, letter in enumerate(text):
        skytale[i % width, i / width] = letter

    skytale.flatten()
    plain_text = ''.join(str(skytale))
    plain_text = utils.fix_text(plain_text)
    return plain_text
