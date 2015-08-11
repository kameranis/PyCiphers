"""One-Time Pad cipher

encrypt(text, seed):
    Encrypts text using the One-Time Pad cipher

    E(x) = Caesar.encrypt(x, random) % 26

    text : string
    seed : hashable

decrypt(text, offset[, factor]):
    Decrypts text using the One-Time Pad cipher

    D(x) = Caesar.decrypt(x, random) % 26

    text : string
    seed : hashable
"""


import utils
import Caesar
import random


class OneTimePadError(Exception):
    """One Time Pad Exception Class"""
    def __init__(self, message):
        super(OneTimePadError, self).__init__(message)
        print message


def encrypt(text, seed):
    """Encrypts text using the One-Time Pad cipher

    E(x) = Caesar.encrypt(x, random)

    text : string
    seed : hashable
    """
    if type(text) is not str:
        raise OneTimePadError('Can only encrypt strings.')
    try:
        random.seed(seed)
    except TypeError:
        raise OneTimePadError('Unhashable type: ' + str(type(seed))[7:-2] +
'\nseed must be hashable.')

    return ''.join(Caesar.encrypt(letter, random.randint(0, 25))
                   for letter in utils.fix_text(text))


def decrypt(text, seed):
    """Decrypts text using the One-Time Pad cipher

    D(x) = Caesar.decrypt(x, random)

    text : string
    seed : hashable
    """
    if type(text) is not str:
        raise OneTimePadError('Can only decrypt strings.')
    try:
        random.seed(seed)
    except TypeError:
        raise OneTimePadError('Unhashable type: ' + str(type(seed))[7:-2] +
'\nseed must be hashable.')

    return ''.join(Caesar.decrypt(letter, random.randint(0, 25))
                   for letter in utils.fix_text(text))
