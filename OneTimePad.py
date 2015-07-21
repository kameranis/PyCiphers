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


def encrypt(text, seed):
    """Encrypts text using the One-Time Pad cipher

    E(x) = Caesar.encrypt(x, random)

    text : string
    seed : hashable
    """
    random.seed(seed)

    return ''.join(Caesar.encrypt(letter, random.randint(0, 25))
                   for letter in utils.fix_text(text))


def decrypt(text, seed):
    """Decrypts text using the One-Time Pad cipher

    D(x) = Caesar.decrypt(x, random)

    text : string
    seed : hashable
    """
    random.seed(seed)

    return ''.join(Caesar.decrypt(letter, random.randint(0, 25))
                   for letter in utils.fix_text(text))
