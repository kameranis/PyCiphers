"""Utilities for the PyCiphers library

extended_gcd(x, y)
    Performs the extended Euclidean Algorithm

    Parameters
    ----------
    x, y : int

    Returns
    -------
    gcd(x, y), a, b

    where ax+by=gcd(x, y)

modinv
    Modular Inverse m

    Parameters
    ----------
    a, m : int

    Returns
    -------
    x : int

    such that ax % m = 1

fix_text:
    Capitalizes all letters and removes all non alphanumeral characters

    Parameters
    ----------
    text : str
"""


import re


def extended_gcd(a, b):
    """Extended Euclidean Algorithm

    Given two integers x, y returns
    gcd(x, y), a, b so that ax+by=gcd(a,b)
    """
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = \
            remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), \
        lasty * (-1 if b < 0 else 1)


def modinv(a, m):
    """Computes the modular inverse of a mod m

    Given two integers a, m returns x such that
    a * x % m = 1
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def fix_text(text):
    """Capitalizes all letters and removes all non alphanumeral characters

    text : str
    """
    return re.sub('[^A-Z]', '', text.upper())
