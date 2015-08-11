"""Playfair Cipher

check_padding(padding, which_pad):
    Checks that the padding character is valid

    which_pad is used for debugging reasons

    padding : character
    which_pad : "double" | "end" | "alternate end"

generate_grid(password):
    Generates the grid in the form of a dictionary
    Each letter is translated into a tuple of row and collumn

    password : string

generate_digraphs(text[, double_padding, end_padding]):
    Generates digraphs

    In order to not make use of too much space in large texts,
    it yields each digraph

    text : string
    double_padding : character
    end_padding : character
    alternate_end_pad : character

encrypt(text, password[, double_padding, end_padding]):
    Encrypts text using the Playfair cipher

    text : string
    password : string
    double_padding : character
    end_padding : character
    alternate_end_pad : character

decrypt(text, password[, double_padding, end_padding]):
    Decrypts text using the Playfair cipher

    text : string
    password : string
    double_padding : character
    end_padding : character
    alternate_end_pad : character
"""


import utils


class PlayfairError(Exception):
    """Playfair Exception Class"""
    def __init__(self, message):
        super(PlayfairError, self).__init__(message)
        print message


def check_padding(padding, which_pad):
    """Makes sure the text for the padding character is valid

    padding : character
    which_pad : str used for debugging reasons"""
    if type(padding) is not str:
        raise PlayfairError('Padding must be a string.')
    if len(padding) != 1:
        raise PlayfairError('The ' + which_pad + ' padding \
must be a single character.')
    elif not padding.isalpha():
        raise PlayfairError('The ' + which_pad + ' padding must \
be a letter of the alphabet.')
    padding = padding.upper()
    return padding if padding != 'J' else 'I'


def generate_grid(password):
    """Generates the grid in the form of a dictionary
    Each letter is translated into a tuple of row and collumn

    password : string
    """
    if type(password) is not str:
        raise PlayfairError('Password must be a string.')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grid = dict()
    rev_grid = dict()
    password = utils.fix_text(password)

    i = 0
    for letter in password:
        if letter == 'J':
            letter = 'I'
        if letter not in grid:
            grid[letter] = (i / 5, i % 5)
            alphabet = alphabet.replace(letter, '')
            i += 1

    for letter in alphabet:
        grid[letter] = (i / 5, i % 5)
        i += 1

    for key, value in grid.iteritems():
        rev_grid[value] = key
    return grid, rev_grid


def generate_digraphs(text, double_padding='X', end_padding='Z',
                      alternate_end_padding='Z'):
    """Splits the text into digraphs

    if a digraph consists of a double letter, double_padding is introduced
    between them. If at the end of the text we have an odd number of letters,
    an end_padding is introdiced.

    text : string
    double_padding : character
    end_padding : character
    alternate_end_padding : character
    """
    double_padding = check_padding(double_padding, "double")
    end_padding = check_padding(end_padding, "end")
    alternate_end_padding = check_padding(
            alternate_end_padding, "alternate end")
    text = utils.fix_text(text)
    text = text.replace('J', 'I')

    counter = 0

    while counter < len(text):
        if counter + 1 == len(text):
            # we have reached the end of the text_fixed
            if text[counter] != end_padding:
                yield text[counter] + end_padding
            else:
                yield text[counter] + alternate_end_padding
            break
        elif text[counter] != text[counter + 1]:
            # we just need to create a normal digraph
            yield text[counter] + text[counter + 1]
            counter += 2
        else:
            # we have a double letter digraph, so we add the double padding
            yield text[counter] + double_padding
            counter += 1


def encrypt(text, password, double_padding='X', end_padding='Z',
            alternate_end_padding='X'):
    """Encrypts text using the Playfair cipher

    text : string
    password : string
    double_padding : character
    end_padding : character
    """
    if type(text) is not str:
        raise PlayfairError('Can only encrypt strings.')

    grid, rev_grid = generate_grid(password)

    def encrypt_digraph(digraph):
        """Encrypts a single digraph

        digrpah : 2 characters generated by generate_digraphs
        """
        first_pos = grid[digraph[0]]
        second_pos = grid[digraph[1]]

        if first_pos[0] == second_pos[0]:
            # Same row
            first_encr = rev_grid[(first_pos[0], (first_pos[1] + 1) % 5)]
            second_encr = rev_grid[(second_pos[0], (second_pos[1] + 1) % 5)]

        elif first_pos[1] == second_pos[1]:
            # Same collumn
            first_encr = rev_grid[((first_pos[0] + 1) % 5, first_pos[1])]
            second_encr = rev_grid[((second_pos[0] + 1) % 5, second_pos[1])]

        else:
            # Different row and collumn
            first_encr = rev_grid[(first_pos[0], second_pos[1])]
            second_encr = rev_grid[(second_pos[0], first_pos[1])]

        return first_encr + second_encr

    return ''.join([encrypt_digraph(digraph) for digraph in generate_digraphs(
                text, double_padding, end_padding, alternate_end_padding)])


def decrypt(text, password, double_padding='X', end_padding='Z',
            alternate_end_padding='X'):
    """Decrypts text using the Playfair cipher

    text : string
    password : string
    double_padding : character
    end_padding : character
    """
    if type(text) is not str:
        raise PlayfairError('Can only encrypt strings.')

    grid, rev_grid = generate_grid(password)

    def decrypt_digraph(digraph):
        """Decrypts a single digraph

        digrpah : 2 characters generated by generate_digraphs
        """
        first_pos = grid[digraph[0]]
        second_pos = grid[digraph[1]]

        if first_pos[0] == second_pos[0]:
            # Same row
            first_encr = rev_grid[(first_pos[0], (first_pos[1] - 1) % 5)]
            second_encr = rev_grid[(second_pos[0], (second_pos[1] - 1) % 5)]

        elif first_pos[1] == second_pos[1]:
            # Same collumn
            first_encr = rev_grid[((first_pos[0] - 1) % 5, first_pos[1])]
            second_encr = rev_grid[((second_pos[0] - 1) % 5, second_pos[1])]

        else:
            # Different row and collum
            first_encr = rev_grid[(first_pos[0], second_pos[1])]
            second_encr = rev_grid[(second_pos[0], first_pos[1])]

        return first_encr + second_encr

    return ''.join([decrypt_digraph(digraph) for digraph in generate_digraphs(
                text, double_padding, end_padding, alternate_end_padding)])
