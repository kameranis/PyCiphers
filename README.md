# PyCiphers
Library containing basic cipher implementations.

Thus far I have added the following ciphers:
1. (Affine) Caesar Cipher
2. Vigenere Cipher
3. Playfair Cipher

Each cipher is called as
```
rot13 = ciphers.Caesar(13)
rot13.encrypt("Spam Sausage and Eggs")
```
Each cipher Class contains at least
```
set_parameters(**kwargs)
encrypt(text)
decrypt(text)
```
This plan serves to learn more about ciphers, python classes
and python coding conventions
