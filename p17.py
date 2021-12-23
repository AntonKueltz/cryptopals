from base64 import b64decode
from os import urandom
from random import choice as random_choice

from main import Solution
from p02 import xor
from p10 import aes_cbc_decrypt
from p11 import aes_cbc_encrypt
from p13 import validate_pkcs7

from Crypto.Cipher import AES


def _break_cbc(ctxt: bytes, key: bytes, iv: bytes) -> bytes:
    ptxt = b''
    prevblock = iv

    for block in range(len(ctxt) // AES.block_size):
        ctxtblock = ctxt[block * AES.block_size:(block + 1) * AES.block_size]
        cipherout = b''

        for cur_pad_byte in range(1, AES.block_size+1):
            mask = bytes([(cur_pad_byte ^ s) for s in cipherout])

            for byte in range(0xff + 1):
                validpad = True
                byte_str = int.to_bytes(byte, 1, byteorder='little')
                block = b'A' * (AES.block_size - len(mask) - 1) + byte_str + mask
                out = aes_cbc_decrypt(ctxtblock, key, block)

                # server would be doing this
                try:
                    validate_pkcs7(out)
                except ValueError:
                    validpad = False

                # back to client now
                if validpad:
                    cipher_byte = int.to_bytes(byte ^ cur_pad_byte, 1, byteorder='little')
                    cipherout = cipher_byte + cipherout
                    break

        ptxt += xor(prevblock, cipherout)
        prevblock = ctxtblock

    return ptxt


def p17() -> bytes:
    strs = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB'
        '1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    key, iv = urandom(16), urandom(16)
    ptxt = b64decode(random_choice(strs))

    ctxt = aes_cbc_encrypt(ptxt, key, iv)
    ptxt = _break_cbc(ctxt, key, iv)

    return validate_pkcs7(ptxt)


def main() -> Solution:
    return Solution('17: The CBC padding oracle', p17)
