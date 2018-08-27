from os import urandom

from p02 import xor
from p18 import aes_ctr

from Crypto.Cipher import AES


def _bitflip(ctxt, user_data):
    inject = 'dataz;admin=true'
    targetblock = ctxt[(2 * AES.block_size):(3 * AES.block_size)]
    keybytes = xor(user_data, targetblock)

    badblock = xor(inject, keybytes)
    start = ctxt[:(2 * AES.block_size)]
    end = ctxt[(3 * AES.block_size):]
    return start + badblock + end


def _parse(plaintext):
    data = {}

    for pairs in plaintext.split(';'):
        key, value = pairs.split('=')
        data[key] = value

    return data


def p26():
    user_data = 'A' * 16
    comment1 = 'comment1=cooking%20MCs;userdata='
    comment2 = ';comment2=%20like%20a%20pound%20of%20bacon'
    ptxt = comment1 + user_data.replace(';', '').replace('=', '') + comment2
    key = urandom(16)

    ctxt = aes_ctr(ptxt, key)
    ctxtmod = _bitflip(ctxt, user_data)
    ptxtmod = aes_ctr(ctxtmod, key)
    return _parse(ptxtmod)


def main():
    from main import Solution
    return Solution('26: CTR bitflipping', p26)
