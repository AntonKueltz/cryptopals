from os import urandom
from typing import Dict

from main import Solution
from p02 import xor
from p18 import aes_ctr

from Crypto.Cipher import AES


def _bitflip(ctxt, user_data):
    inject = b'dataz;admin=true'
    targetblock = ctxt[(2 * AES.block_size):(3 * AES.block_size)]
    keybytes = xor(user_data, targetblock)

    badblock = xor(inject, keybytes)
    start = ctxt[:(2 * AES.block_size)]
    end = ctxt[(3 * AES.block_size):]
    return start + badblock + end


def _parse(plaintext: bytes) -> Dict[str, str]:
    data = {}

    for pairs in plaintext.split(b';'):
        key, value = pairs.split(b'=')
        data[key] = value

    return data


def p26():
    user_data = b'A' * 16
    comment1 = b'comment1=cooking%20MCs;userdata='
    comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'
    ptxt = comment1 + user_data.replace(b';', b'%3B').replace(b'=', b'%3D') + comment2
    key = urandom(16)

    ctxt = aes_ctr(ptxt, key)
    ctxtmod = _bitflip(ctxt, user_data)
    ptxtmod = aes_ctr(ctxtmod, key)
    return _parse(ptxtmod)


def main() -> Solution:
    return Solution('26: CTR bitflipping', p26)
