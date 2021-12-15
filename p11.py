from os import urandom
from random import randint

from main import Solution
from p02 import xor
from p08 import detect_ecb_mode
from p09 import pkcs7

from Crypto.Cipher import AES


def aes_ecb_encrypt(ptxt: bytes, key: bytes) -> bytes:
    ctxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7(ptxt)

    for block in range(len(padded) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ctxt += cipher.encrypt(padded[start:end])

    return ctxt


def aes_cbc_encrypt(ptxt: bytes, key: bytes, iv: bytes) -> bytes:
    ctxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    padded = pkcs7(ptxt)

    for block in range(len(padded) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = padded[start:end]

        tmp = xor(prev_block, cur_block)
        ctxtblock = cipher.encrypt(tmp)
        ctxt += ctxtblock

        prev_block = ctxtblock

    return ctxt


def _pad_data(data: bytes) -> bytes:
    before, after = randint(5, 10), randint(5, 10)
    return urandom(before) + data + urandom(after)


def p11() -> str:
    data = b'\x00' * 100
    key = urandom(16)
    data = _pad_data(data)

    if randint(0, 1):
        print('Encrypting in ECB mode...')
        ctxt = aes_ecb_encrypt(data, key)
    else:
        print('Encrypting in CBC mode...')
        iv = urandom(16)
        ctxt = aes_cbc_encrypt(data, key, iv)

    if detect_ecb_mode(ctxt):
        return 'Detected ECB Mode'
    else:
        return 'Detected CBC Mode'


def main() -> Solution:
    return Solution('11: An ECB/CBC detection oracle', p11)
