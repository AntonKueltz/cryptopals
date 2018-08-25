from os import urandom
from random import randint

from p02 import xor
from p09 import pkcs7

from Crypto.Cipher import AES


def aes_ecb_encrypt(ptxt, key):
    ctxt = ''
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7(ptxt)

    for block in range(len(padded) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ctxt += cipher.encrypt(padded[start:end])

    return ctxt


def aes_cbc_encrypt(ptxt, key, iv):
    ctxt = ''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    padded = pkcs7(ptxt)

    for block in range(len(padded) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = padded[start:end]

        tmp = xor(prev_block, cur_block)
        ctxtblock = cipher.encrypt(tmp)
        ctxt += ctxtblock

        prev_block = ctxtblock

    return ctxt


def detect_ecb_mode(ctxt):
    blocks = []

    for block in range(len(ctxt) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        blocks.append(ctxt[start:end])

    return len(blocks) != len(set(blocks))


def _pad_data(data):
    before, after = randint(5, 10), randint(5, 10)
    return urandom(before) + data + urandom(after)


def p11():
    data = '\x00' * 100
    key = urandom(16)
    data = _pad_data(data)

    ctxt = ''
    if randint(0, 1):
        print 'Encrypting in ECB mode...'
        ctxt = aes_ecb_encrypt(data, key)
    else:
        print 'Encrypting in CBC mode...'
        iv = urandom(16)
        ctxt = aes_cbc_encrypt(data, key, iv)

    if detect_ecb_mode(ctxt):
        return 'Detected ECB Mode'
    else:
        return 'Detected CBC Mode'


def main():
    from main import Solution
    return Solution('11: An ECB/CBC detection oracle', p11)
