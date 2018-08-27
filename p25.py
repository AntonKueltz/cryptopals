from base64 import b64decode
from os import urandom

from p02 import xor
from p07 import aes_ecb_decrypt
from p18 import aes_ctr


def _edit_ctxt(ctxt, key, offset, newtext):
    new_ctxt = aes_ctr(newtext, key)
    return ctxt[:offset] + new_ctxt + ctxt[offset + len(new_ctxt):]


def p25():
    with open('Data/25.txt') as f:
        data = b64decode(f.read().replace('\n', ''))

    key = 'YELLOW SUBMARINE'
    ptxt = aes_ecb_decrypt(data, key)

    key = urandom(16)
    ctxt = aes_ctr(ptxt, key)

    newtext = 'A' * len(ctxt)
    edited = _edit_ctxt(ctxt, key, 0, newtext)
    return xor(xor(edited, ctxt), newtext)


def main():
    from main import Solution
    return Solution('25: Break "random access read/write" AES CTR', p25)
