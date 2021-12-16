from binascii import hexlify
from os import urandom

from main import Solution
from p02 import xor
from p10 import aes_cbc_decrypt
from p11 import aes_cbc_encrypt

from Crypto.Cipher import AES


def _check_ascii_compliant(msg: bytes):
    for c in msg:
        if c < 32:
            raise ValueError(msg)


def p27() -> bytes:
    key = urandom(16)
    print(f'The key is {hexlify(key).decode()}')
    msg = b'Super secret message unfortunately encrypted in a bad manner'

    ctxt = aes_cbc_encrypt(msg, key, key)
    c1 = ctxt[:AES.block_size]
    zeros = b'\x00' * AES.block_size
    ctxt = c1 + zeros + c1 + ctxt[3 * AES.block_size:]

    try:
        plaintext = aes_cbc_decrypt(ctxt, key, key)
        return _check_ascii_compliant(plaintext)
    except ValueError as e:
        ptxt = e.args[0]
        p1, p3 = ptxt[:AES.block_size], ptxt[2 * AES.block_size:3 * AES.block_size]
        return b'Recovered ' + hexlify(xor(p1, p3))


def main():
    return Solution('27: Recover the key from CBC with IV=Key', p27)
