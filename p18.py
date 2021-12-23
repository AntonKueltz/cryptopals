from base64 import b64decode

from main import Solution
from p02 import xor

from Crypto.Cipher import AES


def _format_64bit(n: int) -> bytes:
    byts, hx = 0, b''

    while n:
        hx += int.to_bytes(n % 2**8, 1, byteorder='little')
        n //= 2**8
        byts += 1

    hx += b'\x00' * (8 - byts)
    return hx


def aes_ctr(intxt: bytes, key: bytes, nonce: int = 0) -> bytes:
    outtxt = b''
    count = 0
    cipher = AES.new(key, AES.MODE_ECB)

    while intxt:
        val = _format_64bit(nonce) + _format_64bit(count)
        stream = cipher.encrypt(val)

        outtxt += xor(intxt[:AES.block_size], stream)
        intxt = intxt[AES.block_size:]
        count += 1

    return outtxt


def p18() -> bytes:
    text = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX' \
           b'0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    return aes_ctr(b64decode(text), key)


def main() -> Solution:
    return Solution('18: Implement CTR, the stream cipher mode', p18)
