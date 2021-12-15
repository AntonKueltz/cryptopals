from binascii import hexlify, unhexlify

from main import Solution


def xor(buf1: bytes, buf2: bytes) -> bytes:
    return bytes([b1 ^ b2 for (b1, b2) in zip(buf1, buf2)])


def p02() -> bytes:
    left = unhexlify(b'1c0111001f010100061a024b53535009181c')
    right = unhexlify(b'686974207468652062756c6c277320657965')
    return hexlify(xor(left, right))


def main() -> Solution:
    return Solution('2: Fixed XOR', p02)
