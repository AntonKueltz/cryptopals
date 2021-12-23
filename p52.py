from binascii import hexlify
from os import urandom
from typing import List

from p09 import pkcs7

from Crypto.Cipher import AES


def mdhash(m: bytes, h: bytes, nopadding: bool = False) -> bytes:
    state_size = len(h)
    if not nopadding:
        m = pkcs7(m)

    for block in range(len(m) // AES.block_size):
        cipher = AES.new(pkcs7(h), AES.MODE_ECB)
        start = block * AES.block_size
        end = start + AES.block_size
        h = cipher.encrypt(m[start:end])[:state_size]

    return h


def _find_collision(m: bytes, h: bytes) -> (bytes, bytes, bytes):
    lookup = {}

    hashed = mdhash(m, h)
    while hashed not in lookup:
        lookup[hashed] = m
        m = urandom(15)
        hashed = mdhash(m, h)

    return m, lookup[hashed], hashed


def _generate_collisions(n: int, start: bytes) -> List[bytes]:
    h = b'\x00\x00'
    collisions = []

    for _ in range(n):
        prev_collisions = collisions[:]
        s1, s2, hashed = _find_collision(start, h)

        if not collisions:
            collisions = [s1, s2]
        else:
            collisions = [pkcs7(p) + s1 for p in prev_collisions]
            collisions += [pkcs7(p) + s2 for p in prev_collisions]

        h = hashed

    return collisions


def p52() -> str:
    expensive_size = 4
    expensive_state = b'\x00' * expensive_size
    start = urandom(15)

    while True:
        lookup = {}
        collisions = _generate_collisions(expensive_size * 4, start)
        print(f'Generated {len(collisions)} collisions...')

        for m in collisions:
            h = mdhash(m, expensive_state)

            if h in lookup:
                collision = lookup[h]
                assert mdhash(m, b'\x00\x00') == mdhash(collision, b'\x00\x00')
                assert m != collision
                return f'Found collision for values\n{hexlify(m).decode()}\n' \
                       f'and\n{hexlify(collision).decode()}\n' \
                       f'hash = {hexlify(h).decode()}'
            else:
                lookup[h] = m

        start = urandom(15)


def main():
    from main import Solution
    return Solution('52: Iterated Hash Function Multicollisions', p52)
