from binascii import hexlify
from hashlib import new as new_hash
from os import urandom
from struct import pack, unpack
from sys import stdout
from typing import List

from main import Solution


def _lrot(x: int, n: int) -> int:
    mask = 0
    for i in range(n):
        mask |= 2**i
    rotated = (x << n) | ((x >> (32 - n)) & mask)
    return rotated & 0xffffffff


def _rrot(x: int, n: int) -> int:
    rotated = (x >> n) | (x << (32 - n))
    return rotated & 0xffffffff


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _phi0(a: int, b: int, c: int, d: int, mk: int, s: int) -> int:
    tmp = (a + _f(b, c, d) + mk) & 0xffffffff
    return _lrot(tmp, s)


def _reverse_phi0(modified: int, a: int, b: int, c: int, d: int, s: int) -> int:
    return (_rrot(modified, s) - a - _f(b, c, d)) & 0xffffffff


def _phi1(a: int, b: int, c: int, d: int, mk: int, s: int) -> int:
    tmp = (a + _g(b, c, d) + mk + 0x5a827999) & 0xffffffff
    return _lrot(tmp, s)


def _reverse_phi1(modified: int, a: int, b: int, c: int, d: int, s: int) -> int:
    return (_rrot(modified, s) - a - _g(b, c, d) - 0x5a827999) & 0xffffffff


def _equal_bit(x: int, y: int, i: int) -> int:
    shift = i - 1
    xi, yi = (x >> shift) & 1, (y >> shift) & 1
    return x ^ ((xi ^ yi) << shift)


def _clear_bit(x: int, i: int) -> int:
    shift = i - 1
    xi = (x >> shift) & 1
    return x ^ (xi << shift)


def _set_bit(x: int, i: int) -> int:
    shift = i - 1
    return x | (1 << shift)


def _parse_message(M: bytes) -> List[int]:
    blocks = []
    for i in range(0, 64, 4):
        (block,) = unpack('<L', M[i:i + 4])
        blocks.append(block)
    return blocks


def _form_message(blocks: List[int]) -> bytes:
    s = b''
    for block in blocks:
        s += pack('<L', block)
    return s


def _massage_message(M: bytes, a0: int, b0: int, c0: int, d0: int) -> List[int]:
    m = _parse_message(M)

    a1 = _phi0(a0, b0, c0, d0, m[0], 3)
    a1 = _equal_bit(a1, b0, 7)
    m[0] = _reverse_phi0(a1, a0, b0, c0, d0, 3)

    d1 = _phi0(d0, a1, b0, c0, m[1], 7)
    d1 = _clear_bit(d1, 7)
    d1 = _equal_bit(d1, a1, 8)
    d1 = _equal_bit(d1, a1, 11)
    m[1] = _reverse_phi0(d1, d0, a1, b0, c0, 7)

    c1 = _phi0(c0, d1, a1, b0, m[2], 11)
    c1 = _set_bit(c1, 7)
    c1 = _set_bit(c1, 8)
    c1 = _clear_bit(c1, 11)
    c1 = _equal_bit(c1, d1, 26)
    m[2] = _reverse_phi0(c1, c0, d1, a1, b0, 11)

    b1 = _phi0(b0, c1, d1, a1, m[3], 19)
    b1 = _set_bit(b1, 7)
    b1 = _clear_bit(b1, 8)
    b1 = _clear_bit(b1, 11)
    b1 = _clear_bit(b1, 26)
    m[3] = _reverse_phi0(b1, b0, c1, d1, a1, 19)

    a2 = _phi0(a1, b1, c1, d1, m[4], 3)
    a2 = _set_bit(a2, 8)
    a2 = _set_bit(a2, 11)
    a2 = _clear_bit(a2, 26)
    a2 = _equal_bit(a2, b1, 14)
    m[4] = _reverse_phi0(a2, a1, b1, c1, d1, 3)

    d2 = _phi0(d1, a2, b1, c1, m[5], 7)
    d2 = _clear_bit(d2, 14)
    d2 = _equal_bit(d2, a2, 19)
    d2 = _equal_bit(d2, a2, 20)
    d2 = _equal_bit(d2, a2, 21)
    d2 = _equal_bit(d2, a2, 22)
    d2 = _set_bit(d2, 26)
    m[5] = _reverse_phi0(d2, d1, a2, b1, c1, 7)

    c2 = _phi0(c1, d2, a2, b1, m[6], 11)
    c2 = _equal_bit(c2, d2, 13)
    c2 = _clear_bit(c2, 14)
    c2 = _equal_bit(c2, d2, 15)
    c2 = _clear_bit(c2, 19)
    c2 = _clear_bit(c2, 20)
    c2 = _set_bit(c2, 21)
    c2 = _clear_bit(c2, 22)
    m[6] = _reverse_phi0(c2, c1, d2, a2, b1, 11)

    b2 = _phi0(b1, c2, d2, a2, m[7], 19)
    b2 = _set_bit(b2, 13)
    b2 = _set_bit(b2, 14)
    b2 = _clear_bit(b2, 15)
    b2 = _equal_bit(b2, c2, 17)
    b2 = _clear_bit(b2, 19)
    b2 = _clear_bit(b2, 20)
    b2 = _clear_bit(b2, 21)
    b2 = _clear_bit(b2, 22)
    m[7] = _reverse_phi0(b2, b1, c2, d2, a2, 19)

    a3 = _phi0(a2, b2, c2, d2, m[8], 3)
    a3 = _set_bit(a3, 13)
    a3 = _set_bit(a3, 14)
    a3 = _set_bit(a3, 15)
    a3 = _clear_bit(a3, 17)
    a3 = _clear_bit(a3, 19)
    a3 = _clear_bit(a3, 20)
    a3 = _clear_bit(a3, 21)
    a3 = _equal_bit(a3, b2, 23)
    a3 = _set_bit(a3, 22)
    a3 = _equal_bit(a3, b2, 26)
    m[8] = _reverse_phi0(a3, a2, b2, c2, d2, 3)

    d3 = _phi0(d2, a3, b2, c2, m[9], 7)
    d3 = _set_bit(d3, 13)
    d3 = _set_bit(d3, 14)
    d3 = _set_bit(d3, 15)
    d3 = _clear_bit(d3, 17)
    d3 = _clear_bit(d3, 20)
    d3 = _set_bit(d3, 21)
    d3 = _set_bit(d3, 22)
    d3 = _clear_bit(d3, 23)
    d3 = _set_bit(d3, 26)
    d3 = _equal_bit(d3, a3, 30)
    m[9] = _reverse_phi0(d3, d2, a3, b2, c2, 7)

    c3 = _phi0(c2, d3, a3, b2, m[10], 11)
    c3 = _set_bit(c3, 17)
    c3 = _clear_bit(c3, 20)
    c3 = _clear_bit(c3, 21)
    c3 = _clear_bit(c3, 22)
    c3 = _clear_bit(c3, 23)
    c3 = _clear_bit(c3, 26)
    c3 = _set_bit(c3, 30)
    c3 = _equal_bit(c3, d3, 32)
    m[10] = _reverse_phi0(c3, c2, d3, a3, b2, 11)

    b3 = _phi0(b2, c3, d3, a3, m[11], 19)
    b3 = _clear_bit(b3, 20)
    b3 = _set_bit(b3, 21)
    b3 = _set_bit(b3, 22)
    b3 = _equal_bit(b3, c3, 23)
    b3 = _set_bit(b3, 26)
    b3 = _clear_bit(b3, 30)
    b3 = _clear_bit(b3, 32)
    m[11] = _reverse_phi0(b3, b2, c3, d3, a3, 19)

    a4 = _phi0(a3, b3, c3, d3, m[12], 3)
    a4 = _clear_bit(a4, 23)
    a4 = _clear_bit(a4, 26)
    a4 = _equal_bit(a4, b3, 27)
    a4 = _equal_bit(a4, b3, 29)
    a4 = _set_bit(a4, 30)
    a4 = _clear_bit(a4, 32)
    m[12] = _reverse_phi0(a4, a3, b3, c3, d3, 3)

    d4 = _phi0(d3, a4, b3, c3, m[13], 7)
    d4 = _clear_bit(d4, 23)
    d4 = _clear_bit(d4, 26)
    d4 = _set_bit(d4, 27)
    d4 = _set_bit(d4, 29)
    d4 = _clear_bit(d4, 30)
    d4 = _set_bit(d4, 32)
    m[13] = _reverse_phi0(d4, d3, a4, b3, c3, 7)

    c4 = _phi0(c3, d4, a4, b3, m[14], 11)
    c4 = _equal_bit(c4, d4, 19)
    c4 = _set_bit(c4, 23)
    c4 = _set_bit(c4, 26)
    c4 = _clear_bit(c4, 27)
    c4 = _clear_bit(c4, 29)
    c4 = _clear_bit(c4, 30)
    m[14] = _reverse_phi0(c4, c3, d4, a4, b3, 11)

    b4 = _phi0(b3, c4, d4, a4, m[15], 19)
    b4 = _clear_bit(b4, 19)
    b4 = _set_bit(b4, 26)
    b4 = _set_bit(b4, 27)
    b4 = _set_bit(b4, 29)
    b4 = _clear_bit(b4, 30)
    m[15] = _reverse_phi0(b4, b3, c4, d4, a4, 19)

    a5 = _phi1(a4, b4, c4, d4, m[0], 3)
    a5 = _equal_bit(a5, c4, 19)
    a5 = _set_bit(a5, 26)
    a5 = _clear_bit(a5, 27)
    a5 = _set_bit(a5, 29)
    a5 = _set_bit(a5, 32)
    m[0] = _reverse_phi1(a5, a4, b4, c4, d4, 3)
    a1 = _phi0(a0, b0, c0, d0, m[0], 3)
    m[1] = _reverse_phi0(d1, d0, a1, b0, c0, 7)
    m[2] = _reverse_phi0(c1, c0, d1, a1, b0, 11)
    m[3] = _reverse_phi0(b1, b0, c1, d1, a1, 19)
    m[4] = _reverse_phi0(a2, a1, b1, c1, d1, 3)

    d5 = _phi1(d4, a5, b4, c4, m[4], 5)
    d5 = _equal_bit(d5, a5, 19)
    d5 = _equal_bit(d5, b4, 26)
    d5 = _equal_bit(d5, b4, 27)
    d5 = _equal_bit(d5, b4, 29)
    d5 = _equal_bit(d5, b4, 32)
    m[4] = _reverse_phi1(d5, d4, a5, b4, c4, 5)
    a2_ = _phi0(a1, b1, c1, d1, m[4], 3)
    m[5] = _reverse_phi0(d2, d1, a2_, b1, c1, 7)
    m[6] = _reverse_phi0(c2, c1, d2, a2_, b1, 11)
    m[7] = _reverse_phi0(b2, b1, c2, d2, a2_, 19)
    m[8] = _reverse_phi0(a3, a2_, b2, c2, d2, 3)

    return m


def _check_conditions(m: List[int], a: int, b: int, c: int, d: int):
    def _set(x: int, i: int):
        assert ((x >> (i - 1)) & 1) == 1

    def _clr(x: int, i: int):
        assert ((x >> (i - 1)) & 1) == 0

    def _eq(x: int, y: int, i: int):
        assert ((x >> (i - 1)) & 1) == ((y >> (i - 1)) & 1)

    a = _phi0(a, b, c, d, m[0], 3)
    _eq(a, b, 7)
    d = _phi0(d, a, b, c, m[1], 7)
    _clr(d, 7)
    _eq(d, a, 8)
    _eq(d, a, 11)
    c = _phi0(c, d, a, b, m[2], 11)
    _set(c, 7)
    _set(c, 8)
    _clr(c, 11)
    _eq(c, d, 26)
    b = _phi0(b, c, d, a, m[3], 19)
    _set(b, 7)
    _clr(b, 8)
    _clr(b, 11)
    _clr(b, 26)

    a = _phi0(a, b, c, d, m[4], 3)
    _set(a, 8)
    _set(a, 11)
    _clr(a, 26)
    _eq(a, b, 14)
    d = _phi0(d, a, b, c, m[5], 7)
    _clr(d, 14)
    _eq(d, a, 19)
    _eq(d, a, 20)
    _eq(d, a, 21)
    _eq(d, a, 22)
    _set(d, 26)
    c = _phi0(c, d, a, b, m[6], 11)
    _eq(c, d, 13)
    _clr(c, 14)
    _eq(c, d, 15)
    _clr(c, 19)
    _clr(c, 20)
    _set(c, 21)
    _clr(c, 22)
    b = _phi0(b, c, d, a, m[7], 19)
    _set(b, 13)
    _set(b, 14)
    _clr(b, 15)
    _eq(b, c, 17)
    _clr(b, 19)
    _clr(b, 20)
    _clr(b, 21)
    _clr(b, 22)

    a = _phi0(a, b, c, d, m[8], 3)
    _set(a, 13)
    _set(a, 14)
    _set(a, 15)
    _clr(a, 17)
    _clr(a, 19)
    _clr(a, 20)
    _clr(a, 21)
    _eq(a, b, 23)
    _set(a, 22)
    _eq(a, b, 26)
    d = _phi0(d, a, b, c, m[9], 7)
    _set(d, 13)
    _set(d, 14)
    _set(d, 15)
    _clr(d, 17)
    _clr(d, 20)
    _set(d, 21)
    _set(d, 22)
    _clr(d, 23)
    _set(d, 26)
    _eq(d, a, 30)
    c = _phi0(c, d, a, b, m[10], 11)
    _set(c, 17)
    _clr(c, 20)
    _clr(c, 21)
    _clr(c, 22)
    _clr(c, 23)
    _clr(c, 26)
    _set(c, 30)
    _eq(c, d, 32)
    b = _phi0(b, c, d, a, m[11], 19)
    _clr(b, 20)
    _set(b, 21)
    _set(b, 22)
    _eq(b, c, 23)
    _set(b, 26)
    _clr(b, 30)
    _clr(b, 32)

    a = _phi0(a, b, c, d, m[12], 3)
    _clr(a, 23)
    _clr(a, 26)
    _eq(a, b, 27)
    _eq(a, b, 29)
    _set(a, 30)
    _clr(a, 32)
    d = _phi0(d, a, b, c, m[13], 7)
    _clr(d, 23)
    _clr(d, 26)
    _set(d, 27)
    _set(d, 29)
    _clr(d, 30)
    _set(d, 32)
    c = _phi0(c, d, a, b, m[14], 11)
    _eq(c, d, 19)
    _set(c, 23)
    _set(c, 26)
    _clr(c, 27)
    _clr(c, 29)
    _clr(c, 30)
    b = _phi0(b, c, d, a, m[15], 19)
    _clr(b, 19)
    _set(b, 26)
    _eq(b, c, 26)
    _set(b, 27)
    _set(b, 29)
    _clr(b, 30)

    a = _phi1(a, b, c, d, m[0], 3)
    _eq(a, c, 19)
    _set(a, 26)
    _clr(a, 27)
    _set(a, 29)
    _set(a, 32)
    d = _phi1(d, a, b, c, m[4], 5)
    _eq(d, a, 19)
    _eq(d, b, 26)
    _eq(d, b, 27)
    _eq(d, b, 29)
    _eq(d, b, 32)
    c = _phi1(c, d, a, b, m[8], 9)
    b = _phi1(b, c, d, a, m[12], 13)


def _md4_hash(m: bytes):
    return new_hash('md4', m).digest()


def _format_msg(M: bytes) -> str:
    return ' '.join([f'{b:x}' for b in unpack('<LLLLLLLLLLLLLLLL', M)])


def p55() -> str:
    collision = False
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    i = 0
    while not collision:
        i += 1
        if i % 1000 == 0:
            stdout.write('.')
            stdout.flush()

        M = urandom(64)
        m = _massage_message(M, a0, b0, c0, d0)

        m_ = m[:]
        m_[1] = (m[1] + 2 ** 31) & 0xffffffff
        m_[2] = (m[2] + (2 ** 31 - 2 ** 28)) & 0xffffffff
        m_[12] = (m[12] - 2 ** 16) & 0xffffffff

        M = _form_message(m)
        M_ = _form_message(m_)

        collision = _md4_hash(M) == _md4_hash(M_)

    return f'Found MD4 collision for messages\n' \
           f'M = {_format_msg(M)}\n' \
           f'M\' = {_format_msg(M_)}\n' \
           f'h = {hexlify(_md4_hash(M_)).decode()}'


def main() -> Solution:
    return Solution('55: MD4 Collisions', p55)
