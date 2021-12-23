from binascii import hexlify
from os import urandom
from typing import Set, Tuple

from main import Solution
from p39 import RSA

DEBUG = False


def debug_print(s: str):
    if DEBUG:
        print(s)


def ceil(x: int, y: int) -> int:
    return (x + y - 1) // y


def pad_pkcs15(msg: bytes, mod_len: int) -> bytes:
    pad_len = mod_len - len(msg) - 3

    if pad_len < 8:
        raise ValueError(f'Padding of {pad_len} bytes is too short')

    padding = urandom(pad_len)
    padding.replace(b'\x00', b'\xac')  # no zero bytes in padding

    padded = b'\x00\x02' + padding + b'\x00' + msg
    assert len(padded) == mod_len
    return padded


def unpad_pkcs15(padded: bytes) -> bytes:
    if not padded.startswith(b'\x00\x02'):
        raise ValueError(f'Padding must start with 0x0002 (got {padded})')

    padded = padded[2:]
    zero_index = padded.index(0)

    if zero_index < 8:
        raise ValueError(f'Padding must be at least 8 bytes (got {zero_index} bytes)')

    return padded[zero_index + 1:]


def padding_oracle(ctxt: int, rsa: RSA) -> bool:
    ptxt = rsa.dec(ctxt)
    try:
        unpad_pkcs15(int.to_bytes(ptxt, rsa.bitsize // 8, byteorder='big'))
        return True
    except ValueError:
        return False


def update_ctxt(c: int, s: int, rsa: RSA) -> int:
    return (c * pow(s, rsa.e, rsa.N)) % rsa.N


def step2a(c: int, B: int, rsa: RSA) -> int:
    debug_print('Entered step2a...')
    s1 = ceil(rsa.N, (3*B))
    while not padding_oracle(update_ctxt(c, s1, rsa), rsa):
        s1 += 1
    return s1


def step2b(c: int, s: int, rsa: RSA) -> int:
    debug_print('Entered step2b...')
    si = s + 1
    while not padding_oracle(update_ctxt(c, si, rsa), rsa):
        si += 1
    return si


def step2c(c: int, s: int, a: int, b: int, B: int, rsa: RSA) -> int:
    debug_print('Entered step2c...')
    r = ceil(2 * (b*s - 2*B), rsa.N)
    s = ceil((2*B + r*rsa.N), b)

    while not padding_oracle(update_ctxt(c, s, rsa), rsa):
        if s >= ((3*B + r*rsa.N) // a):
            r += 1
            s = ceil((2*B + r*rsa.N), b)
        else:
            s += 1

    return s


def step3(s: int, M: Set[Tuple[int, int]], B: int, n: int) -> Set[Tuple[int, int]]:
    debug_print('Entered step3...')
    newM = set()

    for a, b in M:
        r_min = ceil((a*s - 3*B + 1), n)
        r_max = (b*s - 2*B) // n

        for r in range(r_min, r_max + 1):
            left = max(a, ceil((2*B + r*n), s))
            right = min(b, (3*B - 1 + r*n) // s)
            newM.add((left, right))

    return newM


def _solution_found(M: Set[Tuple[int, int]]) -> bool:
    if len(M) != 1:
        return False

    a, b = next(iter(M))
    return a == b


def bb98(rsa: RSA) -> bytes:
    m = pad_pkcs15(b'kick it, CC', rsa.bitsize // 8)
    debug_print(f'Padded message is {hexlify(m)}, {len(m)} bytes long')
    m = int(hexlify(m), 16)

    c = rsa.enc(m)
    B = 2 ** (rsa.bitsize - 16)
    M = {(2*B, 3*B - 1)}
    s = 1
    i = 1

    while not _solution_found(M):
        debug_print(f'Starting round with M {M}')

        if i == 1:
            s = step2a(c, B, rsa)
        elif len(M) != 1:
            s = step2b(c, s, rsa)
        else:
            a, b = next(iter(M))
            s = step2c(c, s, a, b, B, rsa)

        debug_print(f'Found s for this round: {s}')

        M = step3(s, M, B, rsa.N)
        i += 1

    a, _ = next(iter(M))

    padded = int.to_bytes(a, length=rsa.bitsize // 8, byteorder='big')
    debug_print(unpad_pkcs15(padded).decode())
    return unpad_pkcs15(padded)


def p47() -> str:
    mod_size = 256
    rsa = RSA(bitsize=mod_size)
    return bb98(rsa).decode()


def main() -> Solution:
    return Solution('47: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Simple Case)', p47)
