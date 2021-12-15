from binascii import hexlify, unhexlify
from typing import Optional

from main import Solution

from Crypto.Cipher import AES


def detect_ecb_mode(ctxt: bytes) -> bool:
    blocks = []

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        blocks.append(ctxt[start:end])

    return len(blocks) != len(set(blocks))


def p08() -> Optional[bytes]:
    with open('Data/8.txt', 'rb') as f:
        ctxts = [unhexlify(txt) for txt in f.read().split(b'\n')]

    for ctxt in ctxts:
        if detect_ecb_mode(ctxt):
            return hexlify(ctxt)

    return None


def main():
    return Solution('8: Detect AES in ECB mode', p08)
