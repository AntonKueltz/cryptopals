from binascii import hexlify, unhexlify

from Crypto.Cipher import AES


def detect_ecb_mode(ctxt):
    blocks = []

    for block in range(len(ctxt) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        blocks.append(ctxt[start:end])

    return len(blocks) != len(set(blocks))


def p08():
    with open('Data/8.txt') as f:
        ctxts = [unhexlify(txt) for txt in f.read().split('\n')]

    for ctxt in ctxts:
        if detect_ecb_mode(ctxt):
            return hexlify(ctxt)

    return None


def main():
    from main import Solution
    return Solution('8: Detect AES in ECB mode', p08)
