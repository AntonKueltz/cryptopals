from base64 import b64decode
from os import urandom

from p11 import aes_ecb_encrypt, detect_ecb_mode

from Crypto.Cipher import AES

master_key = urandom(16)


def _encrypt(data):
    global master_key
    return aes_ecb_encrypt(data, master_key)


def _detect_block_size(data):
    initial_len = len(_encrypt(data))
    cur_len = initial_len
    prepend = 1

    while cur_len == initial_len:
        cur_len = len(_encrypt('A' * prepend + data))
        prepend += 1

    return cur_len - initial_len


def _make_lookup_dict(front):
    lookup = {}

    for byte in range(0xff + 1):
        v = front + chr(byte)
        k = _encrypt(v)[:AES.block_size]
        lookup[k] = v

    return lookup


def _crack_blocks(data, attacker_string, block_size):
    prev_block = attacker_string
    ptxt = ''

    for i in range(len(data) / block_size + 1):
        ptxt_block = ''

        for byt in range(block_size):
            lookup = _make_lookup_dict(prev_block[byt+1:] + ptxt_block)
            padlen = block_size - 1 - byt

            intxt = 'A' * padlen + data
            ctxt = _encrypt(intxt)

            idx = i * block_size
            ptxt_block += lookup[ctxt[idx:idx+block_size]][-1]

            if len(ptxt + ptxt_block) == len(data):
                return ptxt + ptxt_block

        prev_block = ptxt_block
        ptxt += ptxt_block

    return ptxt


def p12():
    target = b64decode(
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
        'YnkK'
    )

    block_size = _detect_block_size(target)
    tmp_ctxt = _encrypt('A' * block_size * 4)
    assert detect_ecb_mode(tmp_ctxt)

    return _crack_blocks(target, 'A' * block_size, block_size)


def main():
    from main import Solution
    return Solution('12: Byte-at-a-time ECB decryption (Simple)', p12)
