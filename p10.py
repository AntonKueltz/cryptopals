from base64 import b64decode

from main import Solution
from p02 import xor

from Crypto.Cipher import AES


def aes_cbc_decrypt(ctxt: bytes, key: bytes, iv: bytes) -> bytes:
    ptxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = ctxt[start:end]

        tmp = cipher.decrypt(cur_block)
        ptxt += xor(prev_block, tmp)

        prev_block = cur_block

    return ptxt


def p10() -> bytes:
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * AES.block_size

    with open('Data/10.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        return aes_cbc_decrypt(data, key, iv)


def main() -> Solution:
    return Solution('10: Implement CBC mode', p10)
