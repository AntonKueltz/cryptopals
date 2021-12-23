from binascii import hexlify

from main import Solution
from p02 import xor
from p49 import cbcmac

from Crypto.Cipher import AES


def p50() -> str:
    key = b'YELLOW SUBMARINE'
    msg1 = b'alert(\'MZA who was that?\');\n'
    target_hash = cbcmac(msg1, key=key)

    msg2 = b'alert(\'Ayo, the Wu is back!\');//'
    intermediate_hash = cbcmac(msg2, key=key)

    block0 = b'\x10' * AES.block_size
    block1 = xor(intermediate_hash, msg1[:AES.block_size])
    block2 = msg1[AES.block_size:]
    valid_snippet = msg2 + block0 + block1 + block2
    collision_hash = cbcmac(valid_snippet, key=key)

    assert collision_hash == target_hash
    return f'Created snippet {valid_snippet} ' \
           f'with hash {hexlify(collision_hash).decode()}.\n' \
           f'Target snippet was {msg1} ' \
           f'with hash {hexlify(target_hash).decode()}'


def main() -> Solution:
    return Solution('50: Hashing with CBC-MAC', p50)
