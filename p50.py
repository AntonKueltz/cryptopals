from binascii import hexlify

from p02 import xor
from p49 import cbcmac

from Crypto.Cipher import AES


def p50():
    key = 'YELLOW SUBMARINE'
    str1 = 'alert(\'MZA who was that?\');\n'
    target_hash = cbcmac(str1, key=key)

    str2 = 'alert(\'Ayo, the Wu is back!\');//'
    intermediate_hash = cbcmac(str2, key=key)

    block0 = '\x10' * AES.block_size
    block1 = xor(intermediate_hash, str1[:AES.block_size])
    block2 = str1[AES.block_size:]
    valid_snippet = str2 + block0 + block1 + block2
    collision_hash = cbcmac(valid_snippet, key=key)

    assert collision_hash == target_hash
    return 'Created snippet {} with hash {}. Target snippet was {} with hash {}'.format(
        repr(valid_snippet), hexlify(collision_hash), repr(str1), hexlify(target_hash))


def main():
    from main import Solution
    return Solution('50: Hashing with CBC-MAC', p50)
