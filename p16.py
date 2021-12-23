from os import urandom
from typing import Dict

from main import Solution
from p02 import xor
from p10 import aes_cbc_decrypt
from p11 import aes_cbc_encrypt
from p13 import validate_pkcs7

from Crypto.Cipher import AES


def _bitflip(ctxt: bytes, input_str: str) -> bytes:
    inject = b'dataz;admin=true'
    targetblock = ctxt[AES.block_size:(2 * AES.block_size)]

    badblock = xor(inject, xor(input_str.encode(), targetblock))
    start = ctxt[:AES.block_size]
    end = ctxt[2 * AES.block_size:]
    return start + badblock + end


def _generate_encrypted_data(user_data: str, key: bytes, iv: bytes) -> bytes:
    s1 = 'comment1=cooking%20MCs;userdata='
    s2 = ';comment2=%20like%20a%20pound%20of%20bacon'
    ptxt = s1 + user_data.replace(';', '%3B').replace('=', '%3D') + s2
    return aes_cbc_encrypt(ptxt.encode(), key, iv)


def _decrypt_and_parse(ctxt: bytes, key: bytes, iv: bytes) -> Dict[bytes, bytes]:
    plaintext = validate_pkcs7(aes_cbc_decrypt(ctxt, key, iv))
    data = {}

    for pairs in plaintext.split(b';'):
        key, value = pairs.split(b'=')
        data[key] = value

    return data


def p16() -> Dict[bytes, bytes]:
    input_str = 'A' * 16
    master_key, iv = urandom(16), urandom(16)

    ctxt = _generate_encrypted_data(input_str, master_key, iv)
    ctxtmod = _bitflip(ctxt, input_str)
    return _decrypt_and_parse(ctxtmod, master_key, iv)


def main() -> Solution:
    return Solution('16: CBC bitflipping attacks', p16)
