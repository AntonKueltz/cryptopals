from os import urandom
from typing import Dict

from main import Solution
from p07 import aes_ecb_decrypt
from p09 import pkcs7
from p12 import aes_ecb_encrypt

from Crypto.Cipher import AES


def _parse_encoded_profile(profile: str) -> Dict[str, str]:
    data = {}

    for pairs in profile.split('&'):
        key, value = pairs.split('=')
        data[key] = value

    return data


def _profile_for(email: str) -> str:
    email = email.replace('&', '').replace('=', '')
    return 'email={}&uid=10&role=user'.format(email)


def _cut_paste_attack(ctxt: bytes) -> bytes:
    badblock = ctxt[AES.block_size:(2 * AES.block_size)]
    newctxt = ctxt[:AES.block_size] + ctxt[(2 * AES.block_size):-AES.block_size]
    return newctxt + badblock


def validate_pkcs7(ptxt: bytes) -> bytes:
    padval = ptxt[-1]

    if padval > 16 or padval <= 0:
        raise ValueError(f'Invalid PKCS7 padding - {repr(ptxt)}')

    for i in range(padval):
        if ptxt[-(i + 1)] != padval:
            raise ValueError(f'Invalid PKCS7 padding - {repr(ptxt)}')

    return ptxt[:-padval]


def p13() -> Dict[str, str]:
    master_key = urandom(16)
    email = 'hax0r@bar.' + pkcs7(b'admin').decode() + 'com'

    profile = _profile_for(email).encode()
    ctxt = aes_ecb_encrypt(profile, master_key)

    ctxtmod = _cut_paste_attack(ctxt)
    ptxtmod = aes_ecb_decrypt(ctxtmod, master_key)

    profile = validate_pkcs7(ptxtmod).decode()
    return _parse_encoded_profile(profile)


def main() -> Solution:
    return Solution('13: ECB cut-and-paste', p13)
