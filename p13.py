from os import urandom

from p07 import aes_ecb_decrypt
from p09 import pkcs7
from p12 import aes_ecb_encrypt

from Crypto.Cipher import AES


def _parse_encoded_profile(profile):
    data = {}

    for pairs in profile.split('&'):
        key, value = pairs.split('=')
        data[key] = value

    return data


def _profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return 'email={}&uid=10&role=user'.format(email)


def _cut_paste_attack(ctxt):
    badblock = ctxt[AES.block_size:(2 * AES.block_size)]
    newctxt = ctxt[:AES.block_size] + ctxt[(2 * AES.block_size):-AES.block_size]
    return newctxt + badblock


def validate_pkcs7(ptxt):
    padval = ord(ptxt[-1])

    if padval > 16 or padval <= 0:
        raise ValueError('Invalid PKCS7 padding - {}'.format(repr(ptxt)))

    for i in range(padval):
        if ord(ptxt[-(i+1)]) != padval:
            raise ValueError('Invalid PKCS7 padding - {}'.format(repr(ptxt)))

    return ptxt[:-padval]


def p13():
    master_key = urandom(16)
    email = 'hax0r@bar.' + pkcs7('admin') + 'com'

    profile = _profile_for(email)
    ctxt = aes_ecb_encrypt(profile, master_key)

    ctxtmod = _cut_paste_attack(ctxt)
    ptxtmod = aes_ecb_decrypt(ctxtmod, master_key)

    profile = validate_pkcs7(ptxtmod)
    return _parse_encoded_profile(profile)


def main():
    from main import Solution
    return Solution('13: ECB cut-and-paste', p13)
