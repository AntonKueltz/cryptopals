from hashlib import sha1
from os import urandom

from main import Solution
from p10 import aes_cbc_decrypt
from p11 import aes_cbc_encrypt
from p13 import validate_pkcs7
from p33 import DiffieHellman


def p35() -> str:
    p = DiffieHellman.default_p

    for (g, sk) in [(1, 1), (p, 0), (p - 1, p - 1)]:
        alice = DiffieHellman(g=g)
        bob = DiffieHellman(g=g)

        alice.derive_shared_secret(bob.public)
        bob.derive_shared_secret(alice.public)

        a_msg = b'When does this ever happen?'
        a_iv = urandom(16)
        a_key = sha1(str(alice.shared).encode()).digest()[:16]
        a_sends = aes_cbc_encrypt(a_msg, a_key, a_iv), a_iv

        e_key = sha1(str(sk).encode()).digest()[:16]
        try:
            e_msg = validate_pkcs7(aes_cbc_decrypt(a_sends[0], e_key, a_iv))
        except ValueError:
            sk = pow(p-1, 2, p)
            e_key = sha1(str(sk).encode()).digest()[:16]
            e_msg = validate_pkcs7(aes_cbc_decrypt(a_sends[0], e_key, a_iv))

        if e_msg != a_msg:
            return 'Intercepted Traffic Incorrectly Decrypted'

        b_iv = urandom(16)
        b_key = sha1(str(bob.shared).encode()).digest()[:16]
        b_msg = validate_pkcs7(aes_cbc_decrypt(a_sends[0], b_key, a_iv))
        b_sends = aes_cbc_encrypt(b_msg, b_key, b_iv), b_iv

        e_msg = validate_pkcs7(aes_cbc_decrypt(b_sends[0], e_key, b_iv))
        if e_msg != b_msg:
            return 'Intercepted Traffic Incorrectly Decrypted'

    return 'All Traffic Intercepted And Decrypted!'


def main() -> Solution:
    return Solution('35: Implement DH with negotiated groups, and break with malicious "g" parameters', p35)
