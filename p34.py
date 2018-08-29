from binascii import unhexlify
from os import urandom

from p10 import aes_cbc_decrypt
from p11 import aes_cbc_encrypt
from p13 import validate_pkcs7
from p28 import SHA1
from p33 import DiffieHellman


def p34():
    alice = DiffieHellman()
    bob = DiffieHellman()
    sha1 = SHA1()

    bob.derive_shared_secret(alice.p)
    alice.derive_shared_secret(bob.p)

    a_msg = 'build a protocol and an "echo" bot'
    a_iv = urandom(16)
    a_key = unhexlify(sha1.hash(alice.shared))[:16]
    a_sends = aes_cbc_encrypt(a_msg, a_key, a_iv), a_iv
    print 'Encrypted message "{}"'.format(a_msg)

    e_key = unhexlify(sha1.hash(0))[:16]
    e_msg = validate_pkcs7(aes_cbc_decrypt(a_sends[0], e_key, a_iv))
    if e_msg != a_msg:
        return 'Intercepted Traffic Incorrectly Decrypted'

    b_iv = urandom(16)
    b_key = unhexlify(sha1.hash(bob.shared))[:16]
    b_msg = validate_pkcs7(aes_cbc_decrypt(a_sends[0], b_key, a_iv))
    b_sends = aes_cbc_encrypt(b_msg, b_key, b_iv), b_iv

    e_msg = validate_pkcs7(aes_cbc_decrypt(b_sends[0], e_key, b_iv))
    if e_msg != b_msg:
        return 'Intercepted Traffic Incorrectly Decrypted'

    return 'Intercepted and decrypted message "{}"'.format(e_msg)


def main():
    from main import Solution
    return Solution('34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection', p34)
