from main import Solution
from p39 import RSA
from p47 import bb98


def p48() -> str:
    mod_size = 768
    rsa = RSA(bitsize=mod_size)
    return bb98(rsa).decode()


def main() -> Solution:
    return Solution('48: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Complete Case)', p48)
