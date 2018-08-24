from base64 import b64encode
from binascii import unhexlify


def p01():
    instr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    raw = unhexlify(instr)
    return b64encode(raw)


def main():
    from main import Solution
    return Solution('1: Convert hex to base64', p01)
