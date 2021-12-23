from binascii import hexlify

from main import Solution


def repeating_key_xor(intxt: bytes, key: bytes) -> bytes:
    outtxt = []

    for i, c in enumerate(intxt):
        outtxt.append(c ^ key[i % len(key)])

    return bytes(outtxt)


def p05() -> bytes:
    plaintext = b'Burning \'em, if you ain\'t quick and nimble ' \
                b'I go crazy when I hear a cymbal'
    key = b'ICE'
    return hexlify(repeating_key_xor(plaintext, key))


def main() -> Solution:
    return Solution('5: Implement repeating-key XOR', p05)
