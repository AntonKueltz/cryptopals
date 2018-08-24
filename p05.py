from binascii import hexlify


def repeating_key_xor(intxt, key):
    outtxt = ""

    for i, c in enumerate(intxt):
        outtxt += chr(ord(c) ^ ord(key[i % len(key)]))

    return outtxt


def p05():
    plaintext = 'Burning \'em, if you ain\'t quick and nimble ' \
                'I go crazy when I hear a cymbal'
    key = 'ICE'
    return hexlify(repeating_key_xor(plaintext, key))


def main():
    from main import Solution
    return Solution('5: Implement repeating-key XOR', p05)
