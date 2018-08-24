from binascii import hexlify, unhexlify


def xor(buf1, buf2):
    result = ""
    for b1, b2 in zip(buf1, buf2):
        result += chr(ord(b1) ^ ord(b2))
    return result


def p02():
    left = unhexlify('1c0111001f010100061a024b53535009181c')
    right = unhexlify('686974207468652062756c6c277320657965')
    return hexlify(xor(left, right))


def main():
    from main import Solution
    return Solution('2: Fixed XOR', p02)
