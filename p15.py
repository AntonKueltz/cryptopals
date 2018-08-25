from p13 import validate_pkcs7


def p15():
    ice_baby = 'ICE ICE BABY' + '\x04' * 4
    valid_padding = validate_pkcs7(ice_baby)
    return '{} has valid PKCS7 padding - {}'.format(repr(ice_baby), valid_padding)


def main():
    from main import Solution
    return Solution('15: PKCS#7 padding validation', p15)
