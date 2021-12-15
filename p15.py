from main import Solution
from p13 import validate_pkcs7


def p15() -> str:
    ice_baby = b'ICE ICE BABY' + b'\x04' * 4
    valid_padding = validate_pkcs7(ice_baby)
    return f'{repr(ice_baby)} has valid PKCS7 padding - {valid_padding}'


def main() -> Solution:
    return Solution('15: PKCS#7 padding validation', p15)
