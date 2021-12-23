from main import Solution

from Crypto.Cipher import AES


def pkcs7(data: bytes, block_size: int = AES.block_size) -> bytes:
    bytes_to_pad = block_size - (len(data) % block_size)
    padding_byte = int.to_bytes(bytes_to_pad, 1, byteorder='little')

    for _ in range(bytes_to_pad):
        data += padding_byte

    return data


def p09() -> str:
    return repr(pkcs7(b'YELLOW SUBMARINE', 20))


def main() -> Solution:
    return Solution('9: Implement PKCS#7 padding', p09)
