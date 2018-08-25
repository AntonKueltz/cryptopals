from Crypto.Cipher import AES


def pkcs7(data, block_size=AES.block_size):
    bytes_to_pad = block_size - (len(data) % block_size)

    for _ in range(bytes_to_pad):
        data += chr(bytes_to_pad)
    return data


def p09():
    return repr(pkcs7('YELLOW SUBMARINE', 20))


def main():
    from main import Solution
    return Solution('9: Implement PKCS#7 padding', p09)
