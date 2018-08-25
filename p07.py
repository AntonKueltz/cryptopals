from base64 import b64decode

from Crypto.Cipher import AES


def aes_ecb_decrypt(ctxt, key):
    ptxt = ''
    cipher = AES.new(key, AES.MODE_ECB)

    for block in range(len(ctxt) / AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ptxt += cipher.decrypt(ctxt[start:end])

    return ptxt


def p07():
    key = 'YELLOW SUBMARINE'

    with open('Data/7.txt') as f:
        data = b64decode(f.read().replace('\n', ''))
        return aes_ecb_decrypt(data, key)


def main():
    from main import Solution
    return Solution('7: AES in ECB mode', p07)
