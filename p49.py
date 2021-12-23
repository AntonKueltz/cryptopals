from binascii import hexlify
from hmac import compare_digest
from os import urandom

from Crypto.Cipher import AES

from main import Solution
from p02 import xor
from p09 import pkcs7
from p11 import aes_cbc_encrypt

master_key = urandom(16)


def cbcmac(
        msg: bytes,
        iv: bytes = (b'\x00' * AES.block_size),
        key: bytes = master_key
) -> bytes:
    ctxt = aes_cbc_encrypt(msg, key, iv)
    return ctxt[-AES.block_size:]


def validate_message(msg: bytes, iv: bytes, client_mac: bytes) -> bool:
    server_mac = cbcmac(msg, iv)
    return compare_digest(server_mac, client_mac)


def forge_mac(valid_mac: bytes, our_msg: bytes) -> bytes:
    message_block = xor(valid_mac, pkcs7(our_msg))
    return cbcmac(message_block)


def p49() -> str:
    our_id = 1
    target_id = 2

    valid_msg = f'from=#{our_id}&to=#{target_id}&amount=#{1000000}'.encode()
    good_iv = b'\x00' * AES.block_size
    client_mac = cbcmac(valid_msg, good_iv)

    bad_msg = f'from=#{target_id}&to=#{our_id}&amount=#{1000000}'.encode()
    bad_iv = xor(bad_msg[:AES.block_size], xor(valid_msg[:AES.block_size], good_iv))
    assert validate_message(bad_msg, bad_iv, client_mac)

    valid_msg = f'from=#{target_id}&tx_list=#3:5000;4:7000'.encode()
    valid_mac = cbcmac(valid_msg)

    bad_msg = f';{our_id}:1000000'.encode()
    forged_mac = forge_mac(valid_mac, bad_msg)
    forged_msg = pkcs7(valid_msg) + pkcs7(bad_msg)

    assert compare_digest(forged_mac, cbcmac(forged_msg))
    return f'Successfully stole 1M spacebucks! Message "{forged_msg.decode()}"' \
           f'signed with MAC {hexlify(forged_mac).decode()}'


def main() -> Solution:
    return Solution('49: CBC-MAC Message Forgery', p49)
