#!/usr/bin/env python
import sys

import aes_modes
import padding
import set1
import set2
import set3
import set4
import set5
import set6
import set7
import test
import util


def s1():
    print "1: Convert hex to base64"
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69' \
         '736f6e6f7573206d757368726f6f6d'
    print '{}\n'.format(util.hex_to_base64(s1))

    print '2: Fixed XOR'
    b21 = '1c0111001f010100061a024b53535009181c'.decode('hex')
    b22 = '686974207468652062756c6c277320657965'.decode('hex')
    print '{}\n'.format(util.xor(b21, b22).encode('hex'))

    print '3: Single-byte XOR cipher'
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print '{}\n'.format(set1.single_byte_cipher(s3.decode('hex')))

    print '4: Detect single-character XOR'
    print '{}\n'.format(set1.detect_single_byte())

    print '5: Implement repeating-key XOR'
    s5 = 'Burning \'em, if you ain\'t quick and nimble ' \
         'I go crazy when I hear a cymbal'
    k5 = 'ICE'
    print '{}\n'.format(util.repeating_key_xor(s5, k5).encode('hex'))

    print '6: Break repeating-key XOR'
    print '{}\n'.format(set1.break_repeating_key())

    print '7: AES in ECB mode'
    print '{}\n'.format(set1.decrypt_AES_ECB())

    print '8: Detect AES in ECB mode'
    print '{}\n'.format(set1.detect_ECB())


def s2():
    print '9: Implement PKCS#7 padding'
    s9 = "YELLOW SUBMARINE"
    print '{}\n'.format(padding.pkcs7(s9, block_size=20).encode('hex'))

    print '10: Implement CBC mode'
    print '{}\n'.format(set2.decrypt_CBC_Mode())

    print '11: An ECB/CBC detection oracle'
    print '{}\n'.format(set2.detection_oracle('o'*100))

    print '12 Byte-at-a-time ECB decryption (Simple)'
    s12 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
          'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
          'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
          'YnkK'
    print '{}\n'.format(set2.break_ecb(s12.decode('base64')))

    print '13: ECB cut-and-paste'
    s13 = 'hax0r@bar.' + padding.pkcs7('admin') + 'com'
    print '{}\n'.format(set2.cut_and_paste(s13))

    print '14: Byte-at-a-time ECB decryption (Harder)'
    s14 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
          'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
          'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
          'YnkK'
    print '{}\n'.format(set2.break_ecb(s14.decode('base64'), harder=True))

    print '15: PKCS#7 padding validation'
    s15 = 'ICE ICE BABY' + chr(4) * 4
    print '{}\n'.format(padding.validate(s15))

    print '16: CBC bitflipping attacks'
    print '{}\n'.format(set2.bitflipping('A' * 16))


def s3():
    print '17: The CBC padding oracle'
    print '{}\n'.format(set3.cbc_oracle_attack())

    print '18: Implement CTR, the stream cipher mode'
    s18 = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX' \
          '0KSvoOLSFQ=='
    k18 = 'YELLOW SUBMARINE'
    print '{}\n'.format(aes_modes.AES_CTR(s18.decode('base64'), k18, 0))

    print '19: Break fixed-nonce CTR mode using substitions'
    print '{}\n'.format(set3.break_fixed_nonce1())

    print '20: Break fixed-nonce CTR statistically'
    print '{}\n'.format(set3.break_fixed_nonce2())

    print '21: Implement the MT19937 Mersenne Twister RNG'
    print '{}\n'.format(set3.prng_output())

    print '22: Crack an MT19937 seed'
    print '{}\n'.format(set3.crack_mt19937_seed())

    print '23: Clone an MT19937 RNG from its output'
    print '{}\n'.format(set3.clone_mt19937())

    print '24: Create the MT19937 stream cipher and break it'
    print '{}\n'.format(set3.break_mt19937_stream())


def s4():
    print '25: Break "random access read/write" AES CTR'
    print '{}\n'.format(set4.read_write_CTR())

    print '26: CTR bitflipping'
    print '{}\n'.format(set4.bitflipping_CTR('A' * 16))

    print '27: Recover the key from CBC with IV=Key'
    print '{}\n'.format(set4.key_as_iv())

    print '28: Implement a SHA-1 keyed MAC'
    print '{}\n'.format(set4.sha1mac())

    print '29: Break a SHA-1 keyed MAC using length extension'
    print '{}\n'.format(set4.length_extension_sha1())

    print '30: Break an MD4 keyed MAC using length extension'
    print '{}\n'.format(set4.length_extension_md4())

    print '31: Implement and break HMAC-SHA1 with an artificial timing leak'
    s31 = 'filename'
    print '{}\n'.format(set4.hmac_sha1_timing_leak(s31, 50, 1))

    print '32: Break HMAC-SHA1 with a slightly less artificial timing leak'
    s32 = 'anotherfilename'
    print '{}\n'.format(set4.hmac_sha1_timing_leak(s32, 5, 10))


def s5():
    print '33: Implement Diffie-Hellman'
    print '{}\n'.format(set5.diffie_hellman())

    print '34: Implement a MITM key-fixing attack on Diffie-Hellman with ' \
          'parameter injection'
    print '{}\n'.format(set5.dh_param_injection())

    print '35: Implement DH with negotiated groups, and break with malicious' \
          ' "g" parameters'
    print '{}\n'.format(set5.dh_malicious_group())

    print '36: Implement Secure Remote Password (SRP)'
    print '{}\n'.format(set5.network_srp())

    print '37: Break SRP with a zero key'
    print '{}\n'.format(set5.srp_w_zerokey())

    print '38: Offline dictionary attack on simplified SRP'
    print '{}\n'.format(set5.simple_dict_srp())

    print '39: Implement RSA'
    print '{}\n'.format(set5.basic_rsa())

    print '40: Implement an E=3 RSA Broadcast attack'
    print '{}\n'.format(set5.rsa_broadcast())


def s6():
    print '41: Implement unpadded message recovery oracle'
    print '{}\n'.format(set6.rsa_recovery_oracle())

    print '42: Bleichenbacher\'s e=3 RSA Attack'
    print '{}\n'.format(set6.e_is_3_attack())

    print '43: DSA key recovery from nonce'
    print '{}\n'.format(set6.dsa_key_recovery())

    print '44: DSA nonce recovery from repeated nonce'
    print '{}\n'.format(set6.dsa_repeated_nonce_recovery())

    print '45: DSA parameter tampering'
    print '{}\n'.format(set6.dsa_parameter_tampering())

    print '46: RSA parity oracle'
    print '{}\n'.format(set6.rsa_parity_oracle())

    print '47: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Simple Case)'
    print '{}\n'.format(set6.rsa_pkcs15_oracle_easy())

    print '48: Bleichenbacher\'s PKCS 1.5 Padding Oracle (Complete Case)'
    print '{}\n'.format(set6.rsa_pkcs15_oracle_complete())


def s7():
    print '49: CBC-MAC Message Forgery'
    print '{}\n'.format(set7.cbcmac_forgery())

    print '50: Hashing with CBC-MAC'
    print '{}\n'.format(set7.cbcmac_collision())

    print '51: Compression Ratio Side-Channel Attacks'
    print '{}\n'.format(set7.compression_side_channel())

if __name__ == "__main__":
    sets = [s1, s2, s3, s4, s5, s6, s7]

    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            test.testall()
        elif int(sys.argv[1]) > len(sets):
            print 'Invalid Set Number!'
        else:
            sets[int(sys.argv[1])-1]()

    else:
        for s in sets:
            s()
