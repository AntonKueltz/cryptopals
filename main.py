#!/usr/local/bin/python
import sys

import aes_modes
import padding
import set1
import set2
import set3
import set4
import set5
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
    print '{}\n'.format(set2.break_ecb_simple(s12.decode('base64')))

    print '13: ECB cut-and-paste'
    s13 = 'hax0r@bar.' + padding.pkcs7('admin') + 'com'
    print '{}\n'.format(set2.cut_and_paste(s13))

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


def s4():
    print '28: Implement a SHA-1 keyed MAC'
    print '{}\n'.format(set4.sha1mac())


def s5():
    print '33: Implement Diffie-Hellman'
    print '{}\n'.format(set5.diffie_hellman())

if __name__ == "__main__":
    sets = [s1, s2, s3, s4, s5]

    if len(sys.argv) > 1:
        if int(sys.argv[1]) > len(sets):
            print 'Invalid Set Number!'
        else:
            sets[int(sys.argv[1])-1]()

    else:
        for s in sets:
            s()
