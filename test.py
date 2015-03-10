import time

import aes_modes
import oracle
import padding
import prng
import set1
import set2
import set3
import set4
import set5
import util

# I can't be bothered to format the lyrics for the entire song
vanilla_ice_1 = 'I\'m back and I\'m ringin\' the bell \n'\
                'A rockin\' on the mike while the fly girls yell \n'\
                'In ecstasy in the back of me \n'\
                'Well that\'s my DJ Deshay cuttin\' all them Z\'s \n'\
                'Hittin\' hard and the girlies goin\' crazy \n'\
                'Vanilla\'s on the mike, man I\'m not lazy. \n'

vanilla_ice_2 = 'I\'m back and I\'m ringin\' the bell \n'\
                'A rockin\' on the mike while the fly girls yell \n'\
                'In ecstasy in the back of me \n'\
                'Well that\'s my DJ Deshay cuttin\' all them Z\'s \n'\
                'Hittin\' hard and the girlies goin\' crazy \n'\
                'Vanilla\'s on the mike, man I\'m not lazy. \n'

vanilla_ice_3 = 'Rollin\' in my 5.0\n'\
                'With my rag-top down so my hair can blow\n'\
                'The girlies on standby waving just to say hi\n'\
                'Did you stop? No, I just drove by\n'\

vanilla_ice_4 = 'i\'m rated \"R\"...this is a warning, ya better void / P\n'\
                'cuz I came back to attack others in spite- / Strike l\n'\
                'but don\'t be afraid in the dark, in a park / Not a sc\n'\
                'ya tremble like a alcoholic, muscles tighten up / Wha\n'

vanilla_set = map(lambda x: x.decode('base64'), [
                'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgY'
                'XJlIHB1bXBpbic=',
                'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha'
                '2luZw==',
                'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYm'
                'xl',
                'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
            ])

easter_start = 'i have met them at close of day\n'\
               'coming with vivid faces\n'\
               'from counter or desk among grey\n'\
               'eighteenth-century houses.\n'


# matching the start of the lyrics is generally good enough to verify
def match_start(s1, s2):
    for i, (a, b) in enumerate(zip(s1, s2)):
        if a != b:
            print i, ord(a), ord(b)
            return False
    return True


# this method is long and ugly
def testall():
    '''
    i[n] = input for challenge n
    k[n] = key for challenge n
    e = expected result
    r = actual result
    '''
    retstr = lambda bool: u'\u2713 PASSED' if bool else u'\u2717 FAILED'

    i1 = '49276d206b696c6c696e6720796f757220627261696e206c696b6520612070'\
         '6f69736f6e6f7573206d757368726f6f6d'
    e = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n'
    r = util.hex_to_base64(i1)
    print u'01: {}'.format(retstr(e == r))

    i2_1 = '1c0111001f010100061a024b53535009181c'.decode('hex')
    i2_22 = '686974207468652062756c6c277320657965'.decode('hex')
    e = '746865206b696420646f6e277420706c6179'
    r = util.xor(i2_1, i2_22).encode('hex')
    print u'02: {}'.format(retstr(e == r))

    i3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    e = 'Cooking MC\'s like a pound of bacon'
    r = set1.single_byte_cipher(i3.decode('hex'))
    print u'03: {}'.format(retstr(e == r))

    e = 'Now that the party is jumping\n'
    r = set1.detect_single_byte()
    print u'04: {}'.format(retstr(e == r))

    i5 = 'Burning \'em, if you ain\'t quick and nimble\n'\
         'I go crazy when I hear a cymbal'
    k5 = 'ICE'
    e = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427'\
        '2765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831652863'\
        '26302e27282f'
    r = util.repeating_key_xor(i5, k5).encode('hex')
    print u'05: {}'.format(retstr(e == r))

    e = vanilla_ice_1
    r = set1.break_repeating_key()
    print u'06: {}'.format(retstr(match_start(e, r)))

    e = vanilla_ice_1
    r = set1.decrypt_AES_ECB()
    print u'07: {}'.format(retstr(match_start(e, r)))

    e = 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd'\
        '052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9df'\
        'dbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6a'\
        'ecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db'\
        '1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
    r = set1.detect_ECB()
    print u'08: {}'.format(retstr(e == r))

    i9 = 'YELLOW SUBMARINE'
    e = '59454c4c4f57205355424d4152494e4504040404'
    r = padding.pkcs7(i9, block_size=20).encode('hex')
    print u'09: {}'.format(retstr(e == r))

    e = vanilla_ice_2
    r = set2.decrypt_CBC_Mode()
    print u'10: {}'.format(retstr(match_start(e, r)))

    i11 = 'A' * 100
    k11 = 'ANTONISSUPERCOOL'
    # NOTE: KEY AS IV IS VERY BAD IN PRACTICE, SEE #27
    cbc11 = aes_modes.AES_CBC_encrypt(i11, k11, k11)
    ecb11 = aes_modes.AES_ECB_encrypt(i11, k11)
    rcbc = "Detected CBC mode"
    recb = "Detected ECB mode"
    match = oracle.detect_AES_mode(cbc11) == rcbc
    match = match and oracle.detect_AES_mode(ecb11) == recb
    print u'11: {}'.format(retstr(match))

    i12 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
          'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
          'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
          'YnkK'
    e = vanilla_ice_3
    r = set2.break_ecb(i12.decode('base64'))
    print u'12: {}'.format(retstr(match_start(e, r)))

    i13 = 'hax0r@bar.' + padding.pkcs7('admin') + 'com'
    e = 'role=admin'
    r = set2.cut_and_paste(i13)
    print u'13: {}'.format(retstr(e in r))

    i14 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
          'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
          'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
          'YnkK'
    e = vanilla_ice_3
    r = set2.break_ecb(i14.decode('base64'), harder=True)
    print u'14: {}'.format(retstr(match_start(e, r)))

    i15 = 'ICE ICE BABY' + chr(4) * 4
    e = 'ICE ICE BABY'
    r = padding.validate(i15)
    print u'15: {}'.format(retstr(match_start(e, r)))

    e = ';admin=true;'
    r = set2.bitflipping('A' * 16)
    print u'16: {}'.format(retstr(e in r))

    e = vanilla_set
    r = set3.cbc_oracle_attack()
    print u'17: {}'.format(retstr(r in e))

    i18 = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoO' \
          'LSFQ=='
    k18 = 'YELLOW SUBMARINE'
    e = 'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby '
    r = aes_modes.AES_CTR(i18.decode('base64'), k18, 0)
    print u'18: {}'.format(retstr(e == r))

    e = easter_start
    r = set3.break_fixed_nonce1()
    print u'19: {}'.format(retstr(match_start(e, r)))

    e = vanilla_ice_4
    r = set3.break_fixed_nonce2()
    print u'20: {}'.format(retstr(match_start(e, r)))

    e = '2357136044 2546248239 3071714933 3626093760 2588848963'
    r = set3.prng_output()
    print u'21: {}'.format(retstr(e == r))

    e = int(time.time())
    r = set3.crack_mt19937_seed(False, e)
    print u'22: {}'.format(retstr(e == r))
