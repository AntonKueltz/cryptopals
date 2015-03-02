import mac
import util


def sha1mac():
    msg = 'Some super secret thing I dont want to share'
    key = util.gen_random_bytes(16)
    auth = mac.sha1mac(key, msg)
    testpassed = 0

    try:
        assert(mac.authenticate(key, msg, auth) == True)
        testpassed += 1
        print 'Correct MAC accepted'
    except:
        print 'Correct MAC erroneously rejected'
    try:
        badauth = mac.sha1mac(util.gen_random_bytes(16), msg)
        assert(mac.authenticate(key, msg, badauth) == True)
        print 'Tampered MAC erroneously accepted'
    except:
        testpassed += 1
        print 'Tampered MAC rejected'
    try:
        badmsg = 'I didnt write this'
        assert(mac.authenticate(key, badmsg, auth) == True)
        print 'Tampered message erroneously accepted'
    except:
        testpassed += 1
        print 'Tampered message rejected'

    if testpassed == 3:
        return 'All Tests Passed!'
    else:
        return 'Not All Tests Passed :('
