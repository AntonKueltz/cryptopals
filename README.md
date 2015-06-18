# cryptopals
Solutions for the [Matasano Crypto Challenges](http://cryptopals.com).

### usage
Run by executing ```./main.py [set number]```. The default is to run all sets. If you wish to run only a certain set, pass the set number as a command line param, (e.g. ```./main.py 2``` to run set 2). Solutions are work in progress, I try to do the challenges sequentially but jump ahead every now and then. There is also a WIP (~20 challenges) test suite that you can run via ```./main.py test```. This will run all the implemented challenges and compare them to the expected output.

A note on Set 4 and Set 5: To run sets 4 and 5 (specifically the HMAC timing challenges and Secure Remote Password challenges) you need to be running the server code in parallel. The easiest way to do this is to just open up another terminal and run ```python server.py``` before running the sets.

### structure
The brunt of each sets code is in the corresponding set python file. Some shared code (mostly math and data formatting) is in util. There are also some files like rsa, dsa, etc. that implement crypto protocols as their own classes.

### dependencies
* [pycrypto](https://www.dlitz.net/software/pycrypto/) ```pip install pycrypto```
* [web](http://webpy.org) ```easy_install web.py```
* [requests](http://docs.python-requests.org/en/latest/) ```pip install requests```

I have only run this code on machines that have python 2.7.x, older versions of python 2 may run into trouble. Note that for python 2.7.6 and below the method used to compare hmacs (the == equality op) is not secure and should be avoided. It is only used for backwards compatibility because hmac's compare_digest method was introduced in python 2.7.7.

### progress
* Set 1 ✓ [8/8 complete]
* Set 2 ✓ [8/8 complete]
* Set 3 ✓ [8/8 complete]
* Set 4 ✓ [8/8 complete]
* Set 5 ✓ [8/8 complete]
* Set 6 ✓ [8/8 complete]
* Set 7 ✗ [2/8 complete]
