"""
Benchmark the PyCrypto and cryptography libraries.

(C) 2016  Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function, absolute_import, unicode_literals
import inspect
import time
import types

import Crypto.Cipher.AES
import Crypto.Cipher.Blowfish
import Crypto.Cipher.DES
import Crypto.Cipher.XOR
import Crypto.Cipher.ARC2
import Crypto.Cipher.ARC4
import Crypto.Cipher.CAST
import Crypto.Cipher.DES3
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import Crypto.Hash.MD5
import Crypto.Hash.MD4
import Crypto.Hash.MD2
import Crypto.Hash.SHA
import Crypto.Hash.RIPEMD
import Crypto.Random
import Crypto.Util.number
import Crypto.PublicKey.RSA

from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes

import random

backend = default_backend()


def getCachedValue(cache, bits, generator):
    """ Return and cache large (prime) numbers of specified number of bits """
    if bits not in cache:
        # populate with 2 numbers
        cache[bits] = [generator(bits) for _ in range(2)]

    # rotate, so each call will return a different number
    a = cache[bits]
    cache[bits] = a[1:] + a[:1]
    return cache[bits][0]


bignumbers = {}
def generateNBitNumber(bits):
    # Crypto.Util.number.getRandomNBitInteger
    return getCachedValue(bignumbers, bits, random.getrandbits)


bigprimes = {}     # cache big primes
def generateNBitPrime(bits):
    return getCachedValue(bigprimes, bits, Crypto.Util.number.getPrime)


def generateNBitString(bits):
    return Crypto.Util.number.long_to_bytes(generateNBitNumber(bits))


class Perftest(object):
    """
    Benchmark the test() of childclasses.

    First a few dummy rounds are executed to make sure
    all dynamic initializations are done.
    Then a baseline is established by counting how
    many iterations are executed in 1/20 second.
    Then a 'full' test is run by measuring and executing
    for 1 full second.

    """
    def __init__(self, description):
        self.description = description

    def countrounds(self, to):
        """ count how many iterations of self.test() can be run in the given time span <to> """
        ts = time.clock()
        te = ts+to
        count = 0
        while time.clock() < te:
            self.test()
            count += 1
        return count

    def run(self, counttime, fulltime):
        """ run the test """
        try:
            for _ in range(4):
                self.test()
            nrounds = int(self.countrounds(counttime)*(fulltime/counttime))
            ts = time.clock()
            for _ in range(nrounds):
                self.test()
            te = time.clock()
        except Exception as e:
            print(e)
            te, ts = 1, 0
            nrounds = 0

        print('%8d iter in %8.4f sec : %10.1f iter/sec:  %s' % (nrounds, te-ts, nrounds/(te-ts), self.description))


class TestPythonSysRandom(Perftest):
    """ test PyCrypto SysRandom algorithms """
    def __init__(self, msgbits):
        super(TestPythonSysRandom, self).__init__("sysrand:%d" % (msgbits))
        self.msgbits = msgbits
        self.rng = random.SystemRandom()

    def test(self):
        return self.rng.getrandbits(self.msgbits)


class TestPythonRandom(Perftest):
    """ test PyCrypto PRNG algorithms """
    def __init__(self, msgbits):
        super(TestPythonRandom, self).__init__("random:%d" % (msgbits))
        self.msgbits = msgbits

    def test(self):
        return random.getrandbits(self.msgbits)


class TestPyCryptPRNG(Perftest):
    """ test PyCrypto PRNG algorithms """
    def __init__(self, msgbits):
        super(TestPyCryptPRNG, self).__init__("PRNG:%d" % (msgbits))
        self.msgbits = msgbits

    def test(self):
        return Crypto.Util.number.getRandomNBitInteger(self.msgbits)


class TestGenPrime(Perftest):
    def __init__(self, bits):
        super(TestGenPrime, self).__init__("Crypto.GenPrime:%d" % bits)
        self.bits = bits

    def test(self):
        return Crypto.Util.number.getPrime(self.bits)


class TestPyCryptHash(Perftest):
    """ test PyCrypto hash algorithms """
    def __init__(self, algo, msgbits):
        super(TestPyCryptHash, self).__init__("%s:%d" % (algo.__name__, msgbits))
        self.algo = algo
        self.msg = generateNBitString(msgbits)

    def test(self):
        return self.algo.new(self.msg).digest()


class TestPyCryptCipher(Perftest):
    """ test PyCrypto symmetric ciphers """
    def __init__(self, algo, keybits, msgbits):
        super(TestPyCryptCipher, self).__init__("%s:%d/%d" % (algo.__name__, keybits, msgbits))
        key = generateNBitString(keybits)
        self.cipher = algo.new(key)
        self.msg = generateNBitString(msgbits)

    def test(self):
        return self.cipher.encrypt(self.msg)


class TestPyCryptRsa(Perftest):
    """ test PyCrypto RSA """

    keycache = {}

    def __init__(self, modbits, msgbits):
        super(TestPyCryptRsa, self).__init__("Crypto.RSA:%d/%d" % (modbits, msgbits))
        if modbits not in self.keycache:
            self.keycache[modbits] = Crypto.PublicKey.RSA.generate(modbits, Crypto.Random.new().read)
        self.privkey = self.keycache[modbits]
        self.msg = generateNBitString(msgbits)

    def test(self):
        return self.privkey.encrypt(self.msg, None)


class TestCryptHash(Perftest):
    """ test cryptography hash algorithms """
    def __init__(self, algo, msgbits):
        super(TestCryptHash, self).__init__("cryptography.%s:%d" % (algo.name, msgbits))
        self.algo = algo
        self.msg = generateNBitString(msgbits)

    def test(self):
        h = hashes.Hash(self.algo, backend=backend)
        h.update(self.msg)
        return h.finalize()


class TestCryptCipher(Perftest):
    """ test cryptography symmetric ciphers """
    def __init__(self, algo, keybits, msgbits):
        super(TestCryptCipher, self).__init__("cryptography.%s:%d/%d" % (algo.name, keybits, msgbits))
        try:
            key = generateNBitString(keybits)
            self.cipher = ciphers.Cipher(algo(key), mode=None if algo.name=="RC4" else modes.ECB(), backend=backend)
            self.encryptor = self.cipher.encryptor()
            self.msg = generateNBitString(msgbits)
        except Exception as e:
            print(e)
            self.encryptor = None

    def test(self):
        if self.encryptor:
            return self.encryptor.update(self.msg)


class TestCryptRsa(Perftest):
    """ test cryptography RSA """
    keycache = {}

    def __init__(self, modbits, msgbits):
        super(TestCryptRsa, self).__init__("cryptography.rsa:%d/%d" % (modbits, msgbits))
        if modbits not in self.keycache:
            self.keycache[modbits] = backend.generate_rsa_private_key(65537, modbits)
        self.privkey = self.keycache[modbits]
        self.pubkey = self.privkey.public_key()
        self.msg = generateNBitString(msgbits)

    def test(self):
        self.pubkey.encrypt(self.msg, cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15())


class TestCryptEc(Perftest):
    """ test cryptography Elliptic Curve DH """
    def __init__(self, curve):
        super(TestCryptEc, self).__init__("cryptography.ec:%s" % curve.name)
        self.alice_priv = backend.generate_elliptic_curve_private_key(curve)
        self.bob_priv = backend.generate_elliptic_curve_private_key(curve)
        self.bob_pub = self.bob_priv.public_key()

    def test(self):
        self.alice_priv.exchange(cryptography.hazmat.primitives.asymmetric.ec.ECDH(), self.bob_pub)


class TestModexp(Perftest):
    """ test modular exponentiation for RSA """
    def __init__(self, modbits, msgbits, expbits):
        super(TestModexp, self).__init__("modexp:%d/%d/%d" % (modbits, msgbits, expbits))
        self.msg = generateNBitNumber(msgbits)
        self.exponent = generateNBitNumber(expbits)
        self.modulus = generateNBitPrime(modbits)

    def test(self):
        return pow(self.msg, self.exponent, self.modulus)


class TestLambda(Perftest):
    """ test generic lambda expression """
    def __init__(self, fn):
        super(TestLambda, self).__init__(inspect.getsource(fn).strip())
        self.fn = fn

    def test(self):
        return self.fn()


class TestEval(Perftest):
    """ test string containing a python expression  """
    def __init__(self, fn):
        super(TestEval, self).__init__("eval:"+fn)
        name = "tst_%x" % id(self)
        exec("def %s(): %s" % (name, fn))
        self.test = locals().get(name)


# an empty function
def nop(): pass


def TestArgRange(testname, *args, **kwargs):
    """ generate tests, enumerating through a set of arguments """

    # cur contains the current index set
    cur = [0 for _ in range(len(kwargs))]
    # end contains the max index for the specific args.
    end = [len(_) if type(_)==tuple else 1 for _ in kwargs.values()]
    while True:
        # build arg list
        kw = {}
        for (k, v), i in zip(kwargs.items(), cur):
            if type(v)==tuple:
                kw[k] = v[i]
            else:
                kw[k] = v

        # create test
        yield testname(*args, **kw)

        # increment ix list
        i = 0
        while i<len(cur) and cur[i]==end[i]-1:
            cur[i] = 0
            i += 1
        while i<len(cur) and end[i]==1:
            i += 1
        if i<len(cur):
            cur[i] += 1
        else:
            break


def create_test_list():
    hash_msg_bitsizes = tuple(pow(2, _) for _ in range(8, 24))
    symm_msg_bitsizes = tuple(pow(2, _) for _ in range(8, 24))
    prng_msg_bitsizes = tuple(pow(2, _) for _ in range(8, 18))

    return [
        TestArgRange(TestPythonRandom, msgbits=prng_msg_bitsizes),
        TestArgRange(TestPythonSysRandom, msgbits=prng_msg_bitsizes),
        TestArgRange(TestPyCryptPRNG, msgbits=prng_msg_bitsizes),
        TestArgRange(TestGenPrime, bits=(32, 64, 128, 256, 512)),


        # cryptography symmetric ciphers
        TestArgRange(TestCryptCipher, algorithms.AES,       keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.TripleDES, keybits=64,  msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.TripleDES, keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.TripleDES, keybits=192, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.Blowfish,  keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.CAST5,     keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.ARC4,      keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.IDEA,      keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.SEED,      keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestCryptCipher, algorithms.Camellia,  keybits=256, msgbits=symm_msg_bitsizes),


        # pycrypt symmetric ciphers
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.AES,      keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.DES,      keybits=64,  msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.DES3,     keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.DES3,     keybits=192, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.Blowfish, keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.CAST,     keybits=128, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.ARC4,     keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.XOR,      keybits=256, msgbits=symm_msg_bitsizes),
        TestArgRange(TestPyCryptCipher, Crypto.Cipher.ARC2,     keybits=256, msgbits=symm_msg_bitsizes),


        # cryptography hashes
        TestArgRange(TestCryptHash, hashes.SHA224(),    msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.SHA256(),    msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.SHA384(),    msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.SHA512(),    msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.SHA1(),      msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.MD5(),       msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.RIPEMD160(), msgbits=hash_msg_bitsizes),
        TestArgRange(TestCryptHash, hashes.Whirlpool(), msgbits=hash_msg_bitsizes),

        # pycrypt hashes
        TestArgRange(TestPyCryptHash, Crypto.Hash.SHA224,    msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.SHA256,    msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.SHA384,    msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.SHA512,    msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.SHA,       msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.MD5,       msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.RIPEMD,    msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.MD2,       msgbits=hash_msg_bitsizes),
        TestArgRange(TestPyCryptHash, Crypto.Hash.MD4,       msgbits=hash_msg_bitsizes),

        # cryptography rsa
        TestArgRange(TestCryptRsa, modbits=(1024,2048,4096), msgbits=(2,256,512,1024)),

        # PyCrypto rsa
        TestArgRange(TestPyCryptRsa, modbits=(1024,2048,4096), msgbits=(2,256,512,1024)),

        # now some tests to see how very simple operations perform
        TestEval("pass"),
        TestEval("1+2"),
        TestEval("8*9"),

        TestLambda(nop),
        TestLambda(lambda: 1),
        TestLambda(lambda: 1+2),
        TestLambda(lambda: 1+2+3+4),
        TestLambda(lambda: 8*9),
        TestLambda(lambda: pow(1, 1, 2)),

        # some elliptic curve crypto
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT571R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT409R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT283R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT233R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT163R2),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT571K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT409K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT283K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT233K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECT163K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP521R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP384R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP256R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP256K1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP224R1),
        TestCryptEc(cryptography.hazmat.primitives.asymmetric.ec.SECP192R1),


    ]


def create_modexp_list():
    return [
        TestArgRange(TestModexp, modbits=(128,256,512,1024,2048,4096), msgbits=(2,256,512,1024,2048,4096), expbits=(2,16,128,256,512,1024,2048,4096)),
    ]


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Crypto benchmark')
    parser.add_argument('--modexp', action='store_true')
    args = parser.parse_args()

    if args.modexp:
        tests = create_modexp_list()
    else:
        tests = create_test_list()

    for test in tests:
        if type(test) == types.GeneratorType:
            for item in test:
                item.run(0.005, 0.1)
        elif isinstance(test, Perftest):
            test.run(0.005, 0.1)
        else:
            print("?", test)

if __name__ == '__main__':
    main()
