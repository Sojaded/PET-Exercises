#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib
import pytest
#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement an encryption and decryption function
# that performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """
    plaintext = message.encode("utf8")
    aes = Cipher("aes-128-gcm")  # Using AES GCM mode
    iv = urandom(16)  # Generate a random IV
    enc = aes.enc(K, iv)  # Initialize the encryption context
    ciphertext, tag = enc.update(plaintext) + enc.finalize(), enc.get_tag()
    
    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K. 
        In case decryption fails, throw an exception.
    """
    aes = Cipher("aes-128-gcm")
    dec = aes.dec(K, iv)  # Initialize the decryption context
    dec.set_tag(tag)
    try:
        plaintext = dec.update(ciphertext) + dec.finalize()
    except:
        raise Exception("decryption failed")
    
    return plaintext.decode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
# - Test if a point is on a curve.
# - Implement Point addition.
# - Implement Point doubling.
# - Implement Scalar multiplication (double & add).
# - Implement Scalar multiplication (Montgomery ladder).
# MUST NOT USE ANY OF THE petlib.ec FUNCTIONS. Only petlib.bn!

from petlib.bn import Bn

def is_point_on_curve(a, b, p, x, y):
    """
    Check if a point (x, y) is on the curve defined by a, b, and prime p.
    An Elliptic Curve on a prime field p is defined as:
    y^2 = x^3 + ax + b (mod p)
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x is None and y is None)

    if x is None and y is None:
        return True
    
    lhs = (y * y) % p  # y^2 mod p
    rhs = (x * x * x + a * x + b) % p  # x^3 + ax + b mod p
    return lhs == rhs

def is_none_point(x, y):
    """Helper function to check if a point is None (the identity point)"""
    return x is None and y is None

def point_add(a, b, p, x0, y0, x1, y1):
    """
    EC point addition:
    (xr, yr) = (x0, y0) + (x1, y1)
    """
    if is_none_point(x0, y0):
        return (x1, y1)
    if is_none_point(x1, y1):
        return (x0, y0)

    # Raise exception if points are identical
    if x0 == x1 and y0 == y1:
        raise Exception("EC Points must not be equal")

    if x0 == x1 and y0 == (p - y1) % p:
        return (None, None)

    lam = ((y1 - y0) * (x1 - x0).mod_inverse(p)) % p
    xr = (lam * lam - x0 - x1) % p
    yr = (lam * (x0 - xr) - y0) % p
    return xr, yr

def point_double(a, b, p, x, y):
    """
    EC point doubling:
    (xr, yr) = 2 * (x, y)
    """
    if y is None or y == 0:
        return (None, None)

    lam = ((3 * x * x + a) * (2 * y).mod_inverse(p)) % p
    xr = (lam * lam - 2 * x) % p
    yr = (lam * (x - xr) - y) % p
    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Scalar multiplication using double and add algorithm:
    Q = r * P
    """
    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Scalar multiplication using Montgomery ladder algorithm:
    r * (x, y)
    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(scalar.num_bits())):
        if scalar.is_bit_set(i):
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])
        else:
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])

    return R0






#####################################################
# TASK 4 -- Standard ECDSA signatures

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing and the corresponding public key. """
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)

def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature. """
    digest = sha256(message.encode("utf8")).digest()
    sig = do_ecdsa_sign(G, priv_sign, digest)
    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message. """
    digest = sha256(message.encode("utf8")).digest()
    return do_ecdsa_verify(G, pub_verify, sig, digest)

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
from petlib.ec import EcGroup
from petlib.bn import Bn
from petlib.cipher import Cipher
from os import urandom

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()  # Private key for the user
    pub_enc = priv_dec * G.generator()  # Public key
    return (G, priv_dec, pub_enc)

def dh_encrypt(pub, message, aliceSig=None):
    """ Encrypt a message for Bob using his public key and optionally sign with Alice's key. """
    G, priv_dec, pub_enc = dh_get_key()
    shared_key = (priv_dec * pub).export()  # Derive shared key

    # Adjust key length to 16 bytes (AES-128)
    key_length = 16
    if len(shared_key) < key_length:
        shared_key = shared_key.ljust(key_length, b'\0')  # Pad with zeros
    elif len(shared_key) > key_length:
        shared_key = shared_key[:key_length]  # Truncate

    # Initialize AES-GCM cipher
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)  # Initialization vector
    enc = aes.enc(shared_key, iv)  # Encryptor object
    ciphertext = enc.update(message.encode("utf8")) + enc.finalize()
    tag = enc.get_tag()  # Get authentication tag
    
    return (iv, ciphertext, tag, pub_enc)

def dh_decrypt(priv, ciphertext, iv, tag, pub_enc, aliceVer=None):
    """ Decrypt a received message using Bob's private key and verify if signed by Alice. """
    shared_key = (priv * pub_enc).export()
    
    # Adjust key length for decryption
    key_length = 16
    if len(shared_key) < key_length:
        shared_key = shared_key.ljust(key_length, b'\0')
    elif len(shared_key) > key_length:
        shared_key = shared_key[:key_length]
    
    # Initialize AES-GCM cipher for decryption
    aes = Cipher("aes-128-gcm")
    dec = aes.dec(shared_key, iv)
    dec.set_tag(tag)  # Set the tag for verification
    
    try:
        plaintext = dec.update(ciphertext) + dec.finalize()
    except Exception as e:
        raise Exception("Decryption failed: " + str(e))

    return plaintext.decode("utf8")

# Example Usage
if __name__ == "__main__":
    G, priv_alice, pub_alice = dh_get_key()
    G, priv_bob, pub_bob = dh_get_key()
    
    message = "Hello, Bob!"
    iv, ciphertext, tag, pub_enc = dh_encrypt(pub_bob, message)

    try:
        decrypted_message = dh_decrypt(priv_bob, ciphertext, iv, tag, pub_enc)
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"Error: {e}")


#####################################################
# Task 6 - Time scalar multiplication (Open Task)

import time

def time_scalar_mul(a, b, p, x, y, scalar):
    """ Measure time taken to perform scalar multiplication. """
    start_time = time.process_time()
    point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar)
    end_time = time.process_time()
    return end_time - start_time

# Tests
def test_encrypt():
    key = urandom(16)
    message = "Test message"
    iv, ciphertext, tag = encrypt_message(key, message)
    assert len(ciphertext) == len(message)

def test_decrypt():
    key = urandom(16)
    message = "Test message"
    iv, ciphertext, tag = encrypt_message(key, message)
    plaintext = decrypt_message(key, iv, ciphertext, tag)
    assert plaintext == message

def test_fails():
    key = urandom(16)
    message = "Test message"
    iv, ciphertext, tag = encrypt_message(key, message)
    with pytest.raises(Exception):
        decrypt_message(key, iv, ciphertext[:-1], tag)

