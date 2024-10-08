#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test test_file_name.py

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import pytest

try:
    from Lab01Solutions import *
except:
    from Lab01Code import *

@pytest.mark.task1
def test_petlib_present():
    """
    Try to import Petlib and pytest to ensure they are 
    present on the system, and accessible to the python 
    environment.
    """
    import petlib 
    import pytest
    assert True

@pytest.mark.task1
def test_code_present():
    """
    Try to import the code file. 
    This is where the lab answers will be.
    """
    assert True


#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)

@pytest.mark.task2
def test_gcm_encrypt():
    """ Tests encryption with AES-GCM """
    from os import urandom
    K = urandom(16)
    message = u"Hello World!"
    iv, ciphertext, tag = encrypt_message(K, message)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

@pytest.mark.task2
def test_gcm_decrypt():
    """ Tests decryption with AES-GCM """
    from os import urandom
    K = urandom(16)
    message = u"Hello World!"
    iv, ciphertext, tag = encrypt_message(K, message)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    m = decrypt_message(K, iv, ciphertext, tag)
    assert m == message

@pytest.mark.task2
def test_gcm_fails():
    from pytest import raises
    from os import urandom

    K = urandom(16)
    message = u"Hello World!"
    iv, ciphertext, tag = encrypt_message(K, message)

    with raises(Exception) as excinfo:
        decrypt_message(K, iv, urandom(len(ciphertext)), tag)
    assert 'Decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(K, iv, ciphertext, urandom(len(tag)))
    assert 'Decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(K, urandom(len(iv)), ciphertext, tag)
    assert 'Decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(urandom(len(K)), iv, ciphertext, tag)
    assert 'Decryption failed' in str(excinfo.value)


#####################################################
# TASK 3 -- Elliptic Curve Arithmetic

@pytest.mark.task3
def test_on_curve():
    """
    Test if a point is on a curve.
    """
    from petlib.ec import EcGroup
    G = EcGroup(713)  # NIST curve
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx, gy = g.get_affine()

    assert is_point_on_curve(a, b, p, gx, gy)
    assert is_point_on_curve(a, b, p, None, None)

@pytest.mark.task3
def test_point_addition():
    """
    Test whether EC point addition is correct.
    """
    from pytest import raises
    from petlib.ec import EcGroup
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()
    r = G.order().random()
    gx1, gy1 = (r * g).get_affine()

    assert is_point_on_curve(a, b, p, gx0, gy0)
    assert is_point_on_curve(a, b, p, gx1, gy1)

    x, y = point_add(a, b, p, gx0, gy0, gx1, gy1)
    assert is_point_on_curve(a, b, p, x, y)

    assert (x, y) == point_add(a, b, p, gx1, gy1, gx0, gy0)

    x, y = point_add(a, b, p, gx0, gy0, None, None)
    assert x == gx0 and y == gy0

@pytest.mark.task3
def test_point_double():
    """
    Test if EC point doubling is correct.
    """
    from petlib.ec import EcGroup
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()

    x2, y2 = point_double(a, b, p, gx0, gy0)
    assert is_point_on_curve(a, b, p, x2, y2)

    assert (x2, y2) == point_double(a, b, p, gx0, gy0)

@pytest.mark.task3
def test_scalar_mult_double_and_add():
    """
    Test scalar multiplication using the double-and-add algorithm.
    """
    from petlib.ec import EcGroup
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()
    r = G.order().random()

    x, y = point_scalar_multiplication_double_and_add(a, b, p, gx0, gy0, r)
    assert is_point_on_curve(a, b, p, x, y)

@pytest.mark.task3
def test_scalar_mult_montgomery_ladder():
    """
    Test scalar multiplication using the Montgomery Ladder.
    """
    from petlib.ec import EcGroup
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()
    r = G.order().random()

    x, y = point_scalar_multiplication_montgomerry_ladder(a, b, p, gx0, gy0, r)
    assert is_point_on_curve(a, b, p, x, y)


#####################################################
# TASK 4 -- ECDSA Signatures

@pytest.mark.task4
def test_key_gen():
    """ Test the key generation of ECDSA """
    G, priv, pub = ecdsa_key_gen()
    assert priv is not None
    assert pub is not None

@pytest.mark.task4
def test_produce_signature():
    """ Test ECDSA signing """
    msg = u"Test" * 1000
    G, priv, pub = ecdsa_key_gen()
    sig = ecdsa_sign(G, priv, msg)
    assert sig is not None

@pytest.mark.task4
def test_check_signature():
    """ Test ECDSA signature and verification """
    msg = u"Test" * 1000
    G, priv, pub = ecdsa_key_gen()
    sig = ecdsa_sign(G, priv, msg)
    assert ecdsa_verify(G, pub, msg, sig)

@pytest.mark.task4
def test_check_fail():
    """ Ensure verification fails with wrong message """
    msg = u"Test" * 1000
    msg2 = u"Text" * 1000
    G, priv, pub = ecdsa_key_gen()
    sig = ecdsa_sign(G, priv, msg)
    assert not ecdsa_verify(G, pub, msg2, sig)


#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange

@pytest.mark.task5
def test_dh_key_gen():
    """ Test DH key generation """
    G, priv, pub = dh_get_key()
    assert priv is not None
    assert pub is not None

@pytest.mark.task5
def test_dh_encrypt_decrypt():
    """ Test DH encryption and decryption """
    G, priv_bob, pub_bob = dh_get_key()
    message = u"Secret message"
    iv, ciphertext, tag, pub_alice = dh_encrypt(pub_bob, message)

    assert len(ciphertext) == len(message)

    decrypted_message = dh_decrypt(priv_bob, ciphertext, iv, tag, pub_alice)
    assert decrypted_message == message
