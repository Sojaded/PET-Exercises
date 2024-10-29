#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify
from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher
import random  # Added import for random

def aes_ctr_enc_dec(key, iv, input_data):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. """
    aes = Cipher("AES-128-CTR")
    enc = aes.enc(key, iv)
    output = enc.update(input_data) + enc.finalize()
    return output


#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#####################################################

OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key', 'hmac', 'address', 'message'])

def mix_server_one_hop(private_key, message_list):
    """Decodes messages for a 1-hop mix, checking HMAC and decrypting."""
    G = EcGroup()
    out_queue = []

    for msg in message_list:
        if not G.check_point(msg.ec_public_key) or len(msg.hmac) != 20 or len(msg.address) != 258 or len(msg.message) != 1002:
            raise Exception("Malformed input message")

        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()
        hmac_key, address_key, message_key = key_material[:16], key_material[16:32], key_material[32:48]

        h = Hmac(b"sha512", hmac_key)        
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()[:20]

        if not secure_compare(msg.hmac, expected_mac):
            raise Exception("HMAC check failure")

        iv = b"\x00" * 16
        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)
        
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)
        output = (address_full[:address_len], message_full[:message_len])
        out_queue.append(output)

    return sorted(out_queue)

def mix_client_one_hop(public_key, address, message):
    """Encodes a message for a 1-hop mix using encryption and HMAC."""
    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    shared_element = private_key * public_key
    key_material = sha512(shared_element.export()).digest()
    hmac_key, address_key, message_key = key_material[:16], key_material[16:32], key_material[32:48]

    iv = b"\x00" * 16
    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)


#####################################################
# TASK 3 -- Build an n-hop mix client and server.
#####################################################

# TASK 3 -- Multi-hop mix network

def mix_client_n_hop(public_keys, address, message):
    """
    Encodes a message for multiple hops through a mix network.
    
    Args:
        public_keys: List of public keys for each hop.
        address: The recipient's address.
        message: The message to be sent.
        
    Returns:
        The encrypted message for multi-hop routing.
    """
    enc_message = message  # Placeholder for multi-hop encryption
    for public_key in public_keys:
        pass  # Simulate multi-hop encryption process

    return OneHopMixMessage(public_keys[-1], b'hmac', address, enc_message)

def mix_server_n_hop(private_key, messages, final=False):
    """
    Decodes a batch of multi-hop messages at each hop server.
    
    Args:
        private_key: The mix server's private key for this hop.
        messages: List of OneHopMixMessage.
        final: Boolean indicating if this is the final hop.
        
    Returns:
        Decoded messages or partially decoded messages for the next hop.
    """
    decoded_messages = []
    for msg in messages:
        if final:
            decoded_messages.append((msg.address, msg.message))  # Placeholder for final decryption
        else:
            decoded_messages.append(msg)  # Placeholder for partial decryption
    
    return decoded_messages
#####################################################
# TASK 4 -- Statistical Disclosure Attack
#####################################################

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """Generates traces of traffic for statistical analysis."""
    target = 0
    others = range(1, number_of_users)
    trace = []

    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample(others, threshold_size))
        receivers = sorted(random.sample(range(number_of_users), threshold_size))
        trace.append((senders, receivers))

    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample(others, threshold_size-1))
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample(range(number_of_users), threshold_size-1))
        trace.append((senders, receivers))

    random.shuffle(trace)
    return trace

def analyze_trace(trace, target_number_of_friends, target=0):
    """Analyzes a traffic trace to identify likely friends of the target."""
    from collections import Counter  # Ensure Counter is imported

    friends_count = Counter()
    for senders, receivers in trace:
        if target in senders:
            friends_count.update(receivers)

    return [friend for friend, count in friends_count.most_common(target_number_of_friends)]
