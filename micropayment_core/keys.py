# coding: utf-8
# Copyright (c) 2016 Fabian Barkhau <fabian.barkhau@gmail.com>
# License: MIT (see LICENSE file)


from ecdsa import SigningKey
from ecdsa.curves import SECP256k1
from pycoin.serialize import b2h, h2b
from pycoin.key import Key
from pycoin import encoding, networks
from pycoin.ecdsa import sign as ecdsa_sign
from pycoin.ecdsa import verify as ecdsa_verify
from pycoin.ecdsa import generator_secp256k1 as G
from micropayment_core import util
import ecdsa


# Formats (DER = PEM = WIF = PrivKey > PubKey > Address)
# * DER: Private key in binary encoded DER format.
# * PEM: Private key in base64 encoded PEM format.
# * Wif: Private key in bitcoin wallet import format
# * PrivKey: Hex encoded 32Byte secret exponent.
# * PubKey: Hex encoded 33Byte compressed public key
# * Address: Bitcoin address format


# TODO add functions
# pem_to_der
# pem_to_wif
# pem_to_privkey
# der_to_pem
# wif_to_pem
# privkey_to_pem
# pubkey_from_pem
# address_from_pem


def pubkey_from_wif(wif):
    """ Get public key from given bitcoin wif.

    Args:
        wif (str): Private key encode in bitcoin wif format.

    Return:
        str: Hex encoded 33Byte compressed public key.
    """
    return b2h(Key.from_text(wif).sec())


def pubkey_from_der(der):
    """ Get public key from given DER encoded private key.

    Args:
        der (bytes): Private key in binary encoded DER format.

    Return:
        str: Hex encoded 33Byte compressed public key.
    """
    return pubkey_from_privkey(der_to_privkey(der))


def address_from_privkey(privkey, netcode="BTC"):
    """ Get bitcoin address from given private key.

    Args:
        privkey (str): Hex encoded 32Byte secret exponent.
        netcode (str): Netcode for resulting bitcoin address.

    Return:
        str: Bitcoin address
    """
    return address_from_pubkey(pubkey_from_privkey(privkey), netcode=netcode)


def address_from_der(der, netcode="BTC"):
    """ Get bitcoin address from given DER encoded private key.

    Args:
        der (bytes): Private key in binary encoded DER format.
        netcode (str): Netcode for resulting bitcoin address.

    Return:
        str: Bitcoin address
    """
    return address_from_pubkey(pubkey_from_der(der), netcode=netcode)


def der_to_privkey(der):
    """ Get private key from given DER encoded private key format.

    Args:
        der (bytes): Private key in binary encoded DER format.

    Return:
        str: Hex encoded 32Byte secret exponent
    """
    sk = SigningKey.from_der(der)
    # FIXME assert is secp256k1 private key
    return b2h(sk.to_string())


def privkey_to_der(privkey):
    """ Get private key in DER encoded fromat.

    Args:
        privkey (str): Hex encoded private key

    Return:
        str: Private key in binary encoded DER format.
    """
    return SigningKey.from_string(h2b(privkey), curve=SECP256k1).to_der()


def wif_to_privkey(wif):
    """ Get private key from given bitcoin wif.

    Args:
        wif (str): Private key encode in bitcoin wif format.

    Return:
        str: Hex encoded 32Byte secret exponent
    """
    return b2h(encoding.to_bytes_32(Key.from_text(wif).secret_exponent()))


def wif_to_der(wif):
    """ Get private key in DER encoded format from given bitcoin wif.

    Args:
        wif (str): Private key encode in bitcoin wif format.

    Return:
        str: Private key in binary encoded DER format.
    """
    return privkey_to_der(wif_to_privkey(wif))


def privkey_to_wif(privkey, netcode="BTC"):
    """ Get private key from bitcoin wif.

    Args:
        privkey (str): Hex encoded private key

    Return:
        str: Private key encode in bitcoin wif format.
    """
    prefix = networks.wif_prefix_for_netcode(netcode)
    secret_exponent = encoding.from_bytes_32(h2b(privkey))
    return encoding.secret_exponent_to_wif(secret_exponent, wif_prefix=prefix)


def der_to_wif(der, netcode="BTC"):
    """ Get DER encoded private key from given bitcoin wif.

    Args:
        der (bytes): Private key in binary encoded DER format.
        netcode (str): Netcode for resulting bitcoin address.

    Return:
        str: Private key encode in bitcoin wif format.
    """
    return privkey_to_wif(der_to_privkey(der), netcode=netcode)


def pubkey_from_privkey(privkey):
    """ Get public key from given private key.

    Args:
        privkey (str): Hex encoded private key

    Return:
        str: Hex encoded 33Byte compressed public key
    """
    return pubkey_from_wif(privkey_to_wif(privkey))


def address_from_pubkey(pubkey, netcode="BTC"):
    """ Get bitcoin address from given public key.

    Args:
        pubkey (str): Hex encoded 33Byte compressed public key
        netcode (str): Netcode for resulting bitcoin address.

    Return:
        str: Bitcoin address
    """
    prefix = networks.address_prefix_for_netcode(netcode)
    public_pair = encoding.sec_to_public_pair(h2b(pubkey))
    return encoding.public_pair_to_bitcoin_address(
        public_pair, address_prefix=prefix
    )


def address_from_wif(wif):
    """ Get bitcoin address from given bitcoin wif.

    Args:
        wif (str): Private key encode in bitcoin wif format.

    Return:
        str: Bitcoin address
    """
    return Key.from_text(wif).address()


def netcode_from_wif(wif):
    """ Returns netcode for given bitcoin wif. """
    return Key.from_text(wif).netcode()


def netcode_from_address(address):
    """ Returns netcode for given bitcoin address. """
    return Key.from_text(address).netcode()


def uncompress_pubkey(pubkey):
    """ Convert compressed public key to uncompressed public key.

    Args:
        pubkey (str): Hex encoded 33Byte compressed public key

    Return:
        str: Hex encoded uncompressed 65byte public key (4 + x + y).
    """
    compressed_pubkey = h2b(pubkey)
    public_pair = encoding.sec_to_public_pair(compressed_pubkey)
    return b2h(encoding.public_pair_to_sec(public_pair, compressed=False))


def sign(privkey, data):
    """ Sign data with given private key.

    Args:
        privkey (str): Hex encoded private key
        data (str): Hex encoded data to be signed.

    Return:
        str: Hex encoded signature in DER format.
    """
    wif = privkey_to_wif(privkey)
    e = util.bytestoint(h2b(data))
    secret_exponent = Key.from_text(wif).secret_exponent()
    r, s = ecdsa_sign(G, secret_exponent, e)
    return b2h(ecdsa.util.sigencode_der(r, s, G.order()))


def verify(pubkey, signature, data):
    """ Verify data is signed by private key.

    Args:
        pubkey (str): Hex encoded 33Byte compressed public key
        signature (str): Hex encoded signature in DER format.

    Return:
        bool: True if signature is valid.
    """
    public_pair = encoding.sec_to_public_pair(h2b(pubkey))
    val = util.bytestoint(h2b(data))
    sig = ecdsa.util.sigdecode_der(h2b(signature), G.order())
    return ecdsa_verify(G, public_pair, val, sig)
