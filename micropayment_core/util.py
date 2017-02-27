# coding: utf-8
# Copyright (c) 2016 Fabian Barkhau <fabian.barkhau@gmail.com>
# License: MIT (see LICENSE file)


import codecs
import contextlib
import sys
from decimal import Decimal
from io import StringIO


from pycoin.tx import Tx
from pycoin.serialize import b2h
from pycoin.serialize import h2b
from pycoin.serialize import b2h_rev
from pycoin import encoding
from pycoin.ui import address_for_pay_to_script


def gettxid(rawtx):
    Tx.ALLOW_SEGWIT = False  # XXX so so bad!!
    return b2h_rev(Tx.from_hex(rawtx).hash())


def script_address(script_hex, netcode="BTC"):
    return address_for_pay_to_script(h2b(script_hex), netcode=netcode)


def hash160hex(hexdata):
    return b2h(encoding.hash160(h2b(hexdata)))


def to_satoshis(btc_quantity):
    return int(Decimal(str(btc_quantity)) * Decimal("100000000"))


def bytestoint(data):
    return int(codecs.encode(data, 'hex_codec'), 16)


def load_tx(get_txs_func, rawtx):
    Tx.ALLOW_SEGWIT = False
    tx = Tx.from_hex(rawtx)

    unspent_info = {}  # txid -> index
    for txin in tx.txs_in:
        unspent_info[b2h_rev(txin.previous_hash)] = txin.previous_index
    utxo_rawtxs = get_txs_func(list(unspent_info.keys()))

    for utxo_txid, utxo_rawtx in utxo_rawtxs.items():
        utxo_tx = Tx.from_hex(utxo_rawtx)
        prev_index = unspent_info[utxo_txid]
        tx.unspents.append(utxo_tx.txs_out[prev_index])
    return tx


@contextlib.contextmanager
def xxx_capture_out():
    oldout, olderr = sys.stdout, sys.stderr
    try:
        out = [StringIO(), StringIO()]
        sys.stdout, sys.stderr = out
        yield out
    finally:
        sys.stdout, sys.stderr = oldout, olderr
        out[0] = out[0].getvalue()
        out[1] = out[1].getvalue()
