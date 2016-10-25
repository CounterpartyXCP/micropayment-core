import json
import unittest
from micropayment_core import util


FIXTURES = json.load(open("tests/fixtures.json"))


class TestUtils(unittest.TestCase):

    def test_gettxid(self):
        for txid, rawtx in FIXTURES["transactions"].items():
            result = util.gettxid(rawtx)
            self.assertEqual(result, txid)

    def test_script2address(self):
        for address, script_hex in FIXTURES["scripts"].items():
            result = util.script_address(
                script_hex, netcode="XTN"
            )
            self.assertEqual(result, address)

    def test_hash160(self):
        hex_digest = util.hash160hex("f483")
        expected = "4e0123796bee558240c5945ac9aff553fcc6256d"
        self.assertEqual(hex_digest, expected)

    def test_to_satoshis(self):
        satoshis = util.to_satoshis(1.0)
        self.assertEqual(satoshis, 100000000)


if __name__ == "__main__":
    unittest.main()
