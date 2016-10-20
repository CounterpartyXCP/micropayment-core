import unittest
from micropayment_core import keys


# openssl ecparam -genkey -name secp256k1 -noout -outform DER -out private.key
DER = open("tests/private.key", 'rb').read()

# openssl ec -inform DER -in private.key -noout -text -conv_form compressed
PRIVKEY = "45c6efba90601d9ff8f6f46550cc4661b940f39761963d82529e555ead8e915b"
PUBKEY = "0200802cc451fa39b0730bb5f37a3670e96e9e8e8ea479381f077ff4730fe2ed0b"

WIF = "cPvLdJrWg1PeudwB2TyTwf34Fdgn93WtKeB1GbUbfyCoNyc65nkR"
ADDRESS = "n4Hdm3aPxk8T816q8FGo5BghNLPNDAcX4v"
NETCODE = "XTN"


class TestKeys(unittest.TestCase):

    def test_der_to_privkey(self):
        privkey = keys.der_to_privkey(DER)
        self.assertEqual(privkey, PRIVKEY)

    def test_privkey_to_der(self):
        der = keys.privkey_to_der(PRIVKEY)
        self.assertEqual(DER, der)

    def test_pubkey_from_privkey(self):
        pubkey = keys.pubkey_from_privkey(PRIVKEY)
        self.assertEqual(pubkey, PUBKEY)

    def test_pubkey_from_der(self):
        pubkey = keys.pubkey_from_der(DER)
        self.assertEqual(pubkey, PUBKEY)

    def test_address_from_privkey(self):
        address = keys.address_from_privkey(PRIVKEY, netcode=NETCODE)
        self.assertEqual(address, ADDRESS)

    def test_address_from_der(self):
        address = keys.address_from_der(DER, netcode=NETCODE)
        self.assertEqual(address, ADDRESS)

    def test_wif_to_privkey(self):
        privkey = keys.wif_to_privkey(WIF)
        self.assertEqual(privkey, PRIVKEY)

    def test_wif_to_der(self):
        der = keys.wif_to_der(WIF)
        self.assertEqual(DER, der)

    def test_der_to_wif(self):
        wif = keys.der_to_wif(DER, netcode=NETCODE)
        self.assertEqual(WIF, wif)

    def test_address_from_wif(self):
        address = keys.address_from_wif(WIF)
        self.assertEqual(address, ADDRESS)

    def test_address_from_pubkey(self):
        address = keys.address_from_pubkey(PUBKEY, netcode=NETCODE)
        self.assertEqual(address, ADDRESS)

    def test_netcode_from_wif(self):
        netcode = keys.netcode_from_wif(WIF)
        self.assertEqual(netcode, NETCODE)

    def test_netcode_from_address(self):
        netcode = keys.netcode_from_address(ADDRESS)
        self.assertEqual(netcode, NETCODE)


if __name__ == "__main__":
    unittest.main()
