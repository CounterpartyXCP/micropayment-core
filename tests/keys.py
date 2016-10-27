import json
import unittest
from micropayment_core import keys


FIXTURES = json.load(open("tests/fixtures.json"))


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

    def test_address_from_privkey(self):
        address = keys.address_from_privkey(PRIVKEY, netcode=NETCODE)
        self.assertEqual(address, ADDRESS)

    def test_wif_to_privkey(self):
        privkey = keys.wif_to_privkey(WIF)
        self.assertEqual(privkey, PRIVKEY)

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

    def test_generate_wif(self):
        wif = keys.generate_wif()
        privkey = keys.wif_to_privkey(wif)
        self.assertEqual(len(privkey), 64)

    def test_generate_wif(self):
        privkey = keys.generate_privkey()
        self.assertEqual(len(privkey), 64)

    def test_pem_serialization(self):
        pem = keys.privkey_to_pem(PRIVKEY)
        privkey = keys.pem_to_privkey(pem)
        self.assertEqual(privkey, PRIVKEY)

    def test_pubkey_compression(self):
        uncompressed = keys.uncompress_pubkey(PUBKEY)
        self.assertEqual(len(uncompressed), 65 * 2)  # 65bytes
        compressed = keys.compress_pubkey(uncompressed)
        self.assertEqual(compressed, PUBKEY)


class TestAuth(unittest.TestCase):

    def test_consistancy(self):
        data = "f483"
        wif = keys.generate_wif()
        privkey = keys.wif_to_privkey(wif)
        pubkey = keys.pubkey_from_wif(wif)
        signature = keys.sign(privkey, data)
        valid = keys.verify(pubkey, signature, data)
        self.assertTrue(valid)

    def test_consistancy_sha256(self):
        data = "f483"
        wif = keys.generate_wif()
        privkey = keys.wif_to_privkey(wif)
        pubkey = keys.pubkey_from_wif(wif)
        signature = keys.sign_sha256(privkey, data)
        valid = keys.verify_sha256(pubkey, signature, data)
        self.assertTrue(valid)

    def test_unicode_sha256(self):
        data = u"üöä"
        wif = keys.generate_wif()
        privkey = keys.wif_to_privkey(wif)
        pubkey = keys.pubkey_from_wif(wif)
        signature = keys.sign_sha256(privkey, data)
        valid = keys.verify_sha256(pubkey, signature, data)
        self.assertTrue(valid)

    def test_compatibility(self):

        # https://github.com/Storj/service-middleware/blob/master/test/authenticate.unit.js#L476
        pubkey = FIXTURES["auth_compatibility"]["pubkey"]
        signature = FIXTURES["auth_compatibility"]["signature"]
        data = FIXTURES["auth_compatibility"]["data"]
        valid = keys.verify(pubkey, signature, data)
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
