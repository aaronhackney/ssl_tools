# -*- coding: utf-8 -*-
# Import statements
# =================
import unittest
from hashlib import md5
from ssl_tools.ssl_tools import SSLTools


class TestSSLTools(unittest.TestCase):

    pkcs_12_password = 'abc123!'

    pkcs12_b64_encoded_keypair = """
    -----BEGIN PKCS12-----
    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
    AgQA
    -----END PKCS12-----
    """

    pem_keypair = {
        'key': """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDyRSHLdribR/Kc
xtBZZrDP84lIMHRWfWCYqrdqBEj9iaXJ3Ahd47ZDlT6EVEzgi13+PfCtZ6rCo1Eo
j6LM2FR/osxKGA2VVdTMC1WJnPwg+DciyGjN6JJu59ogVd4FnOpMoIanzL0TCn91
pvT/KM0Gn9rKax/OkujLIU7hKp/2oGItXsInUYF2PVy/GPw56VqI8NU3J9xlFKWH
XMmeMmNpLsQUA5qWKQEFESpMSgMbKUsM/FJrHZ08YgEYYpo30XFUmcE35D2wq2Kh
FVITamYEo+6582J/EiIKrLPtjiFM2fe10mDK5fr5u1vYOwjAUtJdqkC7Pho00xRf
wIr23uJBAgMBAAECggEAPAAEkF4Q9r4RFyRC7d05nWrIXVVIvrHS5kRjY9F3XTlF
krJYbR5L4b14y++P0Y2ag/CFpoB14Tnuy9+U12wdMzYXp6MA3DLzXmxRLSFwrN6k
Uww0rogymd54Xkk90QCNY1hfOPgC/I/9RJ9KblYFvuYAmuCAclneZw5S+X9jugF/
q/qP3Z9Av+8oVvKiHfyJO/+CX2jl3J58hwr5+cu9TTZxQ1W/BPV8AX8hGW5bL62o
ZyJiWBICUQmrG8AsEI9uTCAF2K/ct3m03to+otMtBnaxFUGofwbMIbfsnu/ZZv9D
lf5U4Ca8+kQHF2fF/58sSwh6x+f6ac5npZkxuBW8RQKBgQD5n6xFmWs/2FYd0Tlj
hdi+CuLPYbG5FxYEbQV4DYD9vLRiFA2/jc6BQ/HNSChfceEEDTxbHVDNkH/++X8/
ngk4286vPXNZFxmmIk0MJpsrzqrZE7kxiXtuA2O9uKTHnkNB9maFcmz5lMsEgTXT
8OZQaSmhT+C6g00aPu1gYN57jQKBgQD4dV9N/qzTnL7YFzOqwM6CU0KTMEN77SJM
7qy+ClnZpmDM1q34fA6KAb+SQV92OlpGxgqiLykH8nMK0w2kmgzhczFhEv/dVdLS
91qGLGAw7jFWKOgkevfpKXOM1CK8vWaDAOHvnRLRL3xTGyZipJdBqLgQ7JzTWlXu
RGkDIGX6hQKBgQDlOiGikC4SpQD/xJ/kqobMjYaWVeo0Q+TuD4dUJWJsn5st7ahq
XThjMBeeIUMh0puFcvoX2aXX/3fqlwapTuC9G+yCs/V2vGXLT/hczh70bYYqbZhE
yzFTZz1yfVqkDMtKiZC/vsIftulvq4/YnoGBGfEmtwlxfR2SmnK1bH8iCQKBgQCg
U40GVVrMyo7T/lTW0MfxjSyesjw50dGad0F8+Ez2h8hbJgTpHZR8NZibFhg1wH3U
waLG+Uuu1yKpT3u0RbweFyk8DPiSqPj8LaV6g1Qm/u1TPd5e/ALRsG/h5lnsFQP7
cSxaZK9p0QyWzCQ+7xqzwd3U/fpM4DQnJnnlDJkByQKBgFWbBuivWTW2oZdhEDcg
TdDtEmtU/TeGWk/MO81UN0Id0vYDa5kYqjaVyuqYz/hwSCiztuK4cAA4e/U+hjKs
HD1iE4tO1mnD/i8Ufd+k0KWtr14AZJDQqJ6DJHSQGyuEKNSvD3fmKVWzso48+6Z0
YQdOxOfTfpHZo4u2PILtsaGZ
-----END PRIVATE KEY-----""",
        'certificate': """-----BEGIN CERTIFICATE-----
MIIDgDCCAmigAwIBAgIE4xQEWzANBgkqhkiG9w0BAQsFADCBgTEUMBIGA1UEBxML
U2FuIEFudG9uaW8xDjAMBgNVBAgTBVRleGFzMQswCQYDVQQGEwJVUzESMBAGA1UE
ChMJTXlDb21wYW55MRgwFgYDVQQDEw9taXRtLmRvbWFpbi5pbnQxHjAcBgkqhkiG
9w0BCQIWD21pdG0uZG9tYWluLmludDAeFw0xODA1MjIxNDEzMDVaFw0yODA1MTkx
NDEzMDVaMIGBMRQwEgYDVQQHEwtTYW4gQW50b25pbzEOMAwGA1UECBMFVGV4YXMx
CzAJBgNVBAYTAlVTMRIwEAYDVQQKEwlNeUNvbXBhbnkxGDAWBgNVBAMTD21pdG0u
ZG9tYWluLmludDEeMBwGCSqGSIb3DQEJAhYPbWl0bS5kb21haW4uaW50MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8kUhy3a4m0fynMbQWWawz/OJSDB0
Vn1gmKq3agRI/YmlydwIXeO2Q5U+hFRM4Itd/j3wrWeqwqNRKI+izNhUf6LMShgN
lVXUzAtViZz8IPg3IshozeiSbufaIFXeBZzqTKCGp8y9Ewp/dab0/yjNBp/aymsf
zpLoyyFO4Sqf9qBiLV7CJ1GBdj1cvxj8OelaiPDVNyfcZRSlh1zJnjJjaS7EFAOa
likBBREqTEoDGylLDPxSax2dPGIBGGKaN9FxVJnBN+Q9sKtioRVSE2pmBKPuufNi
fxIiCqyz7Y4hTNn3tdJgyuX6+btb2DsIwFLSXapAuz4aNNMUX8CK9t7iQQIDAQAB
MA0GCSqGSIb3DQEBCwUAA4IBAQAnOCTiw5ytLAOOiyZUncDnwpx2DaqjbE7IO56Y
QYQp3qYKf4PvXRZ1AZIYNEMFXpH6B31NqNlMCweTDShaYaJMhteZi1dY35F631Qf
IHbG6MTh67szRVw1UL8boGq+x+JagbBse3ro02I8aJMBNdiRGwx0a0tE9TdfApgG
opUIALFOyVj2FwYuz7IwmQjRZ//yA0yAtg8p/sU66Ie1LqEmi/8Z4ezelKNcuGOM
tJFh7UxOwgnneCq5admAddG6YEBfx5uLeH5dBWHcqME2R7a/6XwG6Nm2p4KHcLtu
0hhehy++dAmZU33X4x9Q9OH6vhm6wKsk8Jj+FOla0Dx6zM1X
-----END CERTIFICATE-----"""}

    pkcs12_md5_signature = 'f7bdeefb62e8a84fc16de1469babe4fe'

    def setUp(self):
        self.ssl_tool = SSLTools()

    def test_decode_pkcs12_b64(self):
        """decode_pkcs12_b64 returns a byte string. Hash the byte string and compare against our known value"""
        pkcs12_bin = self.ssl_tool.decode_pkcs12_b64(self.pkcs12_b64_encoded_keypair)
        md5_hash = md5(pkcs12_bin).hexdigest()
        self.assertEqual(md5_hash, 'f7bdeefb62e8a84fc16de1469babe4fe')

    def test_pkcs12_to_pem_key(self):
        pkcs12_bin = self.ssl_tool.decode_pkcs12_b64(self.pkcs12_b64_encoded_keypair)
        pem = self.ssl_tool.pkcs12_to_pem(pkcs12_bin, self.pkcs_12_password)
        self.assertEqual(self.pem_keypair['key'].strip(), pem['key'].decode().strip())

    def test_pkcs12_to_pem_certificate(self):
        pkcs12_bin = self.ssl_tool.decode_pkcs12_b64(self.pkcs12_b64_encoded_keypair)
        pem = self.ssl_tool.pkcs12_to_pem(pkcs12_bin, self.pkcs_12_password)
        self.assertEqual(self.pem_keypair['certificate'].strip(), pem['certificate'].decode().strip())

    def test_get_certificate_details(self):
        details = self.ssl_tool.get_certificate_details(self.pem_keypair['certificate'].strip())

        with self.subTest("not_after"):
            self.assertEqual('05-19-2028', details['not_after'])
        with self.subTest("not_before"):
            self.assertEqual('05-22-2018', details['not_before'])
        with self.subTest("serial"):
            self.assertEqual(-485227429, details['serial'])
        with self.subTest("is_expired"):
            self.assertEqual(False, details['is_expired'])
        with self.subTest("signature_algorithm"):
            self.assertEqual('sha256WithRSAEncryption', details['signature_algorithm'])

    def test_get_certificate_details_subject(self):
        details = self.ssl_tool.get_certificate_details(self.pem_keypair['certificate'].strip())

        with self.subTest("L - localityName"):
            self.assertEqual('San Antonio', details['subject']['L'])
        with self.subTest("ST - stateOrProvinceName"):
            self.assertEqual('Texas', details['subject']['ST'])
        with self.subTest("C - countryName"):
            self.assertEqual('US', details['subject']['C'])
        with self.subTest("O - organizationName"):
            self.assertEqual('MyCompany', details['subject']['O'])
        with self.subTest("CN - commonName"):
            self.assertEqual('mitm.domain.int', details['subject']['CN'])






if __name__ == '__main__':
    unittest.main()
