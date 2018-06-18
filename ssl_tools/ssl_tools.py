# /bin/env python3

from OpenSSL import crypto
from base64 import b64decode
from datetime import datetime


class SSLTools:
    """
    This class is used to perform common SSL certificate manipulations and extract commonly used data from SSL
    certificates.
    """

    @staticmethod
    def decode_pkcs12_b64(b64):
        """Static method that takes a pkcs12, base64 encoded string and returns a pkcs12 binary"""
        b64 = b64.replace('-----BEGIN PKCS12-----', '')  # strip out the usual first line, if found
        b64 = b64.replace('-----END PKCS12-----', '')    # strip out the usual last line, if found
        try:
            return b64decode(b64.strip())
        except b64.binascii.Error:
            print('b64 conversion error - string is incorrectly padded')

    @staticmethod
    def pkcs12_to_pem(pkcs12, passwd):
        """Static method that takes a pkcs12 keypair binary and returns the PEM formatted, clear text cert and key"""
        keypair = dict()
        try:
            keypair['key'] = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                                    crypto.load_pkcs12(pkcs12, passwd.encode('utf-8'))
                                                    .get_privatekey())
            keypair['certificate'] = crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                             crypto.load_pkcs12(pkcs12, passwd.encode('utf-8'))
                                                             .get_certificate())
            return keypair
        except crypto.Error:
            print('Error extracting certificate and/or key. Is the password correct?')
            return None

    @staticmethod
    def get_certificate_details(pem_certificate):
        """Static method that takes a PEM certificate and returns a dictionary of certificate information"""
        try:
            x509_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_certificate)
            cert_details = dict()
            cert_details['not_after'] = x509_certificate.get_notAfter().decode()     # formatted as an ASN.1 TIME
            cert_details['not_after'] = datetime.strptime(cert_details['not_after'], '%Y%m%d%H%M%SZ').date().strftime('%m-%d-%Y')
            cert_details['not_before'] = x509_certificate.get_notBefore().decode()   # formatted as an ASN.1 TIME
            cert_details['not_before'] = datetime.strptime(cert_details['not_before'], '%Y%m%d%H%M%SZ').date().strftime('%m-%d-%Y')
            cert_details['serial'] = x509_certificate.get_serial_number()
            cert_details['is_expired'] = x509_certificate.has_expired()
            cert_details['signature_algorithm'] = x509_certificate.get_signature_algorithm().decode()
            cert_details['subject'] = SSLTools.parse_X509_name(x509_certificate.get_subject().get_components())
            cert_details['issuer'] = SSLTools.parse_X509_name(x509_certificate.get_issuer().get_components())
            return cert_details
        except crypto.Error:
            print("Certificate error. Is this a valid PEM file?")
            return None

    @staticmethod
    def parse_X509_name(x509_name):
        subject = dict()
        for item in x509_name:
            str_item = item[0].decode()     # convert bytes to string
            if str_item == 'CN':
                subject['CN'] = item[1].decode()
            elif str_item == 'C':
                subject['C'] = item[1].decode()
            elif str_item == 'ST':
                subject['ST'] = item[1].decode()
            elif str_item == 'L':
                subject['L'] = item[1].decode()
            elif str_item == 'O':
                subject['O'] = item[1].decode()
            elif str_item == 'OU':
                subject['OU'] = item[1].decode()
            elif str_item == 'emailAddress':
                subject['emailAddress'] = item[1].decode()
            elif str_item == 'unstructuredName':
                subject['unstructuredName'] = item[1].decode()
        if len(subject):
            return subject
        else:
            return None





