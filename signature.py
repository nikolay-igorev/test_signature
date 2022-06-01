import datetime

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def get_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def get_public_key(private_key):
    return private_key.public_key()


def get_certificate(private_key, public_key):
    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(u'cryptography.io')]
        ),
        critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
    )
    cert_string = certificate.public_bytes(Encoding.PEM)
    with open("cert.pem", "w") as cert_file:
        cert_file.write(cert_string.decode())

    return cert_string


def pkcs7_signature_build(file, certificate, private_key):

    cert = x509.load_pem_x509_certificate(certificate)
    private_bytes_string = private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    key = serialization.load_pem_private_key(private_bytes_string, None)
    options = [pkcs7.PKCS7Options.DetachedSignature]

    pkcs7_sign = pkcs7.PKCS7SignatureBuilder().set_data(
         open(file, 'rb').read()
    ).add_signer(
        cert, key, hashes.SHA256()
    ).sign(
        serialization.Encoding.PEM, options
    )

    with open("pkcs7.p7s", "w") as pkcs7_file:
        pkcs7_file.write(pkcs7_sign.decode())


def main():
    private_key = get_private_key()
    public_key = get_public_key(private_key)
    certificate = get_certificate(private_key, public_key)
    pkcs7_signature_build('test.pdf', certificate, private_key)


if __name__ == '__main__':
    main()
