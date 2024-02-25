from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
import datetime

# Generate a private key for the CA
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Information for the CA's certificate
ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SY"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Damascus"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Damascus"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Damascus"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"University CA"),
])

# Create a self-signed root certificate for the CA
ca_certificate = x509.CertificateBuilder().subject_name(
    ca_subject
).issuer_name(
    ca_subject
).public_key(
    ca_private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Valid for 10 years
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(ca_private_key, hashes.SHA256())

# Save CA's private key and certificate
with open("ca_private_key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

with open("ca_certificate.pem", "wb") as f:
    f.write(ca_certificate.public_bytes(Encoding.PEM))
