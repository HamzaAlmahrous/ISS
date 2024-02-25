import base64
import jwt
import hashlib
import json
import os
import hmac
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_csr
from cryptography import x509
from cryptography.hazmat.backends import default_backend

SECRET_KEY = 'your_secret_key'

class encryption:
    
    def generate_token(user_id):
        payload = {'user_id': user_id}
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token

    def decode_token(encoded_token):
        try:
            decoded_payload = jwt.decode(encoded_token, SECRET_KEY, algorithms=['HS256'])
            return decoded_payload
        except jwt.ExpiredSignatureError:
            return None  # Token has expired
        except jwt.InvalidTokenError:
            return None  # Token is invalid

    def hash_password(password):
        # Hash the password using SHA-256
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed_password

    def derive_key(password):
        # Derive a key from the national number (this should be stored securely)
        salt = b'some_salt_value'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode('utf-8'))
        return key

    def sym_encrypt_data(data, key):
        data_str = json.dumps(data)
        # Convert the JSON string to bytes
        data_bytes = data_str.encode('utf-8')
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()

        # Generate a random IV (Initialization Vector)
        # iv = os.urandom(algorithms.AES.block_size)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data
        
    def generate_mac(key, data):
        h = hmac.new(key=key, msg=data, digestmod='sha256')
        mac = h.digest()
        mac_hex = h.hexdigest()
        return mac, mac_hex

    def verify_mac(key, data, received_mac):
    # Generate the expected MAC
        mac, mac_hex = encryption.generate_mac(data, key)
        expected_mac = bytes.fromhex(mac_hex)
        if expected_mac == received_mac:
            return True
        else:
            return False

    def sym_decrypt_data(ciphertext, key):
        # Extract the IV from the ciphertext
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        # Create an AES cipher object with the key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        data_bytes = unpadder.update(decrypted_data) + unpadder.finalize()

        # Convert the bytes to a JSON string and then to a dictionary
        data_str = data_bytes.decode('utf-8')
        decrypted_data = json.loads(data_str)

        return decrypted_data
    
    def asym_load_private_key_from_file(private_key_file_path):
        with open(private_key_file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # Provide a password here if your key is encrypted
                backend=default_backend()
            )
        return private_key

    def asym_load_public_key_from_file(public_key_file_path):
        with open(public_key_file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    
    def asym_serialize_public_key_to_pem(public_key):
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem
    
    def asym_encrypt_with_public_key(data_in_bytes, public_key):
        encrypted_data = public_key.encrypt(
            data_in_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data
    
    def asym_decrypt_with_private_key(encrypted_data, private_key):
        decrypted_data = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    
    def generate_unique_salt():
        # Generate a random 16-byte salt
        return os.urandom(16)

    def derive_session_key(existing_key, salt, info):
        new_key_length = len(existing_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=new_key_length,
            salt=salt,
            info=info,
            backend=default_backend()
        )

        return hkdf.derive(existing_key)
        
    def encrypt_data_with_public_key(data, public_key):
        data_bytes = json.dumps(data).encode()

        encrypted_data = public_key.encrypt(
            data_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_data

    def digital_signing(data, private_key):
        data = json.dumps(data).encode()

        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length= padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()
    
    def decrypt_data_with_private_key(encrypted_data, private_key):
        decrypted_data = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_data.decode()

    def verify_signature(original_data, signature, public_key):

        data = original_data.encode()

        decoded_signature = base64.b64decode(signature)

        try:
            public_key.verify(
                decoded_signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
        
    def create_csr(common_name, title, email, private_key):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.TITLE, title),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(private_key, hashes.SHA256())

        csr_pem = csr.public_bytes(Encoding.PEM)

        with open("client_csr.pem", "wb") as f:
            f.write(csr_pem)

        return csr_pem
    
    def load_csr_pem():
        with open("client_csr.pem", "rb") as f:
            csr_pem = f.read()
            csr = load_pem_x509_csr(csr_pem)
        return csr
    
    def load_certificate_pem(certificate_name):
        with open(certificate_name, "rb") as cert_file:
            ca_certificate_pem = cert_file.read()
        return ca_certificate_pem

    def verify_certificate(client_certificate_pem, ca_certificate_pem):
        # print(client_certificate_pem)
        # print(ca_certificate_pem)
        client_certificate = x509.load_pem_x509_certificate(client_certificate_pem, default_backend())

        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem, default_backend())

        ca_public_key = ca_certificate.public_key()

        certificate_public_key = client_certificate.public_key()
        # Serialize the public key to PEM format
        public_key_pem = certificate_public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        public_key = public_key_pem.decode()

        # subject = client_certificate.subject

        # for attribute in subject:
        #     print(f"{attribute.oid._name}: {attribute.value}")

        signature_algorithm = client_certificate.signature_hash_algorithm

        try:
            ca_public_key.verify(
                signature = client_certificate.signature,
                data = client_certificate.tbs_certificate_bytes,
                algorithm = signature_algorithm,
                padding = padding.PKCS1v15(),
            )
            return True , public_key
        except Exception as e:
            print(f"Verification failed: {e}")
            return False , ''

    def get_certificate_data(client_certificate_pem):
        certificate = x509.load_pem_x509_certificate(client_certificate_pem, default_backend())

        subject = certificate.subject
        print(subject)

        title = None
        common_name = None
        email_address = None

        for attribute in subject:
            if attribute.oid == x509.NameOID.TITLE:
                title = attribute.value
            elif attribute.oid == x509.NameOID.COMMON_NAME:
                common_name = attribute.value
            elif attribute.oid == x509.NameOID.EMAIL_ADDRESS:
                email_address = attribute.value

        return title, common_name, email_address