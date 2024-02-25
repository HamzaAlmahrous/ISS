from flask import Flask, request, jsonify
import os
import datetime
import random
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

app = Flask(__name__)

# Dictionary to store challenges for each CSR
challenges = {}

@app.route('/submit_csr', methods=['POST'])
def submit_csr():
    csr_pem = request.data
    csr = x509.load_pem_x509_csr(csr_pem)

    # Generate a simple mathematical challenge
    a, b = random.randint(1, 100), random.randint(1, 100)
    challenge = f"What is {a} + {b}?"
    challenges[csr_pem] = (a + b, csr)

    # Return the challenge to the client
    return jsonify({"challenge": challenge})

@app.route('/verify_solution', methods=['POST'])
def verify_solution():
    data = request.json
    csr_pem = data.get("csr").encode()
    solution = data.get("solution")

    # Retrieve the stored challenge and CSR
    correct_answer, csr = challenges.get(csr_pem, (None, None))
    if correct_answer is None:
        return jsonify({"error": "CSR not recognized"}), 400

    if int(solution) == correct_answer:
        # Proceed to sign the CSR and issue a certificate
        return issue_certificate(csr)
    else:
        return jsonify({"error": "Incorrect solution"}), 400

@app.route('/get_ca_certificate', methods=['GET'])
def get_ca_certificate():
    with open("ca_certificate.pem", "rb") as cert_file:
        ca_certificate_pem = cert_file.read()
    return jsonify({"ca_certificate": ca_certificate_pem.decode()})

def issue_certificate(csr):
    # Load CA's private key
    with open("ca_private_key.pem", "rb") as key_file:
        ca_private_key = load_pem_private_key(key_file.read(), password=None)

    # Load the CA's certificate
    with open("ca_certificate.pem", "rb") as cert_file:
        ca_certificate = x509.load_pem_x509_certificate(cert_file.read())

    # Sign the CSR with CA's private key to issue a certificate
    certificate = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_private_key, hashes.SHA256())

    # Return the signed certificate
    signed_certificate_pem = certificate.public_bytes(Encoding.PEM)
    return jsonify({"certificate": signed_certificate_pem.decode()})

if __name__ == "__main__":
    app.run(port=5000)
