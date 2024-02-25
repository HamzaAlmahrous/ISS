import socket
import json
import base64
import sys
sys.path.append(r"C:\ITE\ITE 5\ISS\project\ISS")
from Utils.encryption import encryption as enc
from cryptography.hazmat.primitives import serialization
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import time


class Professor:

    def professor_register(server_ip, server_port, register_data):
    # Example: Sending a register request
        # register_data = {
        #     'name': 'hamza',
        #     'password': '12345678',
        #     'email': 'hamza@example.com'
        # }
        return Professor.send_request(server_ip, server_port, 'professor_register', register_data)
 
    def send_request(server_ip, server_port, request_type, data):
        # Create a socket connection to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)

        
        hashed_password = enc.hash_password(data['password'])
        data['password'] = hashed_password
        # Prepare the request as a dictionary
        request = {
            'type': request_type,
            'data': data
        }

        # Convert the request dictionary to a JSON string
        request_json = json.dumps(request)

        # Send the request to the server
        client_socket.sendall(request_json.encode('utf-8'))

        # Receive the response from the server
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Response from server: {response}")

        # Close the socket connection
        client_socket.close()
        return response

    def professor_login(server_ip, server_port, login_data):
        # login_data = {
        #     'email': 'hamza@example.com',
        #     'password': '12345678'
        # }
        return Professor.send_request(server_ip, server_port, 'professor_login', login_data)
    
    def send_edit_request(server_ip, server_port, updated_data, token, password):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)
        # Derive the symmetric key from the national number
        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)

        # Encrypt the request data
        encrypted_request = enc.sym_encrypt_data(updated_data, key)
        mac, mac_hex = enc.generate_mac(encrypted_request, key)
        
        base64_encoded_data = base64.b64encode(encrypted_request).decode('utf-8')
        # Build the request structure
        print(token)
        request = {
            'type': 'edit_professor_data',
            'token': f'Bearer {token}',
            'data': base64_encoded_data,
            'mac' : mac_hex
        }
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        dec_data = ""
        try:
            response = client_socket.recv(1024).decode('utf-8')
            received_encrypted_data_bytes = base64.b64decode(response)
            dec_data = enc.sym_decrypt_data(received_encrypted_data_bytes, key)
            print(f"Response from server: {dec_data}")
        except Exception as e:
            print("Invalid Ciphering.")
        finally:
        # Close the socket connection
            client_socket.close()
            return dec_data
    
    def professor_edit_data(server_ip, server_port, token, password, updated_data):
        # password = '12345678'
        # updated_data = {
        #     'address' : 'Harat aljnan',
        #     'phone' : '777777777',
        #     'mobile_phone' : '888888888',
        # }
        return Professor.send_edit_request(server_ip, server_port, updated_data, token, password)
    
    def hand_shake(server_ip, server_port, token_request, password):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)
        request = {
            'type': 'professor_hand_shake'
        }

        # SENDING THE RIGHT ROUTE
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        # SEND AND RECEIVING PUBLIC KEYS.
        server_public_key_pem = client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
        client_public_key = enc.asym_load_public_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_public_key.pem")
        client_private_key = enc.asym_load_private_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_private_key.pem")
        serialized_public_key = enc.asym_serialize_public_key_to_pem(client_public_key)
        print("server public key:", server_public_key_pem)
        client_socket.sendall(serialized_public_key)

        # SENDING THE SESSION KEY.
        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)
        salt = enc.generate_unique_salt()
        info = b"session_key_derivation"
        session_key = enc.derive_session_key(key, salt, info)
        enc_session_key = enc.asym_encrypt_with_public_key(session_key, server_public_key)
        client_socket.sendall(enc_session_key)
        # RECEIVING THE AKN MESSAGE FROM THE SERVER.
        response = client_socket.recv(1024)
        dec_data = enc.sym_decrypt_data(response, session_key)
        print(f"Response from server: {dec_data}")
        enc_request = enc.sym_encrypt_data(token_request, session_key)
        client_socket.sendall(enc_request)
        
        # Close the socket connection
        client_socket.close()
        
        return server_public_key_pem

    def professor_hand_shake(server_ip, server_port, token, password):
        request = {
            'token': f'Bearer {token}',
        }

        return Professor.hand_shake(server_ip, server_port, request, password)

    def send_marks(server_ip, server_port, token, server_public_key_pem, student_marks, password):
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)

        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)

        request = {
            'type': 'professor_marks',
        }
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        
        client_public_key = enc.asym_load_public_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_public_key.pem")
        client_private_key = enc.asym_load_private_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_private_key.pem")
        
        encrypted_request = enc.encrypt_data_with_public_key(student_marks, server_public_key)

        digital_signature = enc.digital_signing(student_marks, client_private_key)
        # digital_signature = 'tt' + digital_signature
        
        base64_encoded_data = base64.b64encode(encrypted_request).decode('utf-8')
        
        request = {
            'token': f'Bearer {token}',
            'data': base64_encoded_data,
            'digital_signature': digital_signature
        }
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        dec_data = ""
        try:
            response = client_socket.recv(1024)
            dec_data = enc.sym_decrypt_data(response, key)
            print(f"Response from server: {dec_data}")
            
        except Exception as e:
            print("ERROR IN RESPONSE")
            
        # Close the socket connection
        client_socket.close()
        return dec_data

    def professor_send_marks(server_ip, server_port, token, password, student_marks):
        # password = '12345678'
        # student_marks = [{"name": "Alice", "mark": 70}, {"name": "Bob", "mark": 59}]

        server_public_key_pem = Professor.professor_hand_shake(server_ip, server_port, token, password)

        return Professor.send_marks(server_ip, server_port, token, server_public_key_pem, student_marks, password)

    def submit_csr(ca_server_url, common_name, title,  email):
        client_private_key = enc.asym_load_private_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_private_key.pem")
        # common_name = 'hamza'
        # title = 'professor'
        # email = 'hamza@example.com'

        csr_pem = enc.create_csr(common_name, title,  email, client_private_key)

        response = requests.post(ca_server_url, data=csr_pem)
        if response.status_code == 200:
            challenge = response.json().get('challenge')
            print("Received challenge:", challenge)
        else:
            challenge = response.text
            print("Error submitting CSR:", response.text)

        return challenge

    def verify_csr(ca_server_url, solution):
        csr = enc.load_csr_pem()
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        solution_data = {
            'csr': csr_pem.decode(),
            'solution': str(solution)
        }

        response = requests.post(ca_server_url, json=solution_data)
        x = ""
        if response.status_code == 200:
            signed_certificate = response.json().get('certificate')
            print("Received signed certificate")
            x = "Received signed certificate"
            with open("professor_certificate.pem", "w") as cert_file:
                cert_file.write(signed_certificate)
        else:
            print("Error submitting solution:", response.text)
            x = "Error submitting solution"
        
        return x

    def hand_shake_with_certificate(server_ip, server_port, token, password):
        client_certificate = enc.load_certificate_pem("professor_certificate.pem")
        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)

        request = {
            'type': 'professor_hand_shake_with_certificate',
        }
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        
        time.sleep(2.5)
        
        request_2 = {
            'token': f'Bearer {token}',
            'certificate': client_certificate.decode(),
        }
        request_json_2 = json.dumps(request_2)
        client_socket.sendall(request_json_2.encode('utf-8'))
        dec_data = ""
        try:
            response = client_socket.recv(1024)
            dec_data = enc.sym_decrypt_data(response, key)
            print(f"Response from server: {dec_data}")
            
        except Exception as e:
            dec_data = "ERROR IN RESPONSE" 
            print("ERROR IN RESPONSE")
            
        # Close the socket connection
        client_socket.close()
        return dec_data

    def professor_hand_shake_with_certificate(server_ip, server_port, token, password):
        # password = '12345678'
        
        return Professor.hand_shake_with_certificate(server_ip, server_port, token, password)

    def get_marks_with_certificate(server_ip, server_port, token, password):
        client_certificate = enc.load_certificate_pem("professor_certificate.pem")
        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)

        request = {
            'type': 'get_marks_with_certificate',
        }
        request_json = json.dumps(request)
        client_socket.sendall(request_json.encode('utf-8'))
        
        time.sleep(2.5)
        
        request_2 = {
            'token': f'Bearer {token}',
            'certificate': client_certificate.decode(),
        }
        request_json_2 = json.dumps(request_2)
        client_socket.sendall(request_json_2.encode('utf-8'))
        dec_data = ""
        try:
            response = client_socket.recv(1024)
            dec_data = enc.sym_decrypt_data(response, key)
            print(f"Response from server: {dec_data}")
            
        except Exception as e:
            dec_data = "ERROR IN RESPONSE" 
            print("ERROR IN RESPONSE")
            
        # Close the socket connection
        client_socket.close()
        return dec_data

    def professor_get_marks_with_certificate(server_ip, server_port, token, password):
        return Professor.get_marks_with_certificate(server_ip, server_port, token, password)

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 8888    
    #  Requests
    # Professor.professor_register(server_ip, server_port)
    # Professor.professor_login(server_ip, server_port)
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.ftVWQD9oDs-8zTWaaTAq9SYq21WJeq6Y_pz5NY6MIIo"
    # Professor.professor_edit_data(server_ip, server_port, token)
    
    # Professor.professor_send_marks(server_ip, server_port, token)
    
    # submit_ca_server_url = 'http://localhost:5000/submit_csr'
    # Professor.submit_csr(submit_ca_server_url)

    # solution = input("solution:")
    # verify_ca_server_url = 'http://localhost:5000/verify_solution'
    # Professor.verify_csr(verify_ca_server_url, solution)

    # Professor.professor_hand_shake_with_certificate(server_ip, server_port, token)
