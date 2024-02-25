import socket
import json
import sys
import base64
sys.path.append(r"C:\ITE\ITE 5\ISS\project\ISS")
from Utils.encryption import encryption as enc
from cryptography.hazmat.primitives import serialization
import requests
import time

class Student:

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
    
    def student_login(server_ip, server_port, login_data):
        # login_data = {
        #     'email': 'ahmad@example.com',
        #     'password': '12345678'
        # }
        return Student.send_request(server_ip, server_port, 'student_login', login_data)

    def student_register(server_ip, server_port, register_data):
        # register_data = {
        #     'name' : 'ahmad',
        #     'password': '12345678',
        #     'email': 'ahmad@example.com'
        # }
        return Student.send_request(server_ip, server_port, 'student_register', register_data)

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
        request = {
            'type': 'edit_student_data',
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

    def student_edit_data(server_ip, server_port, token, password, updated_data):
            # password = '12345678'
            # updated_data = {
            #     'address' : 'kfrsosoa',
            #     'phone' : '99998999',
            #     'mobile_phone' : '21423',
            # }
            return Student.send_edit_request(server_ip, server_port, updated_data, token, password)

    def send_reports(server_ip, server_port, reports, password):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)
        dec_data = ""
        try:    
            request = {
                'type': 'student_report'
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
            enc_reports = enc.sym_encrypt_data(reports, session_key)
            client_socket.sendall(enc_reports)
            response = client_socket.recv(1024)
            dec_data = enc.sym_decrypt_data(response, session_key)
            print(f"{dec_data}")
            # Close the socket connection
        except Exception as e:
                print("Invalid Ciphering.")
        finally:
             # Close the socket connection
            client_socket.close()
            print("dec_data: ", dec_data)
            return dec_data

    def reports(server_ip, server_port, token, password, reports):
        # password = '12345678'
        # reports = [
        #     {
        #         'report': 'PP 1 Title'
        #     },
        #     {
        #         'report': 'PP 2 Title'
        #     }
        #     ]
        request = {
            'token': f'Bearer {token}',
            'reports': reports
            }
        return Student.send_reports(server_ip, server_port, request, password)

    def submit_csr(ca_server_url, common_name, title,  email):
        client_private_key = enc.asym_load_private_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\client_private_key.pem")
        # common_name = 'hamza'
        # title = 'student'
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
            with open("student_certificate.pem", "w") as cert_file:
                cert_file.write(signed_certificate)
        else:
            print("Error submitting solution:", response.text)
            x = "Error submitting solution"
        
        return x

    def hand_shake_with_certificate(server_ip, server_port, token, password):
        client_certificate = enc.load_certificate_pem("student_certificate.pem")
        hashed_password = enc.hash_password(password)
        key = enc.derive_key(hashed_password)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)
        client_socket.connect(server_address)

        request = {
            'type': 'student_hand_shake_with_certificate',
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

    def student_hand_shake_with_certificate(server_ip, server_port, token, password):
        # password = '12345678'
        
        return Student.hand_shake_with_certificate(server_ip, server_port, token, password)
    
    def get_marks_with_certificate(server_ip, server_port, token, password):
        client_certificate = enc.load_certificate_pem("student_certificate.pem")
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

    def student_get_marks_with_certificate(server_ip, server_port, token, password):
        return Student.get_marks_with_certificate(server_ip, server_port, token, password)

if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 8888    
    #  Requests
    # Student.student_register(server_ip, server_port)
    # Student.student_login(server_ip, server_port)
    token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.ftVWQD9oDs-8zTWaaTAq9SYq21WJeq6Y_pz5NY6MIIo'
    Student.student_edit_data(server_ip, server_port, token)
    # Student.reports(server_ip, server_port, token)