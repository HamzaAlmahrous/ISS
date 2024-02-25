import sqlite3
import sys
import base64
import json
sys.path.append(r"C:\ITE\ITE 5\ISS\project\ISS")
from Utils.encryption import encryption as enc
from cryptography.hazmat.primitives import serialization

class Student_Controller:

    def students_login(db_conn, data):
        try:
            # Create a new connection and cursor within the current thread
            thread_conn = sqlite3.connect('university.db')
            cursor = thread_conn.cursor()

            # Fetch user details based on the provided email
            cursor.execute("SELECT id, password FROM students WHERE email=?", (data.get('email'),))
            user_data = cursor.fetchone()

            if user_data:
                # Extract user details
                user_id, stored_hashed_password = user_data

                # Check if the provided password matches the stored hashed password
                if data.get('password') ==  stored_hashed_password:
                    # Login successful
                    token = enc.generate_token(user_id)
                    response = {'message': f"Login successful. Student ID: {user_id}", 'token': token}
                    return response
                else:
                    # Wrong password
                    return "Wrong password"
            else:
                # User not found
                return "User not found"
        except Exception as e:
            return f"Error during registration: {str(e)}"
        finally:
            # Close the cursor and connection within the current thread
            cursor.close()
            thread_conn.close()
    
    def student_register(db_conn, data):
        try:
            # Create a new connection and cursor within the current thread
            thread_conn = sqlite3.connect('university.db')
            cursor = thread_conn.cursor()
            decoded_password = data.get('password')

            # Insert a new record into the students table
            cursor.execute("INSERT INTO students (name,email,password) VALUES (?, ?, ?)",
                        (data.get('name'), data.get('email'), decoded_password))
            thread_conn.commit()

            return "Registration successful"
        except Exception as e:
            return f"Error during registration: {str(e)}"
        finally:
            # Close the cursor and connection within the current thread
            cursor.close()
            thread_conn.close()

    def edit_data(client_socket, data):
        thread_conn = sqlite3.connect('university.db')
        cursor = thread_conn.cursor()

        token = data.get('token')
        if token is not None and token.startswith('Bearer '):
            token = token.split(' ')[1]
            payload = enc.decode_token(token)

            if payload is not None:
                    user_id = payload.get('user_id')  # Retrieve user_id from the payload
            else:
                return 'Invalid or expired token'
        else:
            return 'Token missing or malformed'
        
        # Execute the query with the user_id parameter
        cursor.execute('SELECT password FROM students WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        password = result[0]
        key = enc.derive_key(password)

        try:
            encrypted_data_b64 = data.get('data')
            mac_ = data.get('mac')
            received_mac = bytes.fromhex(mac_)
            encrypted_data = base64.b64decode(encrypted_data_b64)
            decrypted_data = enc.sym_decrypt_data(encrypted_data, key)
            jsonn = json.dumps(decrypted_data)
            json_data = json.loads(jsonn)

            is_valid = enc.verify_mac(key, encrypted_data, received_mac)
            
            if(is_valid):
                cursor.execute('UPDATE students SET address = ?, phone = ?, mobile_phone = ? WHERE id = ?', (json_data.get('address'), json_data.get('phone'), json_data.get('mobile_phone'), user_id))
                thread_conn.commit()

                # # Encrypt the response
                response_data = "Success: Data updated"
                encrypted_response = enc.sym_encrypt_data(response_data, key)
                base64_encoded_data = base64.b64encode(encrypted_response).decode('utf-8')
                return base64_encoded_data
            else:
                # # Encrypt the response
                response_data = "Failed: wrong mac"
                encrypted_response = enc.sym_encrypt_data(response_data, key)
                base64_encoded_data = base64.b64encode(encrypted_response).decode('utf-8')
                return base64_encoded_data
        except Exception as e:
            print(e)
            response_data = "Data is not valid"
            encrypted_response = enc.sym_encrypt_data(response_data, key)
            base64_encoded_data = base64.b64encode(encrypted_response).decode('utf-8')
            return base64_encoded_data
        finally:
            cursor.close()
            thread_conn.close()

    def reports(client_socket):
        thread_conn = sqlite3.connect('university.db')
        cursor = thread_conn.cursor()
        # RECIVING AND SENDING THE PUBLIC KEYS.
        server_public_key = enc.asym_load_public_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\server_public_key.pem")
        server_private_key = enc.asym_load_private_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\server_private_key.pem")
        serialized_public_key = enc.asym_serialize_public_key_to_pem(server_public_key)
        client_socket.sendall(serialized_public_key)
        client_public_key_pem = client_socket.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        client_serialized_public_key = enc.asym_serialize_public_key_to_pem(client_public_key)
        
        # RECIVING SESSION KEY.
        enc_session_key = client_socket.recv(1024)
        # dec_session_key = enc.asym_decrypt_with_private_key(enc_session_key, server_private_key)
        session_key = enc.asym_decrypt_with_private_key(enc_session_key, server_private_key)
        akn_message = {"message" : "AKN MESSAGE"}
        # akn_message_bytes = akn_message.encode('utf-8')
        encrypted_data = enc.sym_encrypt_data(akn_message, session_key)
        client_socket.sendall(encrypted_data)
        # RECIVING REPORTS
        enc_reports = client_socket.recv(1024)
        dec_reports = enc.sym_decrypt_data(enc_reports, session_key)
        # print(dec_reports)
        # print(type(dec_reports))
        jsonn = json.dumps(dec_reports)
        reports = json.loads(jsonn)

        token = reports.get('token')
        if token is not None and token.startswith('Bearer '):
            token = token.split(' ')[1]
            payload = enc.decode_token(token)

            if payload is not None:
                    user_id = payload.get('user_id')  # Retrieve user_id from the payload
            else:
                return 'Invalid or expired token'
        else:
            return 'Token missing or malformed'
        
        cursor.execute('UPDATE students SET public_key = ? WHERE id = ?', (client_serialized_public_key, user_id))
        
        for report in reports['reports']:
            # Extract the report text from each report dictionary
            report_text = report['report']

            # Insert the report into the reports table
            cursor.execute('INSERT INTO reports (student_id, report) VALUES (?, ?)', (user_id, report_text))
        thread_conn.commit()
        res = {
            "Success" :  "Data updated"
        }
        enc_response = enc.sym_encrypt_data(res, session_key)
        client_socket.sendall(enc_response)

        cursor.close()
        thread_conn.close()

    def hand_shake_with_certificate(client_socket):
        thread_conn = sqlite3.connect('university.db')
        cursor = thread_conn.cursor()

        server_public_key = enc.asym_load_public_key_from_file(r"C:\ITE\ITE 5\ISS\project\ISS\server_public_key.pem")

        enc_data = client_socket.recv(2048)
        data = json.loads(enc_data)

        token = data.get('token')

        if token is not None and token.startswith('Bearer '):
            token = token.split(' ')[1]
            payload = enc.decode_token(token)

            if payload is not None:
                    user_id = payload.get('user_id')  # Retrieve user_id from the payload
            else:
                return 'Invalid or expired token'
        else:
            return 'Token missing or malformed'

        client_certificate_pem = data.get('certificate')
        client_certificate_pem = client_certificate_pem.encode()

        cursor.execute('SELECT password FROM students WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        password = result[0]
        key = enc.derive_key(password)

        try:
            ca_certificate_pem = enc.load_certificate_pem("ca_certificate.pem")
            is_valid, public_key = enc.verify_certificate(client_certificate_pem, ca_certificate_pem)
            

            if is_valid:
                cursor.execute('UPDATE students SET public_key = ? WHERE id = ?', (public_key, user_id))
                cursor.execute('UPDATE students SET certificate = ? WHERE id = ?', (client_certificate_pem, user_id))
                message = "valid certificate."
                serialized_public_key = enc.asym_serialize_public_key_to_pem(server_public_key).decode('utf-8')
                akn_message = {"message" : message, "server_public_key" : serialized_public_key}
            
            else:
                message = "invalid certificate."
                akn_message = {"message" : message}
            
            encrypted_data = enc.sym_encrypt_data(akn_message, key)
            client_socket.sendall(encrypted_data)
            
            thread_conn.commit()
        except Exception:
            message = "invalid certificate."
            akn_message = {"message" : message}
            encrypted_data = enc.sym_encrypt_data(akn_message, key)
            client_socket.sendall(encrypted_data)
        finally:
            cursor.close()
            thread_conn.close()