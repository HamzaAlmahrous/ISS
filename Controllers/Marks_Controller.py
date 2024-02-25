import sqlite3
import base64
import json
import sys
sys.path.append(r"C:\ITE\ITE 5\ISS\project\ISS")
from Utils.encryption import encryption as enc
from cryptography.hazmat.primitives import serialization

class Marks_Controller:

    def get_marks_for_professor(cursor, professor_id):
        
        query = "SELECT marks FROM marks WHERE professor_id = ?"
        cursor.execute(query, (professor_id,))
        return cursor.fetchall()
    
    def get_marks_for_student(cursor, student_name):
        cursor.execute("SELECT marks FROM marks")
        records = cursor.fetchall()

        student_marks = []
        for record in records:
            # record[0] contains the marks as a JSON string
            marks_list = json.loads(record[0])

            # Search for the student's name in the list
            for entry in marks_list:
                if entry["name"] == student_name:
                    student_marks.append(entry)

        return student_marks

    def get_marks_using_certificate(client_socket):
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

        try:
            ca_certificate_pem = enc.load_certificate_pem("ca_certificate.pem")
            is_valid, public_key = enc.verify_certificate(client_certificate_pem, ca_certificate_pem)
            
            if is_valid:
                title, common_name, email = enc.get_certificate_data(client_certificate_pem)
                if title == "Professor":
                    cursor.execute('SELECT password FROM professors WHERE id = ?', (user_id,))
                    result = cursor.fetchone()
                    password = result[0]
                    key = enc.derive_key(password)
                    
                    marks = Marks_Controller.get_marks_for_professor(cursor= cursor, professor_id= user_id)
                    print(marks)
                    serialized_public_key = enc.asym_serialize_public_key_to_pem(server_public_key).decode('utf-8')
                    akn_message = {"Client": f"Professor {common_name}", "message" : marks, "server_public_key" : serialized_public_key}
                
                else:
                    cursor.execute('SELECT password FROM students WHERE id = ?', (user_id,))
                    result = cursor.fetchone()
                    password = result[0]
                    key = enc.derive_key(password)

                    marks = Marks_Controller.get_marks_for_student(cursor= cursor, student_name= common_name)
                    print(marks)
                    serialized_public_key = enc.asym_serialize_public_key_to_pem(server_public_key).decode('utf-8')
                    akn_message = {"Client": f"Student {common_name}", "message" : marks, "server_public_key" : serialized_public_key}
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