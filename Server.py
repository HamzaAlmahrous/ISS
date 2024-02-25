import sqlite3
import socket
import threading
import json
from Controllers.Professor_Controller import Professor_Controller
from Controllers.Student_Controller import Student_Controller 
from Controllers.Marks_Controller import Marks_Controller 
from Utils.server_key_gen import generate_server_keys
import requests

def routes(client_socket, database_connection):

    # Receive the request from the client
    request_json = client_socket.recv(2048).decode('utf-8')
    request = json.loads(request_json)
    request_type = request.get('type')

    if request_type == 'professor_login':
        data = request.get('data', {})
        success_message = Professor_Controller.professor_login(database_connection, data)
        success_message_json = json.dumps(success_message)
        client_socket.sendall(success_message_json.encode('utf-8'))

    elif request_type == 'student_login':
        data = request.get('data', {})
        success_message = Student_Controller.students_login(database_connection, data)
        success_message_json = json.dumps(success_message)
        client_socket.sendall(success_message_json.encode('utf-8'))
    
    elif request_type == 'edit_professor_data':
        data = request.get('data', {})
        success_message = Professor_Controller.edit_data(database_connection, request)
        success_message_json = json.dumps(success_message)
        client_socket.sendall(success_message_json.encode('utf-8'))

    elif request_type == 'edit_student_data':
        data = request.get('data', {})
        success_message = Student_Controller.edit_data(database_connection, request)
        success_message_json = json.dumps(success_message)
        client_socket.sendall(success_message_json.encode('utf-8'))

    # Handle register request
    elif request_type == 'student_register':
        data = request.get('data', {})
        success_message = Student_Controller.student_register(database_connection, data)
        client_socket.sendall(success_message.encode('utf-8'))
    
    elif request_type == 'professor_register':
        data = request.get('data', {})
        success_message = Professor_Controller.professor_register(database_connection, data)
        client_socket.sendall(success_message.encode('utf-8'))
    
    elif request_type == 'student_report':
        success_message = Student_Controller.reports(client_socket)

    elif request_type == 'professor_hand_shake':
        success_message = Professor_Controller.hand_shake(client_socket)
    
    elif request_type == 'professor_marks':
        success_message = Professor_Controller.marks(client_socket)

    elif request_type == 'professor_hand_shake_with_certificate':
        success_message = Professor_Controller.hand_shake_with_certificate(client_socket)
    
    elif request_type == 'student_hand_shake_with_certificate':
        success_message = Student_Controller.hand_shake_with_certificate(client_socket)
    
    elif request_type == 'get_marks_with_certificate':
        success_message = Marks_Controller.get_marks_using_certificate(client_socket)

    # Close the client socket
    client_socket.close()

def start_server():
    # Create a socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('127.0.0.1', 8888)
    server_socket.bind(server_address)
    server_socket.listen(5)

    print("Server listening on port 8888...")

    # Connect to the SQLite database
    db_connection = sqlite3.connect('university.db')

    while True:
        # Wait for a connection
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address[0]}:{client_address[1]}")

        # Create a new thread to handle the client
        client_handler = threading.Thread(target=routes, args=(client_socket, db_connection))
        client_handler.start()

def get_ca_certificate(ca_certificate_url):
    response = requests.get(ca_certificate_url)
    if response.status_code == 200:
        ca_certificate_pem = response.json().get('ca_certificate')

        with open("ca_certificate.pem", "w") as cert_file:
            cert_file.write(ca_certificate_pem)

        print("CA's Certificate saved to 'ca_certificate.pem'")
    else:
        print("Error fetching CA's certificate:", response.text)


if __name__ == "__main__":
    try:
        generate_server_keys()
        print("keys generated")
    except Exception:
        print("Error generating keys")
    try:
        ca_certificate_url = 'http://localhost:5000/get_ca_certificate'
        get_ca_certificate(ca_certificate_url)
        print("ca certificate received")
    except Exception:
        print("Error receiving ca certificate")
    start_server()
    # test()