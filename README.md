![cove](https://github.com/HamzaAlmahrous/ISS/blob/main/cover.jpg)

# Information Security System

## Overview
This project aims to develop a system that facilitates communication between Damascus University and its students and doctors.
The system utilizes a client-server model, consisting of a central server for the university and separate client applications (browsers) for students and doctors. The communication between clients and the server relies on sockets over an IP/TCP connection.

## Features
- Multi-client support: The server can handle concurrent connections from multiple students and doctors.
- Information security: The system prioritizes information security through:
1. Confidentiality: Data is protected from unauthorized access.
2. Integrity: Data remains unaltered during transmission and storage.
3. Non-repudiation: The sender and receiver of information are verifiable.
4. Authentication: User identities are confirmed before granting access.
5. Authorization: Users are granted specific permissions based on their roles.
- Secure communication: Weak encryption algorithms and methods are avoided to ensure robust communication.

## Installation
1. clone the repository:
   ```
   git clone https://github.com/HamzaAlmahrous/jigsaw-genius.git
   ```
2. Navigate to the app directory:
   ```
   cd damascus-university-server
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. initialize database:
   ```
   run python .\initialize_database.py
   ```
Note: enter: - (1) to create tables in the first time - (2) to view tables

5. (optional) regenerate ca keys:
   ```
   run python .\ca_server\ca_setup.py 
   ```

6. run ca server:
   ```
   run python .\ca_server\ca_server.py
   ```

7. run our server in new terminal:
   ```
   run python .\Server.py
   ```

8. start the application:
   ```
   run streamlit run .\damascus_university_server.py
   ```
Note: in new terminal

## Contributing
Contributions to improve the app are welcome. Please fork the repository and submit a pull request with your changes.  

