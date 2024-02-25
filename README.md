# Information Security System

## Overview
this overview

## Features
- **feature**: feature.

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
note: enter: - (1) to create tables in the first time - (2) to view tables

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