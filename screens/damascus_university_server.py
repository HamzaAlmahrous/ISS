import streamlit as st
import sys
import json
sys.path.append(r"C:\ITE\ITE 5\ISS\project\ISS")
from Models.Professor import Professor
from Models.Student import Student

server_ip = '127.0.0.1'
server_port = 8888    

def switch_to_register():
    st.session_state.page = "Register"

def switch_to_login():
    st.session_state.page = "Login"

def switch_to_home():
    st.session_state.page = "Home"

def switch_to_reports():
    st.session_state.page = "Reports"

def switch_to_marks():
    st.session_state.page = "Marks"

def switch_to_certificate():
    st.session_state.page = "Certificate"

def switch_to_get_marks():
    st.session_state.page = "GET_MARKS"

st.title("Damascus University Server")

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = "Login"

if 'user_token' not in st.session_state:
    st.session_state.user_token = ""
if 'user_email' not in st.session_state:
    st.session_state.user_email = ""
if 'user_password' not in st.session_state:
    st.session_state.user_password = ""
if 'user_type' not in st.session_state:
    st.session_state.user_type = ""
if 'user_name' not in st.session_state:
    st.session_state.user_name = ""
if 'user_address' not in st.session_state:
    st.session_state.user_address = ""
if 'user_phone' not in st.session_state:
    st.session_state.user_phone = ""
if 'user_mobile_phone' not in st.session_state:
    st.session_state.user_mobile_phone = ""

# Navigation buttons
if st.session_state.page == "Login":
    st.sidebar.button("Switch to Register", key="switch_button", on_click= switch_to_register)

if st.session_state.page == "Register":
    st.sidebar.button("Switch to Login", key="switch_button", on_click= switch_to_login)

# Handle page switching
if st.session_state.page == "Login":
    st.header("Login")
    user_type = st.radio("Select User Type", ("Student", "Professor"), horizontal= True)
    name = st.text_input("Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    login_button = st.button("Login")

    if login_button:
        if email and password and user_type and name:
            login_data = {
                'email': email,
                'password': password
            }
            if user_type == "Student":
                response = Student.student_login(server_ip, server_port, login_data)
            else:
                response = Professor.professor_login(server_ip, server_port, login_data)
            if response.startswith("{"):
                response = json.loads(response)
                st.session_state.user_email = email 
                st.session_state.user_password = password 
                st.session_state.user_type = user_type
                st.session_state.user_name = name
                st.session_state.user_token = response.get("token")
                st.success("Logged in successfully!")
                switch_to_home()
                st.experimental_rerun()
            else:
                st.error(response)
        else:
            st.error("Please fill in all fields.")

elif st.session_state.page == "Register":
    st.header("Register")
    user_type = st.radio("Select User Type", ("Student", "Professor"), horizontal= True)
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    name = st.text_input("Name")
    register_button = st.button("Register")

    if register_button:
        # Add your registration logic here
        if email and password and name and user_type:
            register_data = {
                'name': name,
                'password': password,
                'email': email
            }
            if user_type == "Student":
                response = Student.student_register(server_ip, server_port, register_data)
            else:
                response = Professor.professor_register(server_ip, server_port, register_data)
            if response == "Registration successful":
                st.session_state.user_email = email 
                st.session_state.user_password = password 
                st.session_state.user_type = user_type
                st.session_state.user_name = name
                st.success("Registered successfully!")
                switch_to_login()
                st.experimental_rerun()
            else:
                st.error(response)
        else:
            st.error("Please fill in all fields.")

elif st.session_state.page == "Home":
    st.header("Home")
    user_type = st.radio("Select User Type", ("Student", "Professor"), horizontal= True, index = 0 if st.session_state.user_type == "Student" else 1, disabled=True)
    name = st.text_input("Name", disabled=True, value= st.session_state.user_name)
    email = st.text_input("Email", value= st.session_state.user_email, disabled=True)
    password = st.text_input("Password", type="password", disabled=True, value= st.session_state.user_password)
    address = st.text_input("Address", value= st.session_state.user_address)
    phone = st.text_input("Phone", value= st.session_state.user_phone)
    mobile_phone = st.text_input("Mobile Phone", value= st.session_state.user_mobile_phone)
    update_button = st.button("Update", type= "primary")
    send_button = st.button("Send Report" if st.session_state.user_type == "Student" else "Send Marks", type= "primary")
    certificate_button = st.button("Get Certificate", type= "primary")
    marks_button = st.button("Get Marks", type= "primary")
    logout_button = st.button("Logout")

    if update_button:
        if email and password and name and user_type and address and phone and mobile_phone:
            updated_data = {
                'address' : address,
                'phone' : phone,
                'mobile_phone' : phone,
            }
            if user_type == "Student":
                response = Student.student_edit_data(server_ip, server_port, st.session_state.user_token, st.session_state.user_password, updated_data)
            else:
                response = Professor.professor_edit_data(server_ip, server_port, st.session_state.user_token, st.session_state.user_password, updated_data)
            if response == "Success: Data updated":
                st.session_state.user_address = address 
                st.session_state.user_mobile_phone = mobile_phone
                st.session_state.user_phone = phone
                st.success("Updated successfully!")
            else:
                st.error(response)
        else:
            st.error("Please fill in all fields.")

    if logout_button:
        st.session_state.user_token = ""
        st.session_state.user_email = ""
        st.session_state.user_password = ""
        st.session_state.user_type = ""
        st.session_state.user_name = ""
        st.session_state.user_address = ""
        st.session_state.user_phone = ""
        st.session_state.user_mobile_phone = ""
        switch_to_login()
        st.experimental_rerun()
    
    if send_button:
        if user_type == "Student":
            switch_to_reports()
            st.experimental_rerun()
        else:
            switch_to_marks()
            st.experimental_rerun()

    if certificate_button:
        switch_to_certificate()
        st.experimental_rerun()

    if marks_button:
        switch_to_get_marks()
        st.experimental_rerun()
    
elif st.session_state.page == "Reports":
    st.header("Reports")
    num_reports = st.number_input('Enter the number of reports', value=1, min_value=1, step=1)

    reports = []

    for i in range(int(num_reports)):
        report = st.text_area(f'Report Content {i+1}', key=f'report_{i}')
        reports.append({'title': f"title{i}", 'report': report})

    if st.button('Submit Reports'):
        response = Student.reports(server_ip, server_port, st.session_state.user_token, st.session_state.user_password, reports)
        if str(response).startswith("{'Success'"):
            reports.clear()
            st.success("Reports Sent Successfully!")
        else:
            st.error(response)

    if st.button('back'):
        switch_to_home()
        st.experimental_rerun()

elif st.session_state.page == "Marks":
    st.header("Marks")
    num_marks = st.number_input('Enter the number of students', value=1, min_value=1, step=1)

    marks = []

    for i in range(int(num_marks)):
        student_name = st.text_area(f'student name: {i+1}', key=f'student_name_{i}')
        mark = st.text_area(f'mark: {i+1}', key=f'mark_{i}')
        marks.append({'name': student_name, 'marks': mark})

    if st.button('Submit Marks'):
        response = Professor.professor_send_marks(server_ip, server_port, st.session_state.user_token, st.session_state.user_password, marks)
        print(response)
        if str(response).startswith("{'message'"):
            marks.clear()
            st.success("(Valid Signature) Marks  Sent Successfully!")
        else:
            st.error(response)

    if st.button('back'):
        switch_to_home()
        st.experimental_rerun()

elif st.session_state.page == "Certificate":
    st.header("CA Certificate")
    st.write('Send Certificate Signing Request to the CA')
    if st.button('Send'):
        if st.session_state.user_type == "Professor":
            response = Professor.submit_csr('http://localhost:5000/submit_csr', st.session_state.user_name, st.session_state.user_type, st.session_state.user_email)
            print(response)
            if str(response).startswith("What"):
                st.success(f"CSR sent Solve this challenge to verify: {response}")
            else:
                st.error(response)
        else:
            response = Student.submit_csr('http://localhost:5000/submit_csr', st.session_state.user_name, st.session_state.user_type, st.session_state.user_email)
            print(response)
            if str(response).startswith("What"):
                st.success(f"CSR sent Solve this challenge to verify: {response}")
            else:
                st.error(response)

    solution = st.text_area(f'solution:')

    if st.button('verify'):
        if solution:
            if st.session_state.user_type == "Professor":
                response = Professor.verify_csr('http://localhost:5000/verify_solution', solution)
                print(response)
                if str(response).startswith("Received"):
                    st.success("Received signed certificate")
                else:
                    st.error(response)
            else:
                response = Student.verify_csr('http://localhost:5000/verify_solution', solution)
                print(response)
                if str(response).startswith("Received"):
                    st.success("Received signed certificate")
                else:
                    st.error(response)
        else:
            st.error("please enter the solution first")
    
    st.write('Send Signed Certificate to Damascus Server')
    if st.button('Send to server'):
        if st.session_state.user_type == "Student":
            response = Student.student_hand_shake_with_certificate(server_ip, server_port, st.session_state.user_token, st.session_state.user_password)
            print(response)
            st.success(response)
        else:
            response = Professor.professor_hand_shake_with_certificate(server_ip, server_port, st.session_state.user_token, st.session_state.user_password)
            print(response)
            st.success(response)

    if st.button('back'):
        switch_to_home()
        st.experimental_rerun()

elif st.session_state.page == "GET_MARKS":
    st.header("Get Marks")
    st.write('Send Signed Certificate to Damascus Server and get the marks')
    if st.button('Send to server'):
        if st.session_state.user_type == "Student":
            response = Student.get_marks_with_certificate(server_ip, server_port, st.session_state.user_token, st.session_state.user_password)
            print(response)
            st.success(response)
        else:
            response = Professor.get_marks_with_certificate(server_ip, server_port, st.session_state.user_token, st.session_state.user_password)
            print(response)
            st.success(response)

    if st.button('back'):
        switch_to_home()
        st.experimental_rerun()

