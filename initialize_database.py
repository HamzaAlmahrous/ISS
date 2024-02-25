# initialize_database.py
import sqlite3

def create_tables():
    # Connect to the SQLite database (this will create a new database if it doesn't exist)
    conn = sqlite3.connect('university.db')

    # Create a cursor object to execute SQL queries
    cursor = conn.cursor()

    # Drop existing tables if they exist
    cursor.execute('DROP TABLE IF EXISTS students')
    cursor.execute('DROP TABLE IF EXISTS professors')
    cursor.execute('DROP TABLE IF EXISTS reports')
    cursor.execute('DROP TABLE IF EXISTS marks')

    # Create a table for students
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            password TEXT,
            address TEXT,
            phone TEXT,
            mobile_phone TEXT,
            nat_num TEXT,
            public_key TEXT,
            certificate TEXT
        )
    ''')

    # Create a table for professors
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS professors (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            password TEXT,
            address TEXT,
            phone TEXT,
            mobile_phone TEXT,
            nat_num TEXT,
            public_key TEXT,
            certificate TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY,
            report TEXT,
            student_id INTEGER,
            FOREIGN KEY (student_id) REFERENCES students(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS marks (
            id INTEGER PRIMARY KEY,
            marks TEXT,
            professor_id INTEGER,
            signature TEXT,
            FOREIGN KEY (professor_id) REFERENCES professors(id)
        )
    ''')

    # Commit the changes
    conn.commit()

    # Close the cursor and connection
    cursor.close()
    conn.close()

def view_table(table_name):
    conn = sqlite3.connect('university.db')
    cursor = conn.cursor()

    # Fetch all rows from the specified table
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()

    # Display the fetched data
    for row in rows:
        print(row)

    # Close the cursor and connection
    cursor.close()
    conn.close()

if __name__ == "__main__":
    x = input("enter: - (1) to create tables - (2) to view tables")
    print(x)
    if x == "1":
        create_tables()
    else:
        print("STUDENTS:")
        view_table("students")
        print("-----------------------------")
        print("REPORTS:")
        view_table('reports')
        print("-----------------------------")
        print("PROFESSORS:")
        view_table("professors")
        print("-----------------------------")
        print("MARKS:")
        view_table('marks')
        print("-----------------------------")