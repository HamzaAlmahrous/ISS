import streamlit as st
import pandas as pd
import sqlite3

# For SQLite
conn = sqlite3.connect(r"C:\ITE\ITE 5\ISS\project\ISS\university.db")

query = "SELECT * FROM students"
data = pd.read_sql(query, conn)

st.title('Database Viewer')

if st.button("students"):
    query = "SELECT * FROM students"
    data = pd.read_sql(query, conn)

if st.button("professors"):
    query = "SELECT * FROM professors"
    data = pd.read_sql(query, conn)

if st.button("reports"):
    query = "SELECT * FROM reports"
    data = pd.read_sql(query, conn)

if st.button("marks"):
    query = "SELECT * FROM marks"
    data = pd.read_sql(query, conn)

st.write('Here is the data from the database:')
st.dataframe(data)
