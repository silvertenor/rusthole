import sqlite3, socket
from modules.db import *



create_or_connect_db('rusthole-reporting.db')
# Listen to other service:
HOST = '0.0.0.0'
PORT = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024).decode('utf-8')
                if data != '':
                    insert_or_update_db('rusthole-reporting.db', data)
                if not data:
                    break