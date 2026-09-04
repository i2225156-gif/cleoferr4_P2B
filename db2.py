import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="mysql-prueba-cleofer.alwaysdata.net",
        user="prueba-cleofer",
        password="Cleoferr",
        database="prueba-cleofer_tienda_online"
    )
