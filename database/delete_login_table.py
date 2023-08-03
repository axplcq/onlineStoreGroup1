import sqlite3
import os

def delete_table(database_path, table_name):
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    try:
        cursor.execute(f"DROP TABLE {table_name};")
        print(f"Table '{table_name}' has been deleted successfully.")
    except sqlite3.Error as e:
        print(f"Error occurred: {e}")

    connection.commit()
    connection.close()

if __name__ == '__main__':
    database_path = os.path.join(os.path.dirname(__file__), 'store_records.db')
    table_name = 'log_sessions'
    delete_table(database_path, table_name)