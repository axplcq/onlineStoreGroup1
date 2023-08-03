import os
import sqlite3

def execute_sql(cursor: sqlite3.Cursor, sql: str) -> None:
    cursor.execute(sql)

def main() -> None:
    """Update the database schema."""

    database_path = os.path.join(os.path.dirname(__file__), 'store_records.db')
    sql_query = '''
        CREATE TABLE log_sessions (
            login_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            time_recording DATETIME NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        );
    '''

    # Update the database schema to create the log_sessions table.
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()
    execute_sql(cursor, sql_query)
    connection.commit()
    connection.close()

if __name__ == '__main__':
    main()