import sqlite3
from database.db import Database

db = Database('store_records.db') 
username_to_check = "aturing"
result = db.get_user_role_by_username(username_to_check)
print(result)

