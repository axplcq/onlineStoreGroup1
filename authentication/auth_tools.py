from hashlib import sha512
import os
from database.db import Database
from flask import session
from itsdangerous import URLSafeTimedSerializer
from flask import current_app



def generate_reset_token(email, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email)


def validate_reset_token(token, secret_key, expiration=3600):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(token, max_age=expiration)
        return True
    except:
        return False


def get_username_from_reset_token(token, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        db = Database('database/store_records.db')
        email = serializer.loads(token)
        username = db.get_username_by_email(email)
        return username
    except:
        return None


def hash_password(password: str, salt: str = None) -> tuple:
    encoded_password = password.encode()
    if salt is None:
        salt = os.urandom(16).hex()
    key = sha512(encoded_password + salt.encode()).hexdigest()
    return (salt, key)


def username_exists(username: str) -> bool:
    db = Database('database/store_records.db')
    all_users = db.get_all_user_information()
    for user in all_users:
        if user['username'] == username:
            return True
    return False


def email_exists(email: str) -> bool:
    db = Database('database/store_records.db')
    all_users = db.get_all_user_information()
    for user in all_users:
        if user['email'] == email:
            return True
    return False


def is_admin(username: str) -> bool:
    db = Database('database/store_records.db')
    user_role = db.get_user_role_by_username(username)
    if (user_role=='admin'): 
        return True
    else:
        return False


def update_passwords(username: str, password: str, salt: str, key: str):
    """
    Updates the database with a new username and password combination.
    If the username is already in the file, the password will be updated.

    args:
        - username: A string of the username to store.
        - password: A string of the password to store.
        - salt: A string of the salt to store.
        - key: A string of the hashed password to store.

    returns:
        - None

    modifies:
        - passwords.txt: Updates an existing or adds a new username and password combination to the file.
    """

    db = Database('database/store_records.db')

    # Checks if the username exists in the database
    if db.get_password_hash_by_username(username) is not None:
        db.set_password_hash(username, key)  # Update the password hash for the existing user
 
    else:
        # Gets other user information (e.g., email, first name, last name)
        email = db.get_email_by_username(username)
        first_name = db.get_first_name_by_username(username)
        last_name = db.get_last_name_by_username(username)

        # Insert a new user with the provided username, password hash, salt, and other information
        db.insert_user(username, key, email, first_name, last_name)


def check_password(password: str, salt: str, key: str) -> bool:
    salt, new_key = hash_password(password, salt)
    key, new_key = key.strip(), new_key.strip()
    return key == new_key


def login_pipeline(username: str, password: str) -> bool:
    """
    Checks if a username and password combination is correct.

    args:
        - username: A string of the username to check.
        - password: A string of the password to check.

    returns:
        - True if the username and password combination is correct, False if not.
    """
    if not username_exists(username):
        return False

    db = Database('database/store_records.db')
    password_hash = db.get_password_hash_by_username(username)

    if password_hash is not None:

        session['username'] = username
        session['user_role'] = db.get_user_role_by_username(username)
        db.insert_login(username)
        return True


def main():
    password = input("enter password: ")
    salt, key = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Key: {key}")


if __name__ == "__main__":
    main()
