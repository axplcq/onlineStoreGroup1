from hashlib import sha512
import os
from database.db import Database
from flask import session


def hash_password(password: str, salt: str = None) -> tuple:
    """
    Hashes a password using SHA-512.

    args:
        - password: A string of the password to hash.

    returns:
        - A tuple of the salt and the hashed password, both as strings.
    """
    encoded_password = password.encode() #encoding into bytes
    if salt is None:
        salt = os.urandom(16).hex()
    key = sha512(encoded_password + salt.encode()).hexdigest()
    return (salt, key)


def username_exists(username: str) -> bool:
    """
    Checks if a username exists in the database.

    args:
        - username: A string of the username to check.

    returns:
        - True if the username exists, False if not.
    """

    db = Database('database/store_records.db')  

    all_users = db.get_all_user_information()
    for user in all_users:
        if user['username'] == username:
            print(f"Username '{username}' exists.")
            return True

    print(f"Username '{username}' does not exist.")
    return False

def is_admin(username: str) -> bool:
    """
    Checks if the user with the given username is an admin.

    args:
        - username: A string of the username to check.

    returns:
        - True if the user is an admin, False otherwise.
    """
    db = Database('database/store_records.db')
    user_role = db.get_user_role_by_username(username)

    return user_role == 'admin'


def update_passwords(username: str, password:str, key: str, salt: str):
    """
    Updates the database with a new username and password combination.
    If the username is already in the file, the password will be updated.

    args:
        - username: A string of the username to store.
        - key: A string of the hashed password to store.
        - salt: A string of the salt to store.

    returns:
        - None

    modifies:
        - passwords.txt: Updates an existing or adds a new username and password combination to the file.
    """

    db = Database('database/store_records.db')

    # Hash the password
    salt, password_hash = hash_password(password)

    # Check if the username exists in the database
    if db.get_password_hash_by_username(username) is not None:
        db.set_password_hash(username, password_hash)  # Update the password hash for the existing user
       # db.set_salt(username, salt)  
    else:
        # Get other user information (e.g., email, first name, last name)
        email = db.get_email_by_username(username)
        first_name = db.get_first_name_by_username(username)
        last_name = db.get_last_name_by_username(username)

        # Insert a new user with the provided username, password hash, salt, and other information
        db.insert_user(username, password_hash, email, first_name, last_name)


def check_password(password: str, salt: str, key: str) -> bool:
    """
    Checks if a password is correct by hashing it and comparing it to the given hash key.

    args:
        - password: A string of the password to check.
        - salt: A string of the salt to use.
        - key: A string of the hash to check against.

    returns:
        - True if the password is correct, False if not.
    """
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
        return True


def main():
    password = input("enter password: ")
    salt, key = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Key: {key}")


if __name__ == "__main__":
    main()
