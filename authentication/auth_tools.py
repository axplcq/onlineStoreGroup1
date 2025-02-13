from hashlib import sha512
import os
from database.db import Database
from flask import session
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
import random
import string

def generate_random_password(length=10):
    """
    Generates a random password of specified length.

    args:
        - length: The length of the password to generate. Default is 10.

    returns:
        - Randomly generated password.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def generate_reset_token(email):
    """
    Generates a reset token using the 'itsdangerous library' For forgotten password purposes.

    args:
        - None

    returns:
        - a 'reset token'

    modifies:


    """    

    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email)

def validate_reset_token(token, expiration=3600):

    """
    Validates that the token is valid and not expired.

    args:
        - token, and set expirtation time

    returns:
        - None

    modifies:


    """    

    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, max_age=expiration)
        return True
    except:
        return False
    

def get_username_from_reset_token(token):
    """
    Retrieves the username associated with the reset token

    args:
        - token

    returns:
        - Username or none if something is not right with the token

    modifies:


    """    
    


    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        db = Database('database/store_records.db')
        email = serializer.loads(token)
        useranme = db.get_username_by_email(email)
        return useranme
    except:
        return None

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
            return True

    return False

def email_exists(email: str) -> bool:
    """
    Checks if a email exists in the database.

    args:
        - email: A string of the email to check.

    returns:
        - True if the email exists, False if not.
    """

    db = Database('database/store_records.db')  
    all_users = db.get_all_user_information()

    for user in all_users:
        if user['email'] == email:
            return True

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


def update_passwords(username: str, password: str, salt: str, key: str):
    """
    Updates the database with a new username and password combination.
    If the username is already in the table, the password will be updated.

    args:
        - username: A string of the username to store.
        - salt: A string of the salt to store.
        - key: A string of the hashed password to store.

    returns:
        - None

    modifies:
        - Updates an existing or adds a new username and password combination to the database.
    """

    db = Database('database/store_records.db')
    # Hashs the new password with a new random salt

    salt, key = hash_password(password)

    # Checks if the username exists in the database
    
    if db.get_password_hash_by_username(username) is not None:
        db.set_password_hash(username, key)  # Update the password hash for the existing user
    else:
        return None # If it's a new user we know we alreday have a working functionality in the app.py for 'register'


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
    salt, key = hash_password(password,salt)
    print(f"Salt: {salt}")
    print(f"Key: {key}")


if __name__ == "__main__":
    main()
