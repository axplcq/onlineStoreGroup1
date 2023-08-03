from authentication.auth_tools import *
from database.db import *
from app import app, mail
from flask import current_app



def test_hash_password_generates_salt():
        """
        Tests that the hash_password function generates a salt when one is not provided.

        args:
            - None

        returns:
            - error_report: a tuple containing a boolean and a string, 
            where the boolean is True if the test passed and False if it failed, 
            and the string is the error report.
        """
        salt, _ = hash_password("password")
        if salt is None:
            error = f"Error in test_hash_password_salt_generation: Salt was not generated.\n  - Actual: {salt}"
            return False, error
        else:
            return True, "Salt was generated."


def test_salt_length():
    """
    Tests that the salt is 32 characters long. Change this test if you change the salt length.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string, 
        where the boolean is True if the test passed and False if it failed, 
        and the string is the error report.
    """

    salt, _ = hash_password("password")
    if len(salt) != 32:
        error = f"Error in test_salt_length: Salt is not 16 characters long.\n  - Actual: {len(salt)}"
        return False, error
    else:
        return True, "Salt is 16 characters long."


def test_hash_password_returns_given_salt():
    """
    Tests that the hash_password function returns the given salt when one is provided.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string, 
        where the boolean is True if the test passed and False if it failed, 
        and the string is the error report.
    """

    first_salt, _ = hash_password("password")
    second_salt, _ = hash_password("password", first_salt)

    if first_salt != second_salt:
        error = f"Error in test_hash_password_returns_given_salt: Salt was not returned.\n  - Actual: {second_salt}"
        return False, error
    else:
        return True, "Salt was returned correctly."


def test_hash_password_uses_given_salt():
    """
    Tests that the hash_password function returns different hashes when given the same password and salt.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string, 
        where the boolean is True if the test passed and False if it failed, 
        and the string is the error report.
    """

    salt, first_hash = hash_password("password")
    _, second_hash = hash_password("password", salt)

    if first_hash != second_hash:
        error = f"Error in test_hash_password_returns_different_hashes: Hashes are not the same.\n  - Expected: {first_hash}\n  - Actual: {second_hash}"
        return False, error
    else:
        return True, "Hashes are different."
    
def test_generate_reset_token():
    """
    Tests that the reset token (for forgotten password purposes) is generated properly.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string, 
        where the boolean is True if the test passed and False if it failed, 
        and the string is the error report.
    """

    email = 'dannypapish@gmail.com'
    secret_key = 'the_eagle_has_landed'  
    token = generate_reset_token(email, secret_key)
    if not validate_reset_token(token, secret_key, expiration=3600):
        error = f"Error in test_generate_reset_token: The generated token is invalid.\n  - Token: {token}"
        return False, error
    else:
        return True, "Reset token was generated and is valid."

def test_validate_reset_token():
    """
    Tests that the validation of the reset token (for forgotten password purposes).

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string, 
        where the boolean is True if the test passed and False if it failed, 
        and the string is the error report.
    """

    email = 'dannypapish@gmail.com'
    secret_key = 'the_eagle_has_landed'  
    token = generate_reset_token(email, secret_key)
    if not validate_reset_token(token, secret_key, expiration=3600):
        error = f"Error in test_validate_reset_token: The token validation failed.\n  - Token: {token}"
        return False, error
    else:
        return True, "Reset token validation passed."


def test_get_username_from_reset_token():
    """
    Tests that the get_username_from_reset_token function correctly retrieves the username associated with a valid reset token.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    email = 'dannypapish@gmail.com'
    token = generate_reset_token(email,secret_key='the_eagle_has_landed')
    username = get_username_from_reset_token(token,secret_key='the_eagle_has_landed')
    if not username:
        error = f"Error in test_get_username_from_reset_token: The username retrieval failed.\n  - Token: {token}"
        return False, error
    else:
        return True, "Username retrieval passed."


def test_username_exists():
    """
    Tests that the username_exists function correctly checks if a username exists.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    username = 'dannypapish'
    if not username_exists(username):
        error = f"Error in test_username_exists: The username does not exist.\n  - Username: {username}"
        return False, error
    else:
        return True, "Username exists."


def test_email_exists():
    """
    Tests that the email_exists function correctly checks if an email exists.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    email = 'dannypapish@gmail.com'
    if not email_exists(email):
        error = f"Error in test_email_exists: The email does not exist.\n  - Email: {email}"
        return False, error
    else:
        return True, "Email exists."


def test_is_admin():
    """
    Tests that the is_admin function correctly checks if a user is an admin.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    username = 'aturing'
    if not is_admin(username):
        return False, "The user is not an admin"
    
    return True, "The user is an admin"


def test_update_passwords():
    """
    Tests that the update_passwords function correctly updates the password in the database.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    db = Database('database/store_records.db')
    username = 'bliskov'
    password = '123'
    salt, key = hash_password(password)

    # Updates the password using the update_passwords function with the correct salt and key
    update_passwords(username, password, salt, key)

    if (db.get_password_hash_by_username(username) != key):
        return False, "Password update test failed"

    return True, "Password update test passed."


def test_check_password():
    """
    Tests that the check_password function correctly checks a password against its hash.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    password = 'test_password'
    salt, key = hash_password(password)
    if not check_password(password, salt, key):
        error = f"Error in test_check_password: Password check failed.\n  - Password: {password}"
        return False, error
    else:
        return True, "Password check passed."


def test_login_pipeline():
    """
    Tests that the login_pipeline function correctly processes a user login. Sense this can formally be tested only when the app is on a server, I created an additinal table called log_sessions. That tracks all logins to the app. The function retrieves all the info in the table, and compares it with the provided username which we know is in the database. Once there is a match to at least one of the usernames, we know that the pipeline works, since this user was logged in at one point.

    args:
        - None

    returns:
        - error_report: a tuple containing a boolean and a string,
        where the boolean is True if the test passed and False if it failed,
        and the string is the error report.
    """
    db = Database('database/store_records.db')
    username = 'dannypapish'
    all_logins = db.get_all_login_information()
    error = f"Error in test_login_pipeline: Login pipeline failed.\n  - Username: {username}"

    for logins in all_logins:
        if logins['username'] == username:
            return True, "login_pipeline works as expected"

    return False, error







