import unittest
from database.db import Database
import random
import string



def generate_random_password(length=10):
    """
    Generates random password at the length 10.

    args:
        - length=10

    returns:
        - the password 

    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def test_set_password_hash():
    """
    Test setting a new password hash.

    args:
        - none
    returns:
        - a tuple - boolean + success/fail message 

    """    
    db = Database('database/store_records.db')
    username = "bliskov"
    new_password_hash = "7dvgffhrhfrhrfhrhtrgbgr45743576"
    db.set_password_hash(username, new_password_hash)
    updated_password_hash = db.get_password_hash_by_username(username)
    if updated_password_hash == new_password_hash:
        return True, "set_password_hash_is working!"
    return False, "set_password_hash_is not working properly"

def test_set_email():
    """
    Test setting up a new email.

    args:
        - none
    returns:
        - a tuple - boolean + success/fail message

    """    

    username = "bliskov"
    new_email = "shosh@example.com"
    db = Database('database/store_records.db')
    db.set_email(username, new_email)

    updated_email = db.get_email_by_username(username)
    print(updated_email)
    if updated_email == new_email:
        return True, "set_email_is working!"
    return False, "set_email_is not working properly"

def test_set_first_name():
    """
    Test setting up a new first name.

    args:
        - none
    returns:
        - a tuple - boolean + success/fail message

    """        
    username = "bliskov"
    new_first_name = "shosh"
    db = Database('database/store_records.db')
    db.set_first_name(username, new_first_name)
    updated_first_name = db.get_first_name_by_username(username)
    if updated_first_name == new_first_name:
        return True, "set_first_name_by_username_is working!"
    return False, "set_first_name_by_username_is not working properly"        

def test_set_last_name():
    """
    Test setting up a new last name.

    args:
        - none
    returns:
        - a tuple - boolean + success/fail message

    """    

    username = "bliskov"
    new_last_name = "rom"
    db = Database('database/store_records.db')
    db.set_last_name(username, new_last_name)
    updated_last_name = db.get_last_name_by_username(username)
    if updated_last_name == new_last_name:
        return True, "set_last_name is working!"  
    return False, "set_last_name_is not working properly"  

def test_generate_random_password(): # Test the length of the generated password
    """
    Test the genertation of the new password.

    args:
        - none
    returns:
        - a tuple - boolean + success/fail message

    """    
    password_length = 15
    generated_password = generate_random_password(password_length)

    if len(generated_password) == password_length:
        return True, "test_generate_random_password is working!:" + generated_password
    return False, "test_generate_random_password is not working properly"



if __name__ == '__main__':
    unittest.main()