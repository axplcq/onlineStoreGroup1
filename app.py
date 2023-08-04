#!/usr/bin/env python3

from authentication.auth_tools import login_pipeline, update_passwords, hash_password,username_exists,email_exists,generate_reset_token, validate_reset_token,get_username_from_reset_token
from database.db import Database
from flask import Flask, render_template, request, redirect, url_for,flash
from core.session import Sessions
from flask_mail import Mail, Message

app = Flask(__name__)
# Configure Flask-Mail for the password change process
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dannypapish@gmail.com'
app.config['MAIL_PASSWORD'] = '*******'

mail = Mail(app)


app = Flask(__name__)
app.secret_key = 'the_eagle_has_landed'
HOST, PORT = 'localhost', 8080
global username, products, db, sessions
username = 'default'
db = Database('database/store_records.db')
products = db.get_full_inventory()
sessions = Sessions()
sessions.add_new_session(username, db)


@app.route('/')
def index_page():
    """
    Renders the index page when the user is at the `/` endpoint, passing along default flask variables.

    args:
        - None

    returns:
        - None
    """
    return render_template('index.html', username=username, products=products, sessions=sessions)


@app.route('/login')
def login_page():
    """
    Renders the login page when the user is at the `/login` endpoint.

    args:
        - None

    returns:
        - None
    """
    return render_template('login.html')


@app.route('/home', methods=['POST','GET'])
def login():
    """
    Renders the home page when the user is at the `/home` endpoint with a POST request. Get's the username and password from newly registered user through the register page, and starts a new session. Displays a an error using the 'flash' function in case it can't find the user un the database through the login_pipeline.

    args:
        - None

    returns:
        - None

    modifies:
        - sessions: adds a new session to the sessions object

    """
    passed_username = request.args.get('username')
    passed_password = request.args.get('password')
    username = request.form['username']
    password = request.form['password']
    db = Database('database/store_records.db')
    if login_pipeline(username, password):
        sessions.add_new_session(username, db)
        db.insert_login(username)
        return render_template('home.html', products=products, sessions=sessions, passed_username=passed_username, passed_password=passed_password)
    else:
        flash("Username and/or password are incorrect, please try again.", "warning")
        return redirect(url_for('login_page'))


@app.route('/register')
def register_page():
    """
    Renders the register page when the user is at the `/register` endpoint.

    args:
        - None

    returns:
        - None
    """
    return render_template('register.html')
  



@app.route('/register', methods=['POST', 'GET'])
def register():
    """
    Renders the login page when if everything went well, Displays errors and constraints using the 'flash' function in case if there is a problem.

    args:
        - None

    returns:
        - None

    modifies:

        - database/store_records.db: adds a new user to the database
        - passes the username and password that were inputed to the login page
    """
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']

    # Check if the username already exists
    if username_exists(username):
        flash("Username already exists. Please choose a different username.", "warning")
        return redirect(url_for('register_page'))

    salt, key = hash_password(password)
    update_passwords(username, password,salt,key)
    db.insert_user(username, key, email, first_name, last_name)
    return render_template('login.html', passed_username=username, passed_password=password)

@app.route('/forgot_password')

def forgot_password_page():
    """
    Renders the forgot_password page.

    args:
        - None

    returns:
        - The 'forgot_password' page template

    modifies:


    """    
    return render_template('forgot_password.html')

@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    """
    Handles the user's request for getting a new password instrad of the forgotten one and sends a 'password change' link to the users
    email.

    args:
        - None

    returns:
        - None

    modifies:


    """    
    email = request.form['email']
    if email_exists(email):
        
        reset_token = generate_reset_token(email) # Generates a reset password link or token and send it to the user's email
        send_reset_password_email(email, reset_token)  # Calls the function to send the email
        flash("If your email exists in our system, you will get a link that will allow you to reset your password.", "warning")
    else:
        flash("Email not found in our system. Please try again.", "warning")
    return redirect(url_for('forgot_password'))


def send_reset_password_email(email, reset_token):
    # Send the reset password email using Flask-Mail

    msg = Message('Password Reset', sender='dannypapish@gmail.com', recipients=[email])
    msg.body = f'Click the link below to reset your password: {url_for("password_reset", token=reset_token, _external=True)}'
    mail.send(msg) 

@app.route('/password_reset', methods=['POST'])
def password_reset():
    """
    Takes care of the password reset process.

    args:
        - None

    returns:
        - The 'forgot_password' page template

    modifies:
    Updates the password for the user.

    """        
    
    new_password = request.form['password'] # Retrieves the new password from the form

    reset_token = request.args.get('token') # Retrieves the reset token from the query parameters

    
    if validate_reset_token(reset_token): # Validates the reset token
       
        username = get_username_from_reset_token(reset_token)  # Retrieves the username from the reset password link or token

        
        update_passwords(username, new_password) # Updates the password for the user in case everything went fine, displays an error with 'flash' otherwise

        flash("Password reset successful. You can now log in with your new password.", "success")
        return redirect(url_for('login'))
    else:
        flash("Invalid reset token. Please try again.", "danger")
        return redirect(url_for('forgot_password'))
        


@app.route('/checkout', methods=['POST'])
def checkout():
    """
    Renders the checkout page when the user is at the `/checkout` endpoint with a POST request.

    args:
        - None

    returns:
        - None

    modifies:
        - sessions: adds items to the user's cart
    """
    order = {}
    user_session = sessions.get_session(username)
    for item in products:
        print(f"item ID: {item['id']}")
        if request.form[str(item['id'])] > '0':
            count = request.form[str(item['id'])]
            order[item['item_name']] = count
            user_session.add_new_item(
                item['id'], item['item_name'], item['price'], count)

    user_session.submit_cart()

    return render_template('checkout.html', order=order, sessions=sessions, total_cost=user_session.total_cost)


if __name__ == '__main__':
    app.run(debug=True, host=HOST, port=PORT)
