#!/usr/bin/env python3

from authentication.auth_tools import login_pipeline, update_passwords, hash_password,username_exists,email_exists,generate_reset_token, validate_reset_token,get_username_from_reset_token,generate_random_password
from database.db import Database
from flask import Flask, Markup, session,render_template, request, redirect, url_for,flash
from core.session import Sessions
from flask_mail import Mail, Message
import logging
import random
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
# Configure Flask-Mail for the password change process
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dannypapish@gmail.com'
app.config['MAIL_PASSWORD'] = '*******'
mail = Mail(app)
app.secret_key = 'the_eagle_has_landed'
HOST, PORT = 'localhost', 8080
global username, products, db, sessions
username = 'default'
user_role = 'default'
db = Database('database/store_records.db')
products = db.get_full_inventory()
sessions = Sessions()
sessions.add_new_session(username,db)




@app.route('/')
@app.route('/home')
def index_page():
    """
    Renders the index page when the user is at the `/home` or `/` endpoint, passing along default flask variables.

    args:
        - None

    returns:
        - None
    """
    if 'username' in session:  # Check if user is logged in
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
            
    return render_template('index.html', username=current_username, products=products, sessions=sessions, is_logged_in=is_logged_in)


@app.route('/admin')
def admin_page():

    """
    Renders the login page when the user is at the `/login` endpoint.

    args:
        - None

    returns:
        - None
    """
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True

    return render_template('admin.html')

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
    #passed_username = request.args.get('username')
    #passed_password = request.args.get('password')
    username = request.form['username']
    password = request.form['password']
    db = Database('database/store_records.db')

    if login_pipeline(username, password):
        current_username = session.get('username')
        current_role = db.get_user_role_by_username(current_username) #check the role of the currently login user
        is_logged_in = True #a custom variable that will be passed to the home template to control appearance of specific menu items
        if not current_role=='admin':  # distinct between two cases: 1. the user is an admin - so therfore a different header will be displayed. 2. The user is not an admin, and a regular menu will be displayed. 

            sessions.add_new_session(username, db)
            db.insert_login(username)
            return render_template('home.html', products=products, sessions=sessions, passed_username=username, passed_password=password,is_logged_in=is_logged_in)
        else:

            sessions.add_new_session(username, db)
            db.insert_login(username)
            return render_template('admin.html', products=products, sessions=sessions, passed_username=username, passed_password=password,is_logged_in=is_logged_in)
    else:
        flash("Username and/or password are incorrect, please try again.", "warning")
        return redirect(url_for('login_page'))

@app.route('/logout', methods=['GET'])
def logout():
    """
    Logs out the user from his personal zone to the main index page

    args:
        - None

    returns:
        - None

    modifies:
        - clears all sessions

    """
    session.clear()
    return redirect(url_for('index_page'))

@app.route('/orders')

def orders_page():
    """
    Renders the users page for the admin.

    args:
        - None

    returns:
        - None
    """
    # checks if the user is admin. Otherwise, redirects to login page
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        return redirect(url_for('login_page'))
            
    db = Database('database/store_records.db')
    orders = db.get_transactions_by_username(current_username)
    cost = db.get_cost_by_username(current_username)
    quantity=db.get_quantity_by_username(current_username)
    transaction_id=db.get_transaction_id_by_username(current_username)
    date=db.get_date_by_username(current_username)
    return render_template('orders.html', orders=orders, username=current_username, passed_username=current_username,is_logged_in=is_logged_in,cost=cost,quantity=quantity,transaction_id=transaction_id,date=date)

@app.route('/users',methods=['POST', 'GET'])
def users_page():
    """
    Renders the users page for the admin.

    args:
        - None

    returns:
        - None
    """
    # checks if the user is admin. Otherwise, redirects to login page
    if 'username' in session and session['username'] == 'aturing':
        current_username = session['username']
        is_logged_in = True
    else:
        return redirect(url_for('login_page'))
            
    db = Database('database/store_records.db')
    users = db.get_all_user_information()
    return render_template('users.html', users=users, username=current_username, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/add_user')
def add_user_page():
    """
    Renders the add_user page for the admin.

    args:
        - None

    returns:
        - None
    """
    
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True

    return render_template('add_user.html', username=current_username, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/add_user',methods=['POST', 'GET'])
def add_user():
    """
    Renders the add_user form for the admin.

    args:
        - None

    modifies:
        - Adds a new user to the database based on the form input

    returns:
        - Redirects to the users page after deleting the user.
    """
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
      

    username = request.form['username']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    if username_exists(username):
        flash("Username already exists. Please choose a different username.", "warning")
        return redirect(url_for('add_user_page'))
    if email_exists(email):
        flash("Email already exists. Please choose a different email.", "warning")
        return redirect(url_for('add_user_page'))
    password = generate_random_password()
    salt, password_hash = hash_password(password)
    update_passwords(username, password, salt, password_hash)
    db.insert_user(username, password_hash, email, first_name, last_name)
    return redirect(url_for('users_page'))

@app.route('/delete_user/<string:username>', methods=['POST', 'GET'])
def delete_user_page(username):
    """
    Renders the delete user page when the user is at the `/delete_user` endpoint.

    args:
        - username: The username of the user to be deleted.

    modifies:
        - Deletes a user from the database

    returns:
        - Redirects to a users page after deleting the user.
    """

    #user = db.get_user_by_username(username)
    if request.method == 'POST':
        # Perform the user deletion process using the delete_user function
        db.delete_user(username)
        return redirect(url_for('users_page'))  # Redirect to the admin page after successful deletion

    #return render_template('delete_user.html', user=user)

@app.route('/update_user/<string:username>')


def update_user_page(username):
    """
    Renders the "update user page" when the admin is at the `/update_user` endpoint.

    args:
        - username: The username of the user to be updated.

    modifies:
        - None

    returns:
        - The update_user page form
    """
        # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
    user = db.get_user_by_username(username)
    first_name=db.get_first_name_by_username(username)
    last_name=db.get_last_name_by_username(username)
    email=db.get_email_by_username(username)

    return render_template('update_user.html', user=user,first_name=first_name,last_name=last_name,email=email,username=current_username, passed_username=current_username, is_logged_in=is_logged_in)



@app.route('/update_user/',methods=['POST', 'GET'])
def update_user():
    """
    Renders the update user page with the details of the specific user pre-filled

    args:
        - username: The username of the user to be updated.

    modifies:
        - The admin can modify the user's first, last name and email.

    returns:
        - Redirects to the users page after updating the user.
    """
        # Check if a user is logged in and preserve their information

    username_value = request.form.get('user')
    username = db.get_user_by_username(username_value)
    email = request.form['email']
    first_name=request.form['first_name']
    last_name=request.form['last_name']
    db.set_email(username, email)
    db.set_first_name(username, first_name)
    db.set_last_name(username, last_name) 

    return redirect(url_for('users_page'))
    
@app.route('/inventory',methods=['POST', 'GET'])
def inventory_page():
    """
    Renders the inventory page for the admin.

    args:
        - None

    returns:
        - None
    """
        # Check if a user is logged && admin in and preserve their information, otherwise redirecrs it to login page
    if 'username' in session and session['username'] == 'aturing':
        current_username = session['username']
        is_logged_in = True
    else:
        return redirect(url_for('login_page'))
    
    db = Database('database/store_records.db')
    products = db.get_full_inventory()
    return render_template('inventory.html',products=products,username=current_username, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/add_inventory')
def add_inventory_page():
    """
    Renders the add_inventory page for the admin.

    args:
        - None

    returns:
        - None
    """
        # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
    return render_template('add_inventory.html',username=current_username, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/add_inventory',methods=['POST', 'GET'])
def add_inventory():
    """
    Renders the add_inventory form for the admin.

    args:
        - None

    modifies:
        - Adds a new user to the database based on the form input

    returns:
        - Redirects to the users page after deleting the user.
    """
        # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
    item_name = request.form['item_name']
    info = request.form['info']
    price = request.form['price']
    stock = request.form['stock']
    image_url = request.form['image_url']
    category = request.form['category']
    db.insert_inventory_item(item_name,info,price,stock,image_url,category)

    return redirect(url_for('inventory_page'))

@app.route('/delete_inventory/<string:id>', methods=['POST', 'GET'])
def delete_inventory_page(id):
    """
    Renders the delete inventory page when the admin is at the `/delete_inventory` endpoint.

    args:
        - username: The username of the user to be deleted.

    modifies:
        - Deletes a user from the database

    returns:
        - Redirects to a users page after deleting the user.
    """


    if request.method == 'POST':
        # Perform the user deletion process using the delete_user function
        db.delete_inventory_item(id)
        return redirect(url_for('inventory_page'))  # Redirect to the admin page after successful deletion



@app.route('/update_inventory/<string:id>')
def update_inventory_page(id):
    """
    Renders the "update inventory page" when the admin is at the `/update_inventory` endpoint.

    args:
        - product id: The id of the product to be updated.

    modifies:
        - None

    returns:
        - The update_inventory page form
    """
        # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
    id = id
    item_name=db.get_item_name_by_id(id)
    info=db.get_item_info_by_id(id)
    price=db.get_item_price_by_id(id)
    stock=db.get_item_stock_by_id(id)
    category=db.get_item_category_by_id(id)
    image_url=db.get_item_image_url_by_id(id)
    

    return render_template('update_inventory.html', id=id,item_name=item_name,info=info,price=price,stock=stock,category=category, image_url=image_url,username=current_username, passed_username=current_username, is_logged_in=is_logged_in)



@app.route('/update_inventory',methods=['POST', 'GET'])
def update_inventory():
    """
    Renders the update inventory page with the details of the specific item pre-filled


    modifies:
        - The admin can modify the product details.

    returns:
        - Redirects to the main inventory page after updating the user.
    """
        # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False
    id = request.form.get('id')
    new_item_name = request.form['item_name']
    new_item_info = request.form['info']
    new_item_stock = request.form['stock']
    new_item_price = request.form['price']
    new_item_category = request.form['category']
    new_item_image_url = request.form['image_url']
    db.set_item_name(id,new_item_name)
    db.set_item_info(id,new_item_info)
    db.set_item_stock(id,new_item_stock)
    db.set_item_price(id,new_item_price)
    db.set_item_category(id,new_item_category)
    db.set_item_image_url(id,new_item_image_url)


    return redirect(url_for('inventory_page'))

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

    # Checks if the username already exists
    if username_exists(username):
        flash("Username already exists. Please choose a different username.", "warning")
        return redirect(url_for('register_page'))
    if email_exists(email):
        flash("Email already exists. Please choose a different email.", "warning")
        return redirect(url_for('register'))
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
    order = []
    total_cost = 0

    # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False

    for product in products:
        quantity_str = request.form.get(str(product['id']), '0')
        try:
            quantity = int(quantity_str)
        except ValueError:
            quantity = 0

        if quantity > 0:
            item_total = quantity * product['price']
            order.append({
                'item_name': product['item_name'],
                'quantity': quantity,
                'price': product['price'],
                'item_total': item_total,
                'image_url': product['image_url']
            })
            transaction_id = random.randint(1000, 100000)
            item_id = random.randint(1000, 100000)
            todays_date = datetime.today().date()
            total_cost += item_total
            db.insert_new_sale(transaction_id, session.get('username'), item_id, quantity, todays_date, total_cost)


    return render_template('checkout.html', order=order, total_cost=total_cost, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/user_profile')
def user_profile():
    """
    Renders the user profile page.

    args:
        - None

    returns:
        - The 'user_profile' page template
    """
    # Custom variable that will be passed to the home template to control appearance of specific menu items
    is_logged_in = True 
    # Get the currently logged-in user's username from the session
    current_username = session.get('username')

    return render_template('user_profile.html', passed_username=current_username, is_logged_in=is_logged_in)
    
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """
    Renders the product detail page for the selected product.

    args:
        - product_id: The ID of the product to display details for.

    returns:
        - The 'product_detail' page template
    """
    # Get product details based on product_id from your products list or database
    product = products[product_id - 1]
    
    # Check if a user is logged in and preserve their information
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True

    return render_template('product_detail.html', product=product, passed_username=current_username, is_logged_in=is_logged_in)
    
@app.route('/process_payment', methods=['POST'])
def process_payment():
    """
    Handles the payment processing based on the selected payment method.

    args:
        - None

    returns:
        - Redirects to the payment summary and address input page.
    """
    payment_method = request.form.get('payment_method')
    credit_card_number = request.form.get('card_number')
    
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
    else:
        current_username = None
        is_logged_in = False

    if payment_method == 'credit_card':
        total_amount = request.form.get('total_cost')  # Get the total cost from the form

        return render_template('payment_summary.html', total_amount=total_amount, credit_card_number=credit_card_number, passed_username=current_username, is_logged_in=is_logged_in)

@app.route('/process_order', methods=['POST'])
def process_order():
    """
    Handles the order placement and displays an order confirmation page.

    args:
        - None

    returns:
        - Redirects to the order confirmation page.
    """
    street1 = request.form.get('street1')
    street2 = request.form.get('street2')
    city = request.form.get('city')
    state = request.form.get('state')
    zip_code = request.form.get('zip')
    
    if 'username' in session:
        current_username = session['username']
        is_logged_in = True
        db = Database('database/store_records.db')
        first_name = db.get_first_name_by_username(current_username)
    else:
        current_username = None
        is_logged_in = False
        first_name = None

    

    return render_template('order_confirmation.html', street1=street1, street2=street2, city=city, state=state, zip=zip_code, first_name=first_name, passed_username=current_username, is_logged_in=is_logged_in)


if __name__ == '__main__':
    app.run(debug=True, host=HOST, port=PORT)
