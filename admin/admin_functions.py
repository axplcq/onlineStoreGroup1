from flask import Blueprint, request, redirect, url_for, render_template, flash
from database.db import Database
from authentication.auth_tools import is_admin

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/inventory/add', methods=['GET', 'POST'])
def add_inventory_item():
    if request.method == 'POST':
        # Get data from the form and insert it into the 'inventory' table
        item_name = request.form['item_name']
        info = request.form['info']
        price = float(request.form['price'])
        stock = int(request.form['stock'])
        image_url = request.form['image_url']
        category = request.form['category']

        db = Database('database/store_records.db')
        # Insert the data into the 'inventory' table
        db.insert_new_item(item_name, price, info, stock, image_url, category)
        flash('Inventory item added successfully!', 'success')

    return render_template('add_inventory.html')


@admin_bp.route('/inventory/delete/<int:item_id>', methods=['POST'])
def delete_inventory_item(item_id):
    db = Database('database/store_records.db')
    # Delete the inventory item with the specified ID from the 'inventory' table
    db.delete_item_by_id(item_id)
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('admin.inventory_management'))


@admin_bp.route('/users/add', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        # Get data from the form and insert it into the 'users' table
        username = request.form['username']
        user_role = request.form['user_role']
        password_hash = request.form['password_hash']
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']

        db = Database('database/store_records.db')
        # Insert the data into the 'users' table
        db.insert_user(username, user_role, password_hash, email, first_name, last_name)
        flash('User added successfully!', 'success')

    return render_template('add_user.html')

@is_admin
@admin_bp.route('/users/delete/<string:username>', methods=['POST'])
def delete_user(username):
    db = Database('database/store_records.db')
    # Delete the user with the specified username from the 'users' table
    db.delete_user_by_username(username)
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin.user_management'))