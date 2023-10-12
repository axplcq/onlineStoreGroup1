import sqlite3
import uuid
from flask_mail import Message


def dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    """
    Creates a dictionary from a row in the database. This is used to convert the rows into dictionaries.

    args:
        - cursor: The cursor of the database, which is a built-in sqlite3 class.
        - row: The row to convert into a dictionary.

    returns:
        - The dictionary of the row.
    """

    row_dict = {}
    for index, column in enumerate(cursor.description):
        row_dict[column[0]] = row[index]
    return row_dict







def calculate_cost(price: int, quantity: int, discount: float = 0.0, tax_rate: float = 0.05) -> float:
    """
    Calculates the cost of an item.

    args:
        - price: The price of the item.
        - quantity: The quantity of the item.
        - discount: The discount of the item.
        - tax_rate: The tax rate of the item.

    returns:
        - The cost of the item as a float.
    """
    return (price * quantity) * (1 - discount) * (1 + tax_rate)


def calculate_total_cost(items: dict) -> float:
    """
    Calculates the total cost of a set of items.

    args:
        - items: A dictionary of items to calculate the total cost of.

    returns:
        - The total cost of the sale as a float.
    """
    total_cost = 0
    print(items)
    for i in items:
        item = items[i]
        total_cost += calculate_cost(float(item["price"]), int(item["quantity"]),
                                     float(item["discount"]), int(item["tax_rate"]))
    return total_cost


def generate_unique_id() -> str:
    """
    Generates a unique ID.

    args:
        - None

    returns:
        - A unique ID as a string.
    """
    return str(uuid.uuid4())


def send_order_confirmation_email(email: str, order_details: dict) -> None:
    """
    Sends an order confirmation email to the customer.

    args:
        - email: The customer's email address.
        - order_details: A dictionary containing order details.

    returns:
        - None
    """
    # You need to configure Flask-Mail first, as mentioned in the original code
    msg = Message('Order Confirmation', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'Your order details:\n'
    for item, quantity in order_details.items():
        msg.body += f'{item}: {quantity}\n'
    # Add more order details like shipping information, total cost, etc.
    # msg.body += 'Shipping Information: ...\n'
    # msg.body += f'Total Cost: {total_cost}\n'
    # ...

    # Send the email
    mail.send(msg)
