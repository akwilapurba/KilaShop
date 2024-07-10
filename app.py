from functools import wraps

from bson import ObjectId
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField
from wtforms.fields import PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from pymongo import MongoClient

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key'

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['kilashop']
product_collection = db['product']
user_collection = db['user']

# Bcrypt
bcrypt = Bcrypt(app)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired()])
    middle_name = StringField('Middle Name')
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    submit = SubmitField('Register')


# Define the User Login Form using WTForms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Define the Product Form using WTForms
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    image = StringField('Image Path', validators=[DataRequired()])
    submit = SubmitField('Add Product')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = user_collection.find_one({'username': session['username']})
        if not user or user['role'] != 'admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def home():
    products = list(product_collection.find())  # Fetch all products from MongoDB
    return render_template('index.html', products=products)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password,
            'first_name': form.first_name.data,
            'middle_name': form.middle_name.data,
            'last_name': form.last_name.data,
            'phone_number': form.phone_number.data,
            'address': form.address.data,
            'role': 'member'
        }
        user_collection.insert_one(user_data)
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = user_collection.find_one({'username': form.username.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            session['username'] = user['username']
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('home'))


@app.route('/products')
def products():
    return render_template('products.html')


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    # Get product ID from the request json data
    product_id = request.json.get('product_id')
    product = product_collection.find_one({'_id': ObjectId(product_id)})
    if not product:
        print(f"Product not found for ID: {product_id}")
        return jsonify({'error': 'Product not found'}), 404

    cart_items = session.get('cart', [])
    cart_items.append({
        'product_id': str(product['_id']),  # Convert ObjectId to string
        'name': product['name'],
        'price': product['price'],
        'image_path': product['image_path'],
    })
    session['cart'] = cart_items

    return jsonify({'message': 'Product added to cart successfully'})

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    product_id = request.json.get('product_id')

    if 'cart' in session:
        cart_items = session['cart']
        for item in cart_items:
            if item['product_id'] == product_id:
                cart_items.remove(item)
                break  # Stop after removing the first matching item

        session['cart'] = cart_items

    return jsonify({'message': 'Product removed from cart successfully'})

@app.route('/cart')
def view_cart():
    cart_items = session.get('cart', [])

    return render_template('cart.html', cart_items=cart_items)


@app.route('/delete_cart', methods=['POST'])
def delete_cart():
    session.pop('cart', None)  # Remove the 'cart' key from the session
    flash('Cart cleared successfully!', 'success')
    return redirect(url_for('view_cart'))


@app.route('/admin')
def admin():
    return render_template('admin/dashboard.html', current_page='dashboard')


# Route for adding a product
@app.route('/admin/product', methods=['GET', 'POST'])
def product():
    if request.method == 'POST':
        form = ProductForm(request.form)
        if form.validate():
            name = form.name.data
            price = float(form.price.data)  # Convert DecimalField to float
            image_path = form.image.data  # This should be the path to the image file

            # Insert the product into MongoDB
            product_data = {
                'name': name,
                'price': price,
                'image_path': image_path,
            }
            product_id = product_collection.insert_one(product_data).inserted_id

            # Optionally, you can return the newly added product as JSON
            return jsonify({
                'message': 'Product added successfully',
                'product_id': str(product_id),
                'name': name,
                'price': price,
                'image_path': image_path,
            })
        else:
            # Handle form validation errors
            return jsonify({'error': 'Form validation failed'}), 400

    # Handle GET request for rendering the page initially
    form = ProductForm()
    products = list(product_collection.find())
    return render_template('admin/products.html', form=form, products=products, current_page='product')


# Route for editing a product
@app.route('/admin/product/edit/<string:product_id>', methods=['GET', 'POST'])
@login_required
# @admin_required
def edit_product(product_id):
    form = ProductForm()
    product = product_collection.find_one({'_id': ObjectId(product_id)})
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('product'))

    if form.validate_on_submit():
        name = form.name.data
        price = float(form.price.data)
        image_path = form.image.data

        # Update the product in MongoDB
        product_collection.update_one({'_id': ObjectId(product_id)},
                                      {'$set': {'name': name, 'price': price, 'image_path': image_path}})

        flash('Product updated successfully!', 'success')
        return redirect(url_for('product'))

    # Pre-fill the form with existing product data
    form.name.data = product['name']
    form.price.data = product['price']
    form.image.data = product['image_path']

    return render_template('admin/edit_product.html', form=form, product=product)


# Route for deleting a product
@app.route('/admin/product/delete/<string:product_id>', methods=['DELETE'])
@login_required
# @admin_required
def delete_product(product_id):
    product = product_collection.find_one({'_id': ObjectId(product_id)})
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('product'))

    product_collection.delete_one({'_id': ObjectId(product_id)})
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('products'))


@app.route('/reviews')
def reviews():
    return render_template('reviews.html', current_page='reviews')


if __name__ == '__main__':
    app.run(debug=True)
