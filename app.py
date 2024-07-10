from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, session, flash
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
    return render_template('index.html')


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


@app.route('/cart')
def cart():
    return render_template('cart.html')


@app.route('/admin')
def admin():
    return render_template('admin/dashboard.html', current_page='dashboard')


# Route for adding a product
@app.route('/admin/product', methods=['GET', 'POST'])
def product():
    form = ProductForm()
    if form.validate_on_submit():
        name = form.name.data
        price = float(form.price.data)  # Convert DecimalField to float
        image_path = form.image.data  # This should be the path to the image file

        # Insert the product into MongoDB
        product_data = {
            'name': name,
            'price': price,
            'image_path': image_path,
        }
        product_collection.insert_one(product_data)

        flash('Product added successfully!', 'success')
        return redirect(url_for('product'))

    products = list(product_collection.find())  # Fetch all products from MongoDB

    # Log the products to the console
    for product in products:
        print(product)
    return render_template('admin/products.html', form=form, products=products, current_page='product')

@app.route('/reviews')
def reviews():
    return render_template('reviews.html', current_page='reviews')


if __name__ == '__main__':
    app.run(debug=True)
