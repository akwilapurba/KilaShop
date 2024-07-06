from flask import Flask, render_template, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField
from wtforms.validators import DataRequired
from pymongo import MongoClient

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key'  # Replace with your secret key

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['your_database']
collection = db['products']

# Define the Product Form using WTForms
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    image = StringField('Image Path', validators=[DataRequired()])
    submit = SubmitField('Add Product')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

# Route for adding a product
@app.route('/admin/add_product', methods=['GET', 'POST'])
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        name = form.name.data
        price = form.price.data
        image_path = form.image.data  # This should be the path to the image file

        # Insert the product into MongoDB
        product_data = {
            'name': name,
            'price': price,
            'image_path': image_path,
        }
        collection.insert_one(product_data)

        return redirect(url_for('index'))
    return render_template('add_product.html', form=form)

@app.route('/reviews')
def reviews():
    return render_template('reviews.html')

if __name__ == '__main__':
    app.run(debug=True)
