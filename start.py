from functools import wraps

from flask import Flask, render_template, request, flash, url_for, redirect
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from wtforms import Form, StringField, PasswordField, SubmitField, validators, DecimalField, TextAreaField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Email, ValidationError
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class SimpleForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    password2 = PasswordField(label='Verify Password', validators=[DataRequired(), validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField(label='Submit')


class ShopForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired(), Length(min=8)])
    address = TextAreaField(label='Address', validators=[DataRequired(), Length(min=20)])
    submit = SubmitField(label='Submit')


class ProductForm(FlaskForm):
    name = StringField(label='Name', validators=[DataRequired(), Length(min=5)])
    description = TextAreaField(label='Description', validators=[DataRequired(), Length(min=10)])
    price = DecimalField(label='Price', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

app = Flask(__name__)
app.secret_key = 'one two three'
Bootstrap5(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    flash('You need to be logged in to access this page.', 'error')
    return redirect(url_for('login'))


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return wrapper


class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    address = db.Column(db.String, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin = db.relationship('User', backref='shops')

    def __repr__(self):
        return


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    description = db.Column(db.String, nullable=False)

    price = db.Column(db.Float, nullable=False)
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)
    shop = db.relationship('Shop', backref='products')

    def __repr__(self):
        return f'<Product {self.name}>'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = SimpleForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.password == password:
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Incorrect email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/shops', methods=['GET', 'POST'])
@login_required
@admin_required
def shops():
    form = ShopForm()
    if form.validate_on_submit():
        name = form.name.data
        address = form.address.data
        shop = Shop(name=name, address=address, admin=current_user)
        db.session.add(shop)
        db.session.commit()
        flash('Shop created successfully.', 'success')
        return redirect(url_for('shops'))

    shops = current_user.shops
    return render_template('shops.html', shops=shops, form=form)


@app.route('/shop/<int:id>/products', methods=['GET', 'POST'])
@login_required
def products(id):
    shop = Shop.query.get(id)
    if not shop:
        flash('Shop not found.', 'error')
        return redirect(url_for('index'))

    if not current_user.is_admin and current_user not in shop.admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))

    form = ProductForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        price = form.price.data
        product = Product(name=name, description=description, price=price, shop=shop)
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully.', 'success')
        return redirect(url_for('products', id=id))

    products = shop.products
    return render_template('products.html', shop=shop, products=products, form=form)


if __name__ == '__main__':
    app.run(debug=True)
