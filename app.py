from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from forms import RegistrationForm, LoginForm , ExpenseForm
from database import query_db, insert_db, get_user_by_id, init_db
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        insert_db('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                  (form.username.data, form.email.data, hashed_password))
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = query_db('SELECT * FROM users WHERE email = ?', [form.email.data], one=True)
        if user and bcrypt.check_password_hash(user[3], form.password.data):
            user_obj = User(id=user[0], username=user[1], email=user[2], password=user[3])
            login_user(user_obj, remember=form.remember.data)
            return redirect(url_for('view_expenses'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout',methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# app.py

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        insert_db('INSERT INTO expenses (user_id, description, amount, date) VALUES (?, ?, ?, ?)',
                  (current_user.id, form.description.data, float(form.amount.data), form.date.data))
        flash('Expense added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_expense.html', form=form)


@app.route('/view-expenses')
@login_required
def view_expenses():
    expenses = query_db('SELECT * FROM expenses WHERE user_id = ?', [current_user.id])
    return render_template('view_expenses.html', expenses=expenses)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'init_db':
        init_db(app)  # Pass the `app` object here
        print("Database initialized successfully.")
    else:
        app.run(debug=True)
