from flask import Flask, render_template, request, redirect, url_for, Response
import flask
from flask_wtf.csrf import CSRFProtect, validate_csrf
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

import pandas as pd
import json
import sqlite3


app = Flask(__name__)
app.secret_key = 'this is a secret'

csrf = CSRFProtect()
csrf.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

users = {'user': {'password': 'password'}}

class User(UserMixin):
	pass


@login_manager.user_loader
def user_loader(username):
	if username not in users:
		return

	user = User()
	user.id = username
	return user


@login_manager.request_loader
def request_loader(request):
	username = request.form.get('username')
	if username not in users:
		return

	user = User()
	user.id = username

	user.is_authenticated = request.form['password'] == users[username]['password']

	return user

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'GET':
		return render_template('login.html')

	username = request.form['username']
	if request.form['password'] == users[username]['password']:
		user = User()
		user.id = username
		login_user(user)
		return redirect(url_for('index'))

	return 'Bad login'

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
	return render_template('index.html')

@app.route('/get_data', methods = ['GET', 'POST'])
@login_required
def get_data():
	payload = request.get_json()
	if not payload:
		raise Exception("No payload provided")
	page = int(payload['page']) or 1
	num_rows = int(payload['num_rows']) or 10

	csrf_token = request.headers.get('X-CSRFToken')
	validate_csrf(csrf_token)

	conn = sqlite3.connect('data.db')
	total = int(pd.read_sql_query('select count(*) from data', conn).iloc[0][0])

	offset = (page - 1) * num_rows
	df = pd.read_sql_query('select * from data limit (?), (?)', conn, params = (offset, num_rows,))
	df = df[df.columns[1:].tolist()]

	res = dict(
		total = total,
		columns = df.columns.tolist(),
		page = page,
		pagination = [5, 10, 20],
		num_rows = num_rows,
		data = df.to_dict(orient="records")
		)

	return Response(json.dumps(res), mimetype="application/json")