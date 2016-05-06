from flask import Flask, redirect, session, render_template, request
from mysqlconnection import MySQLConnector
import re
from flask.ext.bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "I<3SecretsToo"
EMailRegex = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
mysql = MySQLConnector(app, 'py-regform')
@app.route('/')
def main():
	return render_template('main.html')

@app.route('/login', methods = ['POST'])
def validate_login():
	if 'registered' in session:
		del session['registered']
	if 'err_email2' in session:
		del session['err_email2']
	if 'err_password2' in session:
		del session['err_password2']		
	sess_count = 0
	if not EMailRegex.match(request.form['email']):
		session['err_email2'] = "The E-Mail must be a valid e-mail address"
		sess_count += 1
	if len(request.form['password']) < 8:
		session['err_password2'] = "Password must be at least 8 characters"
		sess_count += 1
	if sess_count > 0:
		return redirect('/')
	else:
		query = "SELECT * FROM users WHERE email = :email LIMIT 1"
		data = {'email': request.form['email']}
		user = mysql.query_db(query, data)
		if user == []:
			session['notreg'] = "E-Mail is not registered."	
			return redirect('/')
		else:
			if bcrypt.check_password_hash(user[0]['password'], request.form['password']):
				session['loggedinfo'] = {'id': user[0]['id'], 'first_name': user[0]['first_name'], 'last_name': user[0]['last_name']}
				return redirect('/welcome')
			else:
				session['passmatch'] = "E-Mail or Password does not match registered information"
				return redirect('/')

@app.route('/welcome')
def welcome():
	return render_template('thanks.html')

@app.route('/process', methods = ['POST'])
def validate_():
	if 'notreg' in session:
		del session['notreg']
	if 'err_fname' in session:
		del session['err_fname']
	if 'err_lname' in session:
		del session['err_lname']
	if 'err_email' in session:
		del session['err_email']
	if 'err_password' in session:
		del session['err_password']
	if 'err_confirm' in session:
		del session['err_confirm']
	sess_count = 0
	if len(request.form['fname']) < 2:
		session['err_fname'] = "The first name field must be at least two characters"
		sess_count += 1
	elif not str.isalpha(str(request.form['fname'])):
		session['err_fname'] = "First name cannot have number or symbols"
		sess_count += 1
	if len(request.form['lname']) < 2:
		session['err_lname'] = "The last name field must be at least two characters"
		sess_count += 1
	elif not str.isalpha(str(request.form['lname'])):
		session['err_lname'] = "Last name cannot have number or symbols"
		sess_count += 1
	if not EMailRegex.match(request.form['email']):
		session['err_email'] = "The E-Mail must be a valid e-mail address"
		sess_count += 1
	if len(request.form['password']) < 8:
		session['err_password'] = "Password must be at least 8 characters"
		sess_count += 1
	elif not any(char.isdigit() for char in str(request.form['password'])):
		session['err_password'] = "Password must contain at least one number"
		sess_count += 1
	elif not any(char.isupper() for char in str(request.form['password'])):
		session['err_password'] = "Password must contain at least one uppercase letter"
		sess_count += 1
	if request.form['confirmpass'] != request.form['password']:
		session['err_confirm'] = "The confirmation does not match the password"
		sess_count += 1
	if sess_count > 0:
		return redirect('/')
	else:
		if 'err_fname' in session:
			del session['err_fname']
		if 'err_lname' in session:
			del session['err_lname']
		if 'err_email' in session:
			del session['err_email']
		if 'err_password' in session:
			del session['err_password']
		if 'err_confirm' in session:
			del session['err_confirm']
		session['registered'] = "True"
		query1 = "SELECT email FROM users WHERE email = :email"
		data1 = {"email": request.form['email']}
		if not mysql.query_db(query1, data1):
			pw_hash = bcrypt.generate_password_hash(request.form['password'])
			query = "INSERT INTO users(first_name, last_name, email, password, created_on, updated_on) VALUES(:first_name, :last_name, :email, :password, now(), now())"
			info = {
			"first_name": request.form['fname'],
			"last_name": request.form['lname'],
			"email": request.form['email'],
			"password": pw_hash
			}
			mysql.query_db(query, info)
		else:
			session['user_registered'] = "This E-Mail is already registered"
		return redirect('/')

@app.route('/logout')
def logout():
	session.clear()
	return redirect('/')
app.run(debug=True)

	