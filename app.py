from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.secret_key = "This is my secret key"

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class Blog(db.Model):
		__tablename__= 'blog'
		id = db.Column(db.Integer, primary_key=True)
		title = db.Column(db.String(200), nullable=False)
		body = db.Column(db.String, nullable=False)
		author = db.Column(db.String(20), nullable=False)
		created = db.Column(db.DateTime, server_default=db.func.now())
		updated = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

class User(UserMixin, db.Model):
		__tablename__= 'users'
		id = db.Column(db.Integer, primary_key=True)
		email = db.Column(db.String(25), index=True, nullable=False, unique=True)
		username = db.Column(db.String(20) , nullable=False)
		password = db.Column(db.String(255), nullable=False)

		def set_password(self, password):
			self.password = generate_password_hash(password)

		def check_password(self, password):
			return check_password_hash(self.password, password)

		def check_email(self, email):
			return User.query.filter_by(email=email).first()

db.create_all()

class RegisterForm(FlaskForm):
	username = StringField("User name", validators=[validators.DataRequired(),validators.Length(min=3,max=20,message="The message need to be in beetween 3 and 20")])

	email = StringField("User name", validators=[validators.DataRequired(),validators.Length(min=5,max=25,message="The message need to be in beetween 5 and 25"), validators.Emails("Please enter a correst email")])

	password = PasswordField('Your password', validators=[InputRequired(), EqualTo('confirm', message='Passwords must match')])
	confirm = 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/', methods=["GET"])
def root():
    return render_template('index.html')

@app.route('/login', methods=["POST", "GET"])
def login():
  if request.method == 'POST':
			user = User.query.filter_by(email=request.form['email']).first()
			if not user:
				flash('Sorry, your email does not exist!', 'warning')
				return redirect(url_for('register'))
			
			if user.check_password(request.form['password']):
				login_user(user)
				current_user
				flash('Welcome back {0}'.format(user.username), 'success')
				return redirect(url_for('root'))
			flash('Sorry, your email or password is incorrect!', 'warning')
			return redirect(url_for('login'))

			if user.check_password(request.form['username']):
				login_user(user)
				current_user
				flash('Welcome back {0}'.format(user.username), 'success')
				return redirect(url_for('root'))
			flash('Sorry, your username is incorrect!', 'warning')
			return redirect(url_for('posts'))

  return render_template('login.html')

@app.route('/register', methods=['POST','GET'])
def register():
	if current_user.is.authenticated:
		return redirect(url_for('new_post'))

	if request.method == 'POST':
		user = User()
		check = user.check_email(request.form['email'])
		if user:
			flash('Email is available!', 'warning')
			return redirect(url_for('login'))
		if not user:
			new_user = User(email=request.form['email'], username=request.form['username'])
			new_user.generate_password(request.form['password'])
			db.session.add(user)
			db.session.commit()
			flash('You have successfully signed up!', 'success')
			return redirect(url_for('login'))
	return render_template('register.html')

@app.route('/profile', methods=["POST", "GET"])
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
	logout_user(current_user)
	return redirect(url_for('login'))

@app.route('/protected')
def protected():
	return "OK"

@app.route('/posts', methods=["GET"])
def posts():
	if request.method():
		posts = Blog.query.all()
		new_blog = Blog(title=request.form['title'],
						body=request.form['body'],
						author=request.form['author'])
		db.session.add(new_blog)
		db.session.commit()
		return redirect(url_for('new_post'))
    return render_template('blog.html', posts = posts)

if __name__ == "__main__":
    app.run(debug=True)
