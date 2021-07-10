from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from smtplib import SMTP
import os

app = Flask(__name__)

# Getting the environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
my_email = os.getenv('MY_EMAIL')
my_pass = os.getenv('MY_PASSWORD')

# INITIALIZATION
login_manager = LoginManager(app)
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES - with bidirectional relationship
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    posts = db.relationship('BlogPost', backref='user')  # creating a relationship between the two tables
    # the backref = user ensures a bidirectional relation is created where the user of the users table can be accessed
    # the Blog Post table by mentioning user = current_user object
    comments = db.relationship('Comment', backref='user')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # creates a foreign key which stores the user id from
    # users table
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('Comment', backref='post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


# db.create_all()

# To send email to blog owner
def send_email(name, email, ph_no, msg):
    with SMTP('smtp.gmail.com') as connection:
        connection.starttls()
        connection.login(my_email, my_pass)
        connection.sendmail(from_addr=my_email,
                            to_addrs=my_email,
                            msg=f'Subject: Message from BlogPost\n\n'
                                f'Name: {name}\n'
                                f'Email: {email}\n'
                                f'Phone No.: {ph_no}\n'
                                f'Message: \n{msg}'
                            )


# creating user loader function for flask login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user:
            if not current_user.is_anonymous:
                if current_user.id == 1:
                    return function(*args, **kwargs)
                else:
                    return abort(403)
            else:
                return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        name = register_form.name.data
        email = register_form.email.data
        password = generate_password_hash(password=register_form.password.data, salt_length=8)
        new_user = User(name=name, email=email, password=password)
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        except IntegrityError:
            flash('Email already exists. Log in instead.')
            return redirect(url_for('login'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password_input = login_form.password.data
        user = User.query.filter_by(email=email).first()
        if user is not None:
            if check_password_hash(pwhash=user.password, password=password_input):
                login_user(user=user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect. Please try again')
                return redirect(url_for('login'))
        else:
            flash('Email does not exist. Please try again')
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = [comment for comment in Comment.query.all() if comment.post_id == post_id]
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            text = comment_form.comment.data
            new_comment = Comment(text=text,
                                  user=current_user,
                                  post=requested_post)  # creating a new comment saving the user_id and post_id
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("Log In to comment.")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        ph_no = request.form.get('phone')
        msg = request.form.get('message')

    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    print(current_user.name, type(current_user), type(current_user.name))
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            user=current_user  # this will allow the BlogPost table to access the User table data for the
            # particular user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
