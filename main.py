import os
from datetime import date
from functools import wraps
import psycopg2

from sqlalchemy import exc
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy()
db.init_app(app)

# Connect with Postgresql
conn = psycopg2.connect(
    database=os.environ.get("POSTGRES_DATABASE"),
    user=os.environ.get("POSTGRES_USER"),
    password=os.environ.get("POSTGRES_PASSWORD"),
    host=os.environ.get("POSTGRES_HOST"),
    port="5432"
)

cur = conn.cursor()

# Gravatar
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    # id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # parent_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # parent: Mapped["User"] = relationship(back_populates="children")

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"

    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    commenter = relationship("User", back_populates="comments")

    parent_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    comment = db.Column(db.String(500), nullable=False)
    date = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()


# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = RegisterForm()

    if reg_form.validate_on_submit():
        u_name = reg_form.name.data
        u_email = reg_form.email.data
        u_password = generate_password_hash(reg_form.password.data or "", "pbkdf2:sha256", 8)

        new_user = User()
        new_user.name = u_name
        new_user.email = u_email
        new_user.password = u_password

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for("get_all_posts", user=current_user))
        except exc.IntegrityError:
            flash("You have already registered with the same email. Please Login.")
            return redirect(url_for("login"))
    return render_template("register.html", form=reg_form, user=current_user)


# Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()

    if login_form.validate_on_submit():
        u_email = login_form.email.data
        u_password = login_form.password.data

        user = db.session.execute(db.select(User).where(User.email == u_email)).scalar()

        if user:
            if user.password and check_password_hash(user.password, u_password or ""):
                login_user(user)
                # flash('You were successfully logged in')
                return redirect(url_for("get_all_posts", user=current_user))
            else:
                flash('You entered incorrect password! PLease try again.')
                return redirect(url_for("login", user=current_user))
        else:
            flash('You entered wrong email! PLease try again.')
            return redirect(url_for("login", user=current_user))

    return render_template("login.html", form=login_form, user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', user=current_user))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, user=current_user)


# Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment = CommentForm()

    if comment.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login", user=current_user))

        u_comment = comment.comment.data

        new_comment = Comment()
        new_comment.comment = u_comment
        new_comment.commenter = current_user
        new_comment.parent_post = requested_post
        new_comment.date = date.today().strftime("%B %d, %Y")

        db.session.add(new_comment)
        db.session.commit()

    comments = db.session.execute(db.select(Comment).where(Comment.parent_post_id == post_id)).scalars().all()

    return render_template("post.html", post=requested_post, comment_form=comment, comments=comments, user=current_user)


@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    comment = db.get_or_404(Comment, comment_id)
    parent_post_id = comment.parent_post_id
    if comment.commenter != current_user:
        flash("You need to login with the same account you commented with to delete this comment.")
    else:
        db.session.delete(comment)
        db.session.commit()
    return redirect(url_for("show_post", post_id=parent_post_id, user=current_user))


# Python Decorator - @admin_only
def admin_only(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)

    return wrapper


# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost()
        new_post.title = form.title.data
        new_post.subtitle = form.subtitle.data
        new_post.body = form.body.data
        new_post.img_url = form.img_url.data
        new_post.author = current_user
        new_post.date = date.today().strftime("%B %d, %Y")
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", user=current_user))
    return render_template("make-post.html", form=form, user=current_user)


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, user=current_user))
    return render_template("make-post.html", form=edit_form, is_edit=True, user=current_user)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', user=current_user))


@app.route("/about")
def about():
    return render_template("about.html", user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", user=current_user)


if __name__ == "__main__":
    app.run(debug=False)
