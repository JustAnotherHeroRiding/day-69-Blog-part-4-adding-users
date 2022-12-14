from flask import Flask, render_template, redirect, url_for, flash, request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    
    blogposts = db.relationship("BlogPost", back_populates='author')
    comments = db.relationship("Comment", back_populates="comment_author")
    
    
class BlogPost(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id =  db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship("User", back_populates="blogposts")
    
    comments = db.relationship("Comment", back_populates="blog")
    
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id =  db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = db.relationship("User", back_populates="comments")
    
    blog_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    blog = db.relationship("BlogPost", back_populates="comments")
    

#with app.app_context():
    #db.create_all()


def admin_required(func):
  @wraps(func)
  def wrapper(*args, **kwargs):
    if not current_user.is_authenticated or current_user.id != 1:
      # The user is not an administrator
      # Return a 403 Forbidden error
      return abort(403)
    # The user is an administrator
    # Call the original function and return its result
    return func(*args, **kwargs)
  return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts )


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if db.session.query(User).filter(User.email == form.username.data).first():
            flash('These is already an account with that email adress.', "Message")
            return redirect(url_for('login'))
        new_user = User(
            email = form.username.data,
            password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8),
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(db.session.query(User).filter(User.email == form.username.data).first())
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form = form)


@app.route('/login', methods = ["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.username.data
        user = db.session.query(User).filter(User.email == email).first()
        password = form.password.data
        if not user: 
            flash('That email is not a valid username.\n Try again.', "error")
            return redirect(url_for('login'))
        elif check_password_hash(user.password,password):
            login_user(user)
            flash('Logged in successfully.', "error")
            return redirect(url_for('get_all_posts'))
        else:
            flash('Incorrect password.', "error")
            return redirect(url_for('login'))
    return render_template("login.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully logged yourself out.')
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    all_comments = Comment.query.all()
    requested_post = BlogPost.query.get(post_id)
    comments = CommentForm()
    if comments.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text = comments.comment.data,
                comment_author=current_user,
                blog_id = requested_post.id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id = post_id))
        else:
            flash("Only registered users can post comments.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form = comments,all_comments=all_comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods = ["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
