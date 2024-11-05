from flask import Flask, render_template, redirect, flash
from flask_bcrypt import bcrypt, check_password_hash
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields.simple import EmailField, PasswordField, StringField
from wtforms.validators import InputRequired

# init
db = SQLAlchemy()

app = Flask(__name__)

app.config["SECRET_KEY"] = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


class UserDB(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def __repr__(self):
        return f"<UserDB: {self.id}, {self.email}, {self.password}, {self.name}"


class CurrentUser:
    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name

    def check_for_dup_emails(self):
        is_existing_email = UserDB.query.filter_by(email=self.email).first()
        return is_existing_email

    def add_user_to_db(self):
        new_record = UserDB(email=self.email, password=self.password, name=self.name)
        db.session.add(new_record)
        db.session.commit()


class SignupForm(FlaskForm):
    email = EmailField("Email:", validators=[InputRequired()])
    password = PasswordField("Password:", validators=[InputRequired()])
    name = StringField("First Name:", validators=[InputRequired()])


class LoginForm(FlaskForm):
    email = EmailField("Email:", validators=[InputRequired()])
    password = PasswordField("Password:", validators=[InputRequired()])


@login_manager.user_loader
def load_user(user_id):
    return UserDB.query.get(int(user_id))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        new_user = CurrentUser(form.email.data,
                               bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()),
                               form.name.data)

        if new_user.check_for_dup_emails():
            flash("Email address is already used!")
            return redirect("/signup")
        else:
            new_user.add_user_to_db()
        return redirect("/login")
    return render_template("signup.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        current_user = UserDB.query.filter_by(email=form.email.data).first()

        if not current_user:
            flash("Incorrect Email!")
            return redirect("/login")
        if not check_password_hash(current_user.password, form.password.data):
            flash("Incorrect Password!")
            return redirect("/login")

        login_user(current_user)

        return redirect("/user")
    return render_template("login.html", form=form)


@app.route("/user", methods=["GET", "POST"])
@login_required
def user():
    print("User")
    return render_template("userPage.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route("/", methods=["GET", "POST"])
def index():
    print("Index")
    return "Index"


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)