from flask import Flask, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
import logging
import bcrypt
import time
import openai 
import os



app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "your_secret_key"  # Needed for session management
app.config["PEPPER"] = (
    "VeryLongAndCoolPepper"  # we will use this for password peppering
)

db = SQLAlchemy(app)

logging.basicConfig(
    filename="failed_logins.txt",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

failed_attempts = {}
COOLDOWN_TIME = 11
MAX_ATTEMPTS = 3


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

openai.api_key = os.getenv("OPENAI_API_KEY", "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")


def get_inspirational_quote():
    try:
        response = openai.ChatCompletion.create(
            model="gpt",  # using a known working model
            messages=[
                {"role": "user", "content": "give me a random very inspirational quote for my run club"}
            ]
        )
        # Extract the generated quote from the response dictionary
        quote = response['choices'][0]['message']['content'].strip()
    except Exception as e:
        print("Error generating quote:", e)
        quote = "Keep pushing forward, one step at a time!"
    return quote


def is_strong_password(password):
    return (
        len(password) >= 8
        and any(c.isdigit() for c in password)
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c in "!@#$%^&*()-_=+" for c in password)
    )


# home page
@app.route("/")
def home():
    if "username" in session:

        quote = get_inspirational_quote()
        if session["username"] == "admin":
            return (
                f"Hello, {session['username']}!<br>"
                f"<em>{quote}</em><br>"
                f"<a href='/view_password'>View Password</a><br>"
                f"<a href='/admin_page'>Admin Page</a><br>"
                f"<a href='/logout'>Logout</a>"
            )
        else:
            return (
                f"Hello, {session['username']}!<br>"
                f"<em>{quote}</em><br>"
                f"<a href='/view_password'>View Password</a><br>"
                f"<a href='/logout'>Logout</a>"
            )
    return (
        "You are not logged in.<br>"
        "<a href='/login'>Login</a> or <a href='/signup'>Sign Up</a>"
    )


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None
    username_value = ""
    password_value = ""
    cooldown_time = None

    if request.method == "POST":
        # Capture form data
        username_value = request.form["username"]
        password_value = request.form["password"]
        current_time = time.time()

        if username_value in failed_attempts:
            attempts = failed_attempts[username_value]["count"]
            last_attempt = failed_attempts[username_value]["last_attempt"]
            if (
                attempts >= MAX_ATTEMPTS
                and (current_time - last_attempt) < COOLDOWN_TIME
            ):
                remaining_time = int(COOLDOWN_TIME - (current_time - last_attempt))
                error_message = "Too many failed attempts. Please wait."
                cooldown_time = remaining_time  # Pass remaining time to the template
                return render_template(
                    "login.html",
                    error_message=error_message,
                    username_value=username_value,
                    password_value=password_value,
                    cooldown_time=cooldown_time,
                )

        # look up the user in the database
        user = User.query.filter_by(username=username_value).first()
        if user:
            peppered_password = (password_value + app.config["PEPPER"]).encode("utf-8")
            stored_hash = user.password.encode("utf-8")
            if bcrypt.checkpw(peppered_password, stored_hash):
                failed_attempts.pop(username_value, None)
                session["username"] = user.username
                return redirect(url_for("home"))
            else:
                            logging.warning(
                f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}"
            )
            print(f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}")
            if username_value in failed_attempts:
                failed_attempts[username_value]["count"] += 1
                failed_attempts[username_value]["last_attempt"] = current_time
            else:
                failed_attempts[username_value] = {
                    "count": 1,
                    "last_attempt": current_time,
                }
            error_message = "Invalid credentials"
        else:
            logging.warning(
                f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}"
            )
            print(f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}")
            if username_value in failed_attempts:
                failed_attempts[username_value]["count"] += 1
                failed_attempts[username_value]["last_attempt"] = current_time
            else:
                failed_attempts[username_value] = {
                    "count": 1,
                    "last_attempt": current_time,
                }
            error_message = "Invalid credentials"

    return render_template(
        "login.html",
        error_message=error_message,
        username_value=username_value,
        password_value=password_value,
        cooldown_time=cooldown_time,
    )


# sign up page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    error_message = None
    username_value = ""
    password_value = ""

    if request.method == "POST":
        # Get form data
        username_value = request.form["username"]
        password_value = request.form["password"]

        # Check if a user with this username already exists in the DB
        existing_user = User.query.filter_by(username=username_value).first()
        if existing_user:
            error_message = "User with that username already exists"
            return render_template(
                "signup.html",
                error_message=error_message,
                username_value=username_value,
                password_value=password_value,
            )

        if not is_strong_password(password_value):
            error_message = (
                "Password must be at least 8 characters long, contain an uppercase letter, "
                "a lowercase letter, a number, and a special character."
            )
            return render_template(
                "signup.html",
                error_message=error_message,
                username_value=username_value,
                password_value=password_value,
            )
        else:
            # Create a new user record and save it to the database
            peppered_password = (password_value + app.config["PEPPER"]).encode("utf-8")
            hashed_password = bcrypt.hashpw(peppered_password, bcrypt.gensalt())
            new_user = User(username=username_value, password=hashed_password.decode("utf-8"))
            db.session.add(new_user)
            db.session.commit()
            return "User created!<br><a href='/login'>Login now</a>"

    return render_template(
        "signup.html",
        error_message=error_message,
        username_value=username_value,
        password_value=password_value,
    )


# view password
@app.route("/view_password")
def view_password():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    user = User.query.filter_by(username=username).first()

    if user:
        return f"Your password is: <strong>{user.password}</strong><br><a href='/'>Go back</a>"
    else:
        return "User not found."


# Logout route: Clears the session
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))


@app.route("/admin_page")
def admin_page():
    output = "you are not an admin"
    if session.get("username") is not None:
        if session["username"] == "admin":
            # Get all user records from the database
            users = User.query.all()

            # Build a simple string to display each user's info
            output = "<h1>All Users</h1>"
            for user in users:
                output += f"ID: {user.id}, Username: {user.username}, Password: {user.password}<br>"

    return output


# to run the app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5003)
