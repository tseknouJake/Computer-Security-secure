from flask import Flask, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import logging
import bcrypt
import time


is_admin = False

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.secret_key = "your_secret_key"  # Needed for session management

logging.basicConfig(
    filename="failed_logins.txt",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

failed_attempts = {}
COOLDOWN_TIME = 10
MAX_ATTEMPTS = 3


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


def is_strong_password(password):
    return (
        len(password) >= 8
        and any(c.isdigit() for c in password)
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c in "!@#$%^&*()-_=+" for c in password)
    )


# Home page: shows different content based on whether the user is logged in
@app.route("/")
def home():
    if "username" in session:
        if session['username'] == "admin":
            return (
            f"Hello, {session['username']}!<br>"
            f"<a href='/view_password'>View Password</a><br>"
            f"<a href='/admin_page'>Admin Page</a><br>"
            f"<a href='/logout'>Logout</a>"
            )
        else:
            return (
                f"Hello, {session['username']}!<br>"
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
    if request.method == "POST":
        # Get form data
        username = request.form["username"]
        password = request.form["password"]

        current_time = time.time()

        if username in failed_attempts:
            attempts = failed_attempts[username]["count"]
            last_attempt = failed_attempts[username]["last_attempt"]

            if (
                attempts >= MAX_ATTEMPTS
                and (current_time - last_attempt) < COOLDOWN_TIME
            ):
                remaining_time = int(COOLDOWN_TIME - (current_time - last_attempt))
                return (
                    f"Too many failed attempts. Try again in {remaining_time} seconds."
                )

        # Look up the user in the database
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            failed_attempts.pop(username, None)
            session["username"] = user.username
            return redirect(url_for("home"))

        else:
            logging.warning(
                f"Failed login attempt for username: {username} from IP: {request.remote_addr}"
            )

            if username in failed_attempts:
                failed_attempts[username]["count"] += 1
                failed_attempts[username]["last_attempt"] = current_time
            else:
                failed_attempts[username] = {"count": 1, "last_attempt": current_time}

            return "Invalid credentials.<br><a href='/login'>Try again</a>"

    # HTML form for login
    return """
        <h1>Login</h1>
        <form method="post">
          Username: <input type="text" name="username" required><br>
          Password: <input type="password" name="password" required><br>
          <input type="submit" value="Login">
        </form>
        <br>
        <a href='/signup'>Sign Up</a>
    """


# sign up page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # Get form data
        username = request.form["username"]
        password = request.form["password"]

        # Check if a user with this username already exists in the DB
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists.<br><a href='/signup'>Try again</a>"

        if not is_strong_password(password):
            return (
                "Password must be at least 8 characters long, contain an uppercase letter, "
                "a lowercase letter, a number, and a special character.<br><a href='/signup'>Try again</a>"
            )
        else:
            # Create a new user record and save it to the database
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            return "User created!<br><a href='/login'>Login now</a>"

    # HTML form for signup
    return """
        <h1>Sign Up</h1>
        <form method="post">
          Username: <input type="text" name="username" required><br>
          Password: <input type="password" name="password" required><br>
          <input type="submit" value="Sign Up">
        </form>
        <br>
        <a href='/login'>Login</a>
    """


# New route: View Password
@app.route("/view_password")
def view_password():
    if "username" not in session:
        return redirect(url_for("login"))

    # Get the logged-in username from the session
    username = session["username"]
    # Query the database for the user
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
    if session['username']=="admin":            
        # Get all user records from the database
        users = User.query.all()

        # Build a simple string to display each user's info
        output = "<h1>All Users</h1>"
        for user in users:
            output += f"ID: {user.id}, Username: {user.username}, Password: {user.password}<br>"
    else:
        output = "you are not an adminß"
    return output


# def encrypt_password(plain_pword):
#     plain_pword=plain_pword.encode('uft-8')
#     salt

# def decrypt_password(encrypted_pword):
#     result = []
#     for c in pword:
#         # Shift character back by 3 positions
#         result.append(chr(ord(c) - 3))
#     return "".join(result)


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5003)
