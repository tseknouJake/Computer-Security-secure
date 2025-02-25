from flask import Flask, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
import logging
import bcrypt
import time
import pandas as pd


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "your_secret_key"  # for session management
app.config["PEPPER"] = (
    "VeryLongAndCoolPepper"  # we will use this for password peppering
)

# open database
db = SQLAlchemy(app)

# configures the loggins when a user attempts to log in
logging.basicConfig(
    filename="failed_logins.txt",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logging.getLogger("werkzeug").setLevel(logging.WARNING)

failed_attempts = {}
COOLDOWN_TIME = 11
MAX_ATTEMPTS = 3
df = pd.read_csv("quotes.csv", encoding="utf-8")  # we use this csv for the quotes


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


# makes sure we have a secure password that is at least 8 characters long,
# contains an uppercase letter, a lowercase letter, a number, and a special character
def is_strong_password(password):
    return (
        len(password) >= 8
        and any(c.isdigit() for c in password)
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c in "!@#$%^&*()-_=+" for c in password)
    )


# returns an array that has the quote at position 0 and the author name position 1
def get_random_quote_and_author():
    random_row = df.sample(n=1).iloc[0]  # select random row

    return [random_row["Quote"], random_row["Author"]]


# home page
@app.route("/")
def home():
    if "username" in session:
        quote = get_random_quote_and_author()

        # if user is the admin user allow them to go to the admin page
        if session["username"] == "admin":
            return (
                f"Hello, {session['username']}!<br>"
                f"<a href='/view_password'>View Password</a><br>"
                f"<a href='/admin_page'>Admin Page</a><br>"
                f"<a href='/logout'>Logout</a><br>"
                f"""
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 50vh;">
                    <div style="max-width: 800px; margin: 0 auto; text-align: center; padding: 20px;">
                        <h1 style="margin-bottom: 20px;">{quote[0]}</h1>
                        <p> - {quote[1]} </p>
                        <button onclick="location.reload()">New Quote</button>
                    </div>
                </div>
                """
            )
        else:
            # normal user
            return (
                f"Hello, {session['username']}!<br>"
                f"<a href='/view_password'>View Password</a><br>"
                f"<a href='/logout'>Logout</a><br>"
                f"""
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 50vh;">
                    <div style="max-width: 800px; margin: 0 auto; text-align: center; padding: 20px;">
                        <h1 style="margin-bottom: 20px;">{quote[0]}</h1>
                        <p> - {quote[1]} </p>
                        <button onclick="location.reload()">New Quote</button>
                    </div>
                </div>
                """
            )
    return (
        "You are not logged in.<br>"
        "<a href='/login'>Login</a> or <a href='/signup'>Sign Up</a>"
    )


# login page
@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None
    username_value = ""
    password_value = ""
    cooldown_time = None

    if request.method == "POST":
        # capture form data and current time
        username_value = request.form["username"]
        password_value = request.form["password"]
        current_time = time.time()

        # used for the time out
        if username_value in failed_attempts:
            attempts = failed_attempts[username_value]["count"]
            last_attempt = failed_attempts[username_value]["last_attempt"]
            if (
                attempts >= MAX_ATTEMPTS
                and (current_time - last_attempt) < COOLDOWN_TIME
            ):
                # give a cool down if user unsuccessfully tried to log in 3 times
                remaining_time = int(COOLDOWN_TIME - (current_time - last_attempt))
                error_message = "Too many failed attempts. Please wait."
                cooldown_time = remaining_time
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

            # pepper the password with our awesome pepper
            peppered_password = (password_value + app.config["PEPPER"]).encode("utf-8")
            stored_hash = user.password.encode("utf-8")

            # decrypts the encrypted password and if the user is valid then we send the
            # user to the home page
            if bcrypt.checkpw(peppered_password, stored_hash):
                failed_attempts.pop(username_value, None)
                session["username"] = user.username
                return redirect(url_for("home"))
            else:
                logging.warning(
                    f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}"
                )
            print(
                f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}"
            )

            # increase count if the username has tried to log in
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
            print(
                f"Failed login attempt for username: {username_value} from IP: {request.remote_addr}"
            )
            # increase count if the username has tried to log in
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

        #displays message when password isnt strong
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
            # create a new user record and save it to the database
            peppered_password = (password_value + app.config["PEPPER"]).encode("utf-8")
            hashed_password = bcrypt.hashpw(peppered_password, bcrypt.gensalt())
            new_user = User(
                username=username_value, password=hashed_password.decode("utf-8")
            )
            db.session.add(new_user)
            db.session.commit()
            return "User created!<br><a href='/login'>Login now</a>"

    return render_template(
        "signup.html",
        error_message=error_message,
        username_value=username_value,
        password_value=password_value,
    )


# view password route
@app.route("/view_password")
def view_password():
    if "username" not in session:
        return redirect(url_for("login"))

    # get the logged-in username from the session
    username = session["username"]

    # search database for the user
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
    #default output is "you are not an admin"
    output = "you are not an admin"
    if session.get("username") is not None:
        
        #checks if the user is the admin
        if session["username"] == "admin":
            # get all user records from the database
            users = User.query.all()

            # show all users on the page
            output = "<h1>All Users</h1>"
            for user in users:
                output += f"ID: {user.id}, Username: {user.username}, Password: {user.password}<br>"

    return output


# to run the app
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5003)
