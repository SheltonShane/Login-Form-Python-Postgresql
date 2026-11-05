"""
Brickshare backend: Flask + PostgreSQL.

Serves the web page and a small JSON API:
    POST   /api/login            sign in (starts a session)
    POST   /api/logout           sign out (ends the session)
    GET    /api/me               is the browser currently signed in?
    GET    /api/employees        list all employees
    POST   /api/employees        add an employee
    PUT    /api/employees/<id>   edit an employee
    DELETE /api/employees/<id>   delete an employee

Run with:  python app.py   (then open http://localhost:5000)
"""

import os
from contextlib import contextmanager
from datetime import date
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session

# Read settings from the .env file (DB credentials, SECRET_KEY)
load_dotenv()

app = Flask(__name__, static_folder="static")

# The secret key signs the session cookie so users can't forge it.
# The app refuses to start without one, so you can't run with an unsafe default.
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript can't read the cookie
    SESSION_COOKIE_SAMESITE="Lax",   # blocks most cross-site request forgery
    # SESSION_COOKIE_SECURE=True,    # uncomment when you serve the site over HTTPS
)

# ---------------------------------------------------------------------------
# Database connection handling
# ---------------------------------------------------------------------------

# A pool keeps a few connections open and reuses them, which is much faster
# than opening a new connection for every request.
pool = SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.environ["DB_NAME"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
)


@contextmanager
def db_cursor():
    """
    Borrow a connection from the pool and yield a cursor.
    Commits if the block succeeds, rolls back if it raises, and always
    returns the connection to the pool.
    """
    conn = pool.getconn()
    try:
        # RealDictCursor returns rows as dicts: {"name": "Alice", ...}
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_required(view):
    """Decorator: reject the request with 401 unless the user is signed in."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Not signed in."), 401
        return view(*args, **kwargs)
    return wrapper


def row_to_json(row):
    """Convert a database row into something JSON can carry."""
    return {
        "employee_id": row["employee_id"],
        "name": row["name"],
        "surname": row["surname"],
        "dob": row["dob"].isoformat(),      # date -> "1990-03-15"
        "gender": row["gender"],
        "salary": float(row["salary"]),     # Decimal -> number
        "designation": row["designation"],
    }


def clean_employee(data):
    """
    Validate and tidy the JSON sent by the page.
    Returns (record, error). Exactly one of the two is None.
    The database has matching CHECK constraints, but checking here lets us
    return a friendly message instead of a raw database error.
    """
    data = data or {}
    name = str(data.get("name", "")).strip()
    surname = str(data.get("surname", "")).strip()
    gender = str(data.get("gender", "")).strip()
    designation = str(data.get("designation", "")).strip()

    # Every field is required
    if not (name and surname and gender and designation and data.get("dob") not in (None, "")):
        return None, "Please fill in every field."

    # Keep values within the column sizes defined in schema.sql
    if len(name) > 50 or len(surname) > 50 or len(designation) > 100:
        return None, "A value is too long."

    if gender not in ("Male", "Female", "Other"):
        return None, "Gender must be Male, Female or Other."

    # DOB must be a real date (YYYY-MM-DD) and not in the future
    try:
        dob = date.fromisoformat(str(data["dob"]))
    except ValueError:
        return None, "DOB must be a valid date."
    if dob > date.today():
        return None, "DOB cannot be in the future."

    # Salary must be a non-negative number that fits NUMERIC(12,2)
    try:
        salary = round(float(data.get("salary")), 2)
    except (TypeError, ValueError):
        return None, "Salary must be a number."
    if salary < 0 or salary >= 10**10:
        return None, "Salary must be between 0 and 9,999,999,999.99."

    return {
        "name": name, "surname": surname, "dob": dob,
        "gender": gender, "salary": salary, "designation": designation,
    }, None


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    """Serve the login + employees page."""
    return send_from_directory(app.static_folder, "brickshare.html")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    if not username or not password:
        return jsonify(error="Enter your username and password."), 400

    # crypt(password, stored_hash) re-hashes the typed password using the salt
    # stored in the hash; it matches only if the password is correct.
    # %s placeholders keep the values separate from the SQL (prevents SQL injection).
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT user_id, username
            FROM users
            WHERE username = %s
              AND password_hash = crypt(%s, password_hash)
            """,
            (username, password),
        )
        user = cur.fetchone()

    if user is None:
        # Same message whether the username or the password was wrong,
        # so attackers can't tell which usernames exist.
        return jsonify(error="Incorrect username or password."), 401

    session.clear()                      # drop any old session data first
    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    return jsonify(username=user["username"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    """The page calls this on load to find out whether to show login or table."""
    if "user_id" not in session:
        return jsonify(error="Not signed in."), 401
    return jsonify(username=session["username"])


# ---------------------------------------------------------------------------
# Employees (all routes need a signed-in user)
# ---------------------------------------------------------------------------

@app.get("/api/employees")
@login_required
def list_employees():
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT employee_id, name, surname, dob, gender, salary, designation
            FROM employees
            ORDER BY employee_id
            """
        )
        rows = cur.fetchall()
    return jsonify([row_to_json(r) for r in rows])


@app.post("/api/employees")
@login_required
def add_employee():
    rec, error = clean_employee(request.get_json(silent=True))
    if error:
        return jsonify(error=error), 400

    with db_cursor() as cur:
        # RETURNING hands back the new row, including its generated employee_id
        cur.execute(
            """
            INSERT INTO employees (name, surname, dob, gender, salary, designation)
            VALUES (%(name)s, %(surname)s, %(dob)s, %(gender)s, %(salary)s, %(designation)s)
            RETURNING employee_id, name, surname, dob, gender, salary, designation
            """,
            rec,
        )
        row = cur.fetchone()
    return jsonify(row_to_json(row)), 201


@app.put("/api/employees/<int:employee_id>")
@login_required
def edit_employee(employee_id):
    rec, error = clean_employee(request.get_json(silent=True))
    if error:
        return jsonify(error=error), 400

    with db_cursor() as cur:
        cur.execute(
            """
            UPDATE employees
            SET name = %(name)s, surname = %(surname)s, dob = %(dob)s,
                gender = %(gender)s, salary = %(salary)s, designation = %(designation)s
            WHERE employee_id = %(employee_id)s
            RETURNING employee_id, name, surname, dob, gender, salary, designation
            """,
            {**rec, "employee_id": employee_id},
        )
        row = cur.fetchone()

    if row is None:                       # no row had that id
        return jsonify(error="Employee not found."), 404
    return jsonify(row_to_json(row))


@app.delete("/api/employees/<int:employee_id>")
@login_required
def delete_employee(employee_id):
    with db_cursor() as cur:
        cur.execute("DELETE FROM employees WHERE employee_id = %s", (employee_id,))
        deleted = cur.rowcount            # how many rows were removed (0 or 1)

    if deleted == 0:
        return jsonify(error="Employee not found."), 404
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@app.errorhandler(psycopg2.Error)
def database_error(err):
    """Log the real database error, but show the user a generic message."""
    app.logger.exception("Database error")
    return jsonify(error="Database error. Please try again."), 500


if __name__ == "__main__":
    # debug=True auto-reloads on changes. Turn it OFF in production and use a
    # real server such as gunicorn:  gunicorn -w 4 app:app
    app.run(host="127.0.0.1", port=5000, debug=True)
