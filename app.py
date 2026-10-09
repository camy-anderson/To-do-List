import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


# =========================================================
# Environment
# =========================================================

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. "
        "Add SECRET_KEY to the .env file before starting the application."
    )

PORT = int(os.getenv("PORT", "5000"))


# =========================================================
# Flask application
# =========================================================

app = Flask(__name__)

# Single application secret.
# Flask uses this to sign the session cookie.
app.config["SECRET_KEY"] = SECRET_KEY


# =========================================================
# Database
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")


def get_db():
    """
    Get the SQLite connection for the current request.
    """

    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """
    Close the database connection after each request.
    """

    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    """
    Create the database schema.

    No users or tasks are pre-seeded.
    """

    db = sqlite3.connect(DATABASE)

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            task_date TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    db.commit()
    db.close()


# =========================================================
# Authentication
# =========================================================

def login_required(view):
    """
    Require an authenticated user.
    """

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, created_at
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],),
        ).fetchone()

        if user is None:
            session.clear()
            flash(
                "Your session is no longer valid. Please log in again.",
                "error",
            )
            return redirect(url_for("login"))

        g.user = user

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    """
    Require an authenticated user whose role in the
    Flask session is 'admin'.

    The database does not contain a role column.
    """

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, created_at
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],),
        ).fetchone()

        if user is None:
            session.clear()
            flash(
                "Your session is no longer valid. Please log in again.",
                "error",
            )
            return redirect(url_for("login"))

        g.user = user

        # Authorization is based entirely on the role
        # stored in the Flask session cookie.
        if session.get("role") != "admin":
            flash(
                "You do not have permission to access that page.",
                "error",
            )
            return redirect(url_for("dashboard"))

        return view(*args, **kwargs)

    return wrapped_view


# =========================================================
# Template context
# =========================================================

@app.context_processor
def inject_current_user():
    """
    Make the authenticated user available to templates.
    """

    return {
        "current_user": getattr(g, "user", None)
    }


# =========================================================
# Index
# =========================================================

@app.route("/")
def index():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================================================
# Register
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash(
                "Username and password are required.",
                "error",
            )
            return render_template("register.html")

        if len(username) < 3:
            flash(
                "Username must be at least 3 characters long.",
                "error",
            )
            return render_template("register.html")

        if len(password) < 6:
            flash(
                "Password must be at least 6 characters long.",
                "error",
            )
            return render_template("register.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error",
            )
            return render_template("register.html")

        db = get_db()

        existing_user = db.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if existing_user:
            flash(
                "That username is already registered.",
                "error",
            )
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        cursor = db.execute(
            """
            INSERT INTO users (
                username,
                password,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                password_hash,
                datetime.utcnow().isoformat(),
            ),
        )

        db.commit()

        # Every user created through normal registration
        # receives the normal "user" role in the session.
        session.clear()

        session["user_id"] = cursor.lastrowid
        session["role"] = "user"

        flash(
            "Account created successfully.",
            "success",
        )

        return redirect(url_for("dashboard"))

    return render_template("register.html")


# =========================================================
# Login
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash(
                "Username and password are required.",
                "error",
            )
            return render_template("login.html")

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, password, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user is None:
            flash(
                "Invalid username or password.",
                "error",
            )
            return render_template("login.html")

        if not check_password_hash(
            user["password"],
            password,
        ):
            flash(
                "Invalid username or password.",
                "error",
            )
            return render_template("login.html")

        # Start a fresh Flask session after successful login.
        session.clear()

        session["user_id"] = user["id"]

        # Normal application login always creates a
        # normal-user session.
        session["role"] = "user"

        flash(
            "Welcome back.",
            "success",
        )

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# =========================================================
# Logout
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(url_for("login"))


# =========================================================
# Dashboard
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    today = datetime.now().date()
    week_end = today + timedelta(days=6)

    today_string = today.isoformat()
    week_end_string = week_end.isoformat()

    db = get_db()

    tasks = db.execute(
        """
        SELECT
            id,
            title,
            description,
            task_date,
            completed,
            created_at
        FROM tasks
        WHERE user_id = ?
          AND task_date BETWEEN ? AND ?
        ORDER BY
            task_date ASC,
            completed ASC,
            id DESC
        """,
        (
            g.user["id"],
            today_string,
            week_end_string,
        ),
    ).fetchall()

    today_tasks = [
        task
        for task in tasks
        if task["task_date"] == today_string
    ]

    upcoming_tasks = [
        task
        for task in tasks
        if task["task_date"] != today_string
    ]

    completed_today = sum(
        1
        for task in today_tasks
        if task["completed"]
    )

    return render_template(
        "dashboard.html",
        today=today_string,
        week_end=week_end_string,
        today_tasks=today_tasks,
        upcoming_tasks=upcoming_tasks,
        completed_today=completed_today,
        total_tasks=len(tasks),
    )


# =========================================================
# Create task
# =========================================================

@app.route("/tasks/create", methods=["POST"])
@login_required
def create_task():

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    task_date = request.form.get("task_date", "").strip()

    if not title:
        flash(
            "Task title is required.",
            "error",
        )
        return redirect(url_for("dashboard"))

    if not task_date:
        flash(
            "Task date is required.",
            "error",
        )
        return redirect(url_for("dashboard"))

    today = datetime.now().date()
    week_end = today + timedelta(days=6)

    try:
        selected_date = datetime.strptime(
            task_date,
            "%Y-%m-%d",
        ).date()
    except ValueError:
        flash(
            "Invalid task date.",
            "error",
        )
        return redirect(url_for("dashboard"))

    if selected_date < today or selected_date > week_end:
        flash(
            "Tasks can only be scheduled for today or the next six days.",
            "error",
        )
        return redirect(url_for("dashboard"))

    db = get_db()

    db.execute(
        """
        INSERT INTO tasks (
            user_id,
            title,
            description,
            task_date,
            completed,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            g.user["id"],
            title,
            description,
            selected_date.isoformat(),
            0,
            datetime.utcnow().isoformat(),
        ),
    )

    db.commit()

    flash(
        "Task added successfully.",
        "success",
    )

    return redirect(url_for("dashboard"))


# =========================================================
# Toggle task
# =========================================================

@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_task(task_id):

    db = get_db()

    task = db.execute(
        """
        SELECT id, completed
        FROM tasks
        WHERE id = ?
          AND user_id = ?
        """,
        (
            task_id,
            g.user["id"],
        ),
    ).fetchone()

    if task is None:
        flash(
            "Task not found.",
            "error",
        )
        return redirect(url_for("dashboard"))

    new_completed_value = (
        0 if task["completed"] else 1
    )

    db.execute(
        """
        UPDATE tasks
        SET completed = ?
        WHERE id = ?
          AND user_id = ?
        """,
        (
            new_completed_value,
            task_id,
            g.user["id"],
        ),
    )

    db.commit()

    return redirect(url_for("dashboard"))


# =========================================================
# Delete task
# =========================================================

@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):

    db = get_db()

    task = db.execute(
        """
        SELECT id
        FROM tasks
        WHERE id = ?
          AND user_id = ?
        """,
        (
            task_id,
            g.user["id"],
        ),
    ).fetchone()

    if task is None:
        flash(
            "Task not found.",
            "error",
        )
        return redirect(url_for("dashboard"))

    db.execute(
        """
        DELETE FROM tasks
        WHERE id = ?
          AND user_id = ?
        """,
        (
            task_id,
            g.user["id"],
        ),
    )

    db.commit()

    flash(
        "Task deleted.",
        "success",
    )

    return redirect(url_for("dashboard"))


# =========================================================
# Admin
# =========================================================

@app.route("/admin")
@admin_required
def admin():

    secrets = [
        os.getenv("ADMIN_SECRET_1", ""),
        os.getenv("ADMIN_SECRET_2", ""),
        os.getenv("ADMIN_SECRET_3", ""),
    ]

    return render_template(
        "admin.html",
        secrets=secrets,
    )


# =========================================================
# Health check
# =========================================================

@app.route("/health")
def health():

    return {
        "status": "ok"
    }


# =========================================================
# Application startup
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
    )
