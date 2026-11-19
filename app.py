import os
from datetime import date
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash

load_dotenv()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev-only-change-this-key"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)
CSRFProtect(app)


def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "derzhava"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        cursor_factory=RealDictCursor,
    )


def query_one(sql, params=()):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def query_all(sql, params=()):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def execute(sql, params=()):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone() if cur.description else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*allowed):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in allowed:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.get("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_one(
            """SELECT u.user_id, u.username, u.password_hash, u.role_id,
                      u.client_id, u.employee_id, u.is_active, r.role_name
               FROM users u JOIN roles r ON r.role_id = u.role_id
               WHERE u.username = %s""", (username,)
        )
        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(
                user_id=user["user_id"], username=user["username"],
                role=user["role_name"], role_id=user["role_id"],
                client_id=user["client_id"], employee_id=user["employee_id"],
            )
            return redirect(url_for("dashboard"))
        flash("Неверный логин или пароль либо учётная запись отключена.", "error")
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    role = session["role"]
    if role == "admin":
        stats = query_one(
            """SELECT
                 (SELECT COUNT(*) FROM clients) AS clients_count,
                 (SELECT COUNT(*) FROM equipment) AS equipment_count,
                 (SELECT COUNT(*) FROM repair_requests) AS requests_count,
                 (SELECT COUNT(*) FROM repair_requests WHERE request_status IN ('new','accepted','diagnostics','in_repair')) AS active_count"""
        )
        requests = query_all(
            """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                      c.company_name, e.equipment_name
               FROM repair_requests rr JOIN clients c ON c.client_id=rr.client_id
               JOIN equipment e ON e.equipment_id=rr.equipment_id
               ORDER BY rr.request_date DESC, rr.request_id DESC LIMIT 30"""
        )
        return render_template("dashboard.html", stats=stats, requests=requests, mode="admin")
    if role == "engineer":
        requests = query_all(
            """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                      c.company_name, e.equipment_name
               FROM repair_requests rr JOIN clients c ON c.client_id=rr.client_id
               JOIN equipment e ON e.equipment_id=rr.equipment_id
               WHERE rr.assigned_employee_id = %s
               ORDER BY rr.request_date DESC, rr.request_id DESC""",
            (session.get("employee_id"),)
        )
        return render_template("dashboard.html", requests=requests, mode="engineer")
    if role == "client":
        equipment = query_all(
            """SELECT equipment_id, equipment_name, equipment_type, manufacturer,
                      model, serial_number, warranty_until,
                      (warranty_until >= CURRENT_DATE) AS warranty_active
               FROM equipment WHERE client_id=%s ORDER BY equipment_id""",
            (session.get("client_id"),)
        )
        requests = query_all(
            """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                      e.equipment_name
               FROM repair_requests rr JOIN equipment e ON e.equipment_id=rr.equipment_id
               WHERE rr.client_id=%s ORDER BY rr.request_date DESC, rr.request_id DESC""",
            (session.get("client_id"),)
        )
        return render_template("dashboard.html", equipment=equipment, requests=requests, mode="client")
    abort(403)


@app.route("/requests/new", methods=["GET", "POST"])
@roles_required("client")
def new_request():
    equipment = query_all(
        "SELECT equipment_id, equipment_name, serial_number FROM equipment WHERE client_id=%s ORDER BY equipment_name",
        (session["client_id"],)
    )
    if request.method == "POST":
        try:
            equipment_id = int(request.form.get("equipment_id", ""))
        except (TypeError, ValueError):
            flash("Выберите оборудование.", "error")
            return render_template("request_new.html", equipment=equipment)
        description = request.form.get("problem_description", "").strip()
        priority = request.form.get("priority", "medium")
        if not description or len(description) < 10:
            flash("Опишите неисправность подробнее (не менее 10 символов).", "error")
        elif priority not in {"low", "medium", "high", "urgent"}:
            flash("Некорректный приоритет.", "error")
        else:
            with get_db() as conn, conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO repair_requests
                       (client_id, equipment_id, request_date, problem_description, priority, request_status)
                       SELECT %s, equipment_id, CURRENT_DATE, %s, %s, 'new'
                       FROM equipment WHERE equipment_id=%s AND client_id=%s
                       RETURNING request_id""",
                    (session["client_id"], description, priority, equipment_id, session["client_id"])
                )
                created = cur.fetchone()
                if created:
                    cur.execute(
                        """INSERT INTO request_status_history
                           (request_id, old_status, new_status, changed_at, changed_by)
                           VALUES (%s, NULL, 'new', CURRENT_TIMESTAMP, %s)""",
                        (created["request_id"], session["user_id"])
                    )
                    flash(f"Заявка №{created['request_id']} создана.", "success")
                    return redirect(url_for("dashboard"))
            flash("Оборудование не найдено или не принадлежит вашей организации.", "error")
    return render_template("request_new.html", equipment=equipment)


@app.get("/requests/<int:request_id>")
@login_required
def request_detail(request_id):
    item = query_one(
        """SELECT rr.*, c.company_name, e.equipment_name, e.serial_number,
                  emp.full_name AS engineer_name
           FROM repair_requests rr JOIN clients c ON c.client_id=rr.client_id
           JOIN equipment e ON e.equipment_id=rr.equipment_id
           LEFT JOIN employees emp ON emp.employee_id=rr.assigned_employee_id
           WHERE rr.request_id=%s""", (request_id,)
    )
    if not item:
        abort(404)
    role = session["role"]
    if role == "client" and item["client_id"] != session.get("client_id"):
        abort(403)
    if role == "engineer" and item["assigned_employee_id"] != session.get("employee_id"):
        abort(403)
    history = query_all(
        """SELECT h.old_status, h.new_status, h.changed_at, u.username
           FROM request_status_history h LEFT JOIN users u ON u.user_id=h.changed_by
           WHERE h.request_id=%s ORDER BY h.changed_at, h.history_id""", (request_id,)
    )
    repair = query_one("SELECT * FROM repairs WHERE request_id=%s", (request_id,))
    return render_template("request_detail.html", item=item, history=history, repair=repair,
                           can_manage=(role in {"admin", "engineer"}))


@app.post("/requests/<int:request_id>/status")
@roles_required("admin", "engineer")
def update_status(request_id):
    new_status = request.form.get("request_status", "")
    allowed = {"accepted", "diagnostics", "in_repair", "completed", "rejected"}
    if new_status not in allowed:
        abort(400)
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM repair_requests WHERE request_id=%s FOR UPDATE", (request_id,))
        item = cur.fetchone()
        if not item:
            abort(404)
        if session["role"] == "engineer" and item["assigned_employee_id"] != session.get("employee_id"):
            abort(403)
        old_status = item["request_status"]
        employee_id = item["assigned_employee_id"] or session.get("employee_id")
        if new_status in {"diagnostics", "in_repair", "completed"} and not employee_id:
            flash("Для этой заявки сначала назначьте инженера.", "error")
            return redirect(url_for("request_detail", request_id=request_id))
        completion_date = date.today() if new_status in {"completed", "rejected"} else None
        cur.execute(
            """UPDATE repair_requests SET request_status=%s,
               assigned_employee_id=COALESCE(assigned_employee_id,%s),
               completion_date=%s, updated_at=CURRENT_TIMESTAMP WHERE request_id=%s""",
            (new_status, employee_id, completion_date, request_id)
        )
        if old_status != new_status:
            cur.execute(
                """INSERT INTO request_status_history
                   (request_id, old_status, new_status, changed_at, changed_by)
                   VALUES (%s,%s,%s,CURRENT_TIMESTAMP,%s)""",
                (request_id, old_status, new_status, session["user_id"])
            )
        if new_status in {"diagnostics", "in_repair", "completed"}:
            cur.execute(
                """INSERT INTO repairs (request_id, employee_id, repair_start)
                   VALUES (%s,%s,CURRENT_TIMESTAMP)
                   ON CONFLICT (request_id) DO UPDATE SET employee_id=EXCLUDED.employee_id""",
                (request_id, employee_id)
            )
        if new_status == "completed":
            cur.execute("UPDATE repairs SET repair_end=CURRENT_TIMESTAMP WHERE request_id=%s", (request_id,))
        if new_status == "in_repair":
            cur.execute("UPDATE equipment SET equipment_status='under_repair' WHERE equipment_id=%s", (item["equipment_id"],))
        elif new_status in {"completed", "rejected"}:
            cur.execute("UPDATE equipment SET equipment_status='working' WHERE equipment_id=%s AND equipment_status='under_repair'", (item["equipment_id"],))
    flash("Статус заявки обновлён.", "success")
    return redirect(url_for("request_detail", request_id=request_id))


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Недостаточно прав для просмотра этой страницы."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Запрашиваемая страница не найдена."), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", code=500, message="Внутренняя ошибка сервера. Проверьте настройки подключения к БД."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("FLASK_PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
