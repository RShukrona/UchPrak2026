import hmac
import logging
import os
from datetime import date, datetime
from functools import wraps

import psycopg2
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import db

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "change-this-local-secret"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@sk-dergava.ru").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
EMPLOYEE_SECRET_CODE = os.getenv("EMPLOYEE_SECRET_CODE", "")
STATUS_NAMES = ["Новая", "Принята", "В работе", "Ожидание запчастей", "Готова", "Закрыта", "Отменена"]
CLOSED_STATUSES = {"Закрыта", "Отменена"}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Сначала войдите в систему.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def current_user():
    if not session.get("user_id"):
        return None
    return {
        "id": session["user_id"], "name": session.get("full_name"),
        "email": session.get("email"), "role": session.get("role")
    }


def get_client_id():
    if session.get("role") == "client":
        return session.get("user_id")
    return None


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "now": datetime.now()}


@app.get("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.get("/health")
def health():
    try:
        db.fetch_one("SELECT 1 AS ok")
        return {"status": "ok", "database": "connected"}
    except psycopg2.Error:
        app.logger.exception("Database health check failed")
        return {"status": "error", "database": "unavailable"}, 503


def verify_and_upgrade_password(record, password, table, row_id):
    stored = record.get("password") or ""
    valid = False
    if stored.startswith(("pbkdf2:", "scrypt:")):
        try:
            valid = check_password_hash(stored, password)
        except (ValueError, TypeError):
            valid = False
    else:
        # One-time upgrade for demo records created with plaintext passwords.
        valid = hmac.compare_digest(stored, password)
        if valid:
            db.execute(
                f"UPDATE {table} SET password = %s WHERE id = %s",
                (generate_password_hash(password), row_id),
            )
    return valid


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        try:
            user = db.fetch_one(
                """SELECT id, name AS full_name, email, phone, password, 'client' AS role
                   FROM clients WHERE LOWER(email) = %s""", (email,)
            )
            table = "clients"
            if not user:
                user = db.fetch_one(
                    """SELECT id, full_name, email, phone, password, 'employee' AS role
                       FROM employees WHERE LOWER(email) = %s""", (email,)
                )
                table = "employees"

            if user and verify_and_upgrade_password(user, password, table, user["id"]):
                session.clear()
                session.update(user_id=user["id"], full_name=user["full_name"],
                               email=user["email"], role=user["role"])
                flash("Вы успешно вошли в систему.", "success")
                return redirect(url_for("dashboard"))

            if (not user and email == ADMIN_EMAIL and ADMIN_PASSWORD
                    and hmac.compare_digest(password, ADMIN_PASSWORD)):
                session.clear()
                session.update(user_id=999999, full_name="Администратор СК ДЕРЖАВА",
                               email=ADMIN_EMAIL, role="admin")
                flash("Вы вошли как администратор.", "success")
                return redirect(url_for("dashboard"))
        except psycopg2.Error:
            app.logger.exception("Login database error")
            flash("Не удалось подключиться к базе данных. Проверьте настройки .env.", "error")
            return render_template("login.html"), 503
        flash("Неверный email или пароль.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        role = request.form.get("role", "client")
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("secret_code", "")
        if len(name) < 2 or "@" not in email or len(password) < 8:
            flash("Проверьте имя, email и пароль (не менее 8 символов).", "error")
            return render_template("register.html")
        if role == "employee":
            if not EMPLOYEE_SECRET_CODE or not hmac.compare_digest(code, EMPLOYEE_SECRET_CODE):
                flash("Неверный код регистрации сотрудника.", "error")
                return render_template("register.html")
            db.execute(
                """INSERT INTO employees (full_name, position, phone, email, password, specialization)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (name, request.form.get("position", "Инженер"), phone, email,
                 generate_password_hash(password), request.form.get("specialization", "")),
            )
        elif role == "client":
            db.execute(
                """INSERT INTO clients (name, contact_person, email, phone, password, address, registration_date)
                   VALUES (%s, %s, %s, %s, %s, %s, CURRENT_DATE)""",
                (name, request.form.get("contact_person", ""), email, phone,
                 generate_password_hash(password), request.form.get("address", "")),
            )
        else:
            flash("Регистрация администратора через эту форму недоступна.", "warning")
            return render_template("register.html")
        flash("Регистрация завершена. Теперь войдите в систему.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    role = session["role"]
    if role == "admin":
        stats = db.fetch_one(
            """SELECT (SELECT COUNT(*) FROM clients) AS clients_count,
                      (SELECT COUNT(*) FROM employees) AS employees_count,
                      (SELECT COUNT(*) FROM equipment) AS equipment_count,
                      (SELECT COUNT(*) FROM requests) AS requests_count,
                      (SELECT COUNT(*) FROM requests r JOIN statuses s ON s.id=r.status_id
                       WHERE s.name NOT IN ('Закрыта','Отменена')) AS active_count"""
        )
        rows = db.fetch_all(
            """SELECT r.id, r.request_number, r.creation_date, c.name AS client_name,
                      e.model_name, s.name AS status_name, emp.full_name AS employee_name
               FROM requests r JOIN clients c ON c.id=r.client_id
               JOIN equipment e ON e.id=r.equipment_id JOIN statuses s ON s.id=r.status_id
               LEFT JOIN employees emp ON emp.id=r.employee_id
               ORDER BY r.creation_date DESC, r.id DESC LIMIT 12"""
        )
    elif role == "employee":
        stats = db.fetch_one(
            """SELECT COUNT(*) AS requests_count,
                      COUNT(*) FILTER (WHERE s.name='Новая') AS new_count,
                      COUNT(*) FILTER (WHERE s.name='В работе') AS active_count
               FROM requests r JOIN statuses s ON s.id=r.status_id
               WHERE r.employee_id=%s OR (r.employee_id IS NULL AND s.name='Новая')""",
            (session["user_id"],)
        )
        rows = db.fetch_all(
            """SELECT r.id, r.request_number, r.creation_date, c.name AS client_name,
                      e.model_name, s.name AS status_name, emp.full_name AS employee_name
               FROM requests r JOIN clients c ON c.id=r.client_id
               JOIN equipment e ON e.id=r.equipment_id JOIN statuses s ON s.id=r.status_id
               LEFT JOIN employees emp ON emp.id=r.employee_id
               WHERE r.employee_id=%s OR (r.employee_id IS NULL AND s.name='Новая')
               ORDER BY r.creation_date DESC, r.id DESC LIMIT 30""",
            (session["user_id"],)
        )
    else:
        stats = db.fetch_one(
            """SELECT (SELECT COUNT(*) FROM equipment WHERE client_id=%s) AS equipment_count,
                      (SELECT COUNT(*) FROM requests WHERE client_id=%s) AS requests_count""",
            (session["user_id"], session["user_id"])
        )
        rows = db.fetch_all(
            """SELECT r.id, r.request_number, r.creation_date, c.name AS client_name,
                      e.model_name, s.name AS status_name, emp.full_name AS employee_name
               FROM requests r JOIN clients c ON c.id=r.client_id
               JOIN equipment e ON e.id=r.equipment_id JOIN statuses s ON s.id=r.status_id
               LEFT JOIN employees emp ON emp.id=r.employee_id
               WHERE r.client_id=%s ORDER BY r.creation_date DESC, r.id DESC LIMIT 20""",
            (session["user_id"],)
        )
    return render_template("dashboard.html", stats=stats, rows=rows, role=role)


@app.get("/profile")
@login_required
def profile():
    if session["role"] == "admin":
        data = {"name": session["full_name"], "email": session["email"]}
    elif session["role"] == "client":
        data = db.fetch_one(
            """SELECT name, contact_person, email, phone, address, registration_date
               FROM clients WHERE id=%s""", (session["user_id"],)
        )
    else:
        data = db.fetch_one(
            """SELECT full_name AS name, position, email, phone, specialization
               FROM employees WHERE id=%s""", (session["user_id"],)
        )
    return render_template("profile.html", profile=data or {})


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if session["role"] == "admin":
        flash("Профиль администратора задаётся в локальном файле .env.", "info")
        return redirect(url_for("profile"))
    if session["role"] == "client":
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            contact = request.form.get("contact_person", "").strip()
            phone = request.form.get("phone", "").strip()
            email = request.form.get("email", "").strip().lower()
            address = request.form.get("address", "").strip()
            db.execute("UPDATE clients SET name=%s,contact_person=%s,phone=%s,email=%s,address=%s WHERE id=%s",
                       (name, contact, phone, email, address, session["user_id"]))
        else:
            data = db.fetch_one("SELECT name,contact_person,phone,email,address FROM clients WHERE id=%s",
                                (session["user_id"],))
            return render_template("profile_edit.html", profile=data, role="client")
        session["full_name"], session["email"] = name, email
    else:
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            position = request.form.get("position", "").strip()
            phone = request.form.get("phone", "").strip()
            email = request.form.get("email", "").strip().lower()
            specialization = request.form.get("specialization", "").strip()
            db.execute("UPDATE employees SET full_name=%s,position=%s,phone=%s,email=%s,specialization=%s WHERE id=%s",
                       (name, position, phone, email, specialization, session["user_id"]))
        else:
            data = db.fetch_one("SELECT full_name,position,phone,email,specialization FROM employees WHERE id=%s",
                                (session["user_id"],))
            return render_template("profile_edit.html", profile=data, role="employee")
        session["full_name"], session["email"] = name, email
    flash("Профиль обновлён.", "success")
    return redirect(url_for("profile"))


@app.get("/equipment")
@login_required
def equipment_list():
    if session["role"] == "client":
        rows = db.fetch_all(
            """SELECT e.*, c.name AS client_name,
                      (e.warranty_until >= CURRENT_DATE) AS warranty_active
               FROM equipment e JOIN clients c ON c.id=e.client_id
               WHERE e.client_id=%s ORDER BY e.id DESC""", (session["user_id"],)
        )
    else:
        rows = db.fetch_all(
            """SELECT e.*, c.name AS client_name,
                      (e.warranty_until >= CURRENT_DATE) AS warranty_active
               FROM equipment e JOIN clients c ON c.id=e.client_id ORDER BY e.id DESC"""
        )
    return render_template("equipment.html", rows=rows, can_edit=session["role"] in {"admin", "employee"})


@app.route("/equipment/add", methods=["GET", "POST"])
@roles_required("admin", "employee")
def equipment_add():
    clients = db.fetch_all("SELECT id,name FROM clients ORDER BY name")
    if request.method == "POST":
        db.execute(
            """INSERT INTO equipment
               (client_id,model_name,equipment_type,serial_number,production_year,warranty_number,warranty_until,note)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (request.form.get("client_id"), request.form.get("model_name"),
             request.form.get("equipment_type"), request.form.get("serial_number"),
             request.form.get("production_year") or None, request.form.get("warranty_number") or None,
             request.form.get("warranty_until") or None, request.form.get("note") or None)
        )
        flash("Оборудование добавлено.", "success")
        return redirect(url_for("equipment_list"))
    return render_template("equipment_form.html", clients=clients, item=None)


@app.route("/equipment/<int:item_id>/edit", methods=["GET", "POST"])
@roles_required("admin", "employee")
def equipment_edit(item_id):
    item = db.fetch_one("SELECT * FROM equipment WHERE id=%s", (item_id,))
    if not item:
        abort(404)
    clients = db.fetch_all("SELECT id,name FROM clients ORDER BY name")
    if request.method == "POST":
        db.execute(
            """UPDATE equipment SET client_id=%s,model_name=%s,equipment_type=%s,serial_number=%s,
               production_year=%s,warranty_number=%s,warranty_until=%s,note=%s WHERE id=%s""",
            (request.form.get("client_id"), request.form.get("model_name"),
             request.form.get("equipment_type"), request.form.get("serial_number"),
             request.form.get("production_year") or None, request.form.get("warranty_number") or None,
             request.form.get("warranty_until") or None, request.form.get("note") or None, item_id)
        )
        flash("Данные оборудования обновлены.", "success")
        return redirect(url_for("equipment_list"))
    return render_template("equipment_form.html", clients=clients, item=item)


@app.post("/equipment/<int:item_id>/delete")
@roles_required("admin")
def equipment_delete(item_id):
    db.execute("DELETE FROM equipment WHERE id=%s", (item_id,))
    flash("Оборудование удалено, если на него не ссылаются заявки.", "success")
    return redirect(url_for("equipment_list"))


@app.get("/requests")
@login_required
def requests_list():
    where, params = "", ()
    if session["role"] == "client":
        where, params = "WHERE r.client_id=%s", (session["user_id"],)
    elif session["role"] == "employee":
        where, params = "WHERE r.employee_id=%s OR (r.employee_id IS NULL AND s.name='Новая')", (session["user_id"],)
    rows = db.fetch_all(
        f"""SELECT r.id,r.request_number,r.creation_date,r.problem_description,
                   c.name AS client_name,e.model_name,s.name AS status_name,emp.full_name AS employee_name,
                   r.final_cost
            FROM requests r JOIN clients c ON c.id=r.client_id
            JOIN equipment e ON e.id=r.equipment_id JOIN statuses s ON s.id=r.status_id
            LEFT JOIN employees emp ON emp.id=r.employee_id
            {where} ORDER BY r.creation_date DESC,r.id DESC""", params
    )
    return render_template("requests.html", rows=rows)


@app.route("/requests/new", methods=["GET", "POST"])
@roles_required("client")
def request_new():
    equipment = db.fetch_all("SELECT id,model_name,serial_number,warranty_until FROM equipment WHERE client_id=%s ORDER BY model_name",
                             (session["user_id"],))
    if request.method == "POST":
        equipment_id = request.form.get("equipment_id")
        description = request.form.get("problem_description", "").strip()
        if len(description) < 10:
            flash("Опишите неисправность подробнее (не менее 10 символов).", "error")
        else:
            item = db.fetch_one("SELECT id,warranty_until FROM equipment WHERE id=%s AND client_id=%s",
                                (equipment_id, session["user_id"]))
            status = db.fetch_one("SELECT id FROM statuses WHERE name='Новая'")
            if not item or not status:
                flash("Оборудование или начальный статус не найдены.", "error")
            else:
                warranty = bool(item["warranty_until"] and item["warranty_until"] >= date.today())
                number = "REQ-" + datetime.now().strftime("%Y%m%d%H%M%S%f")
                db.execute(
                    """INSERT INTO requests
                       (request_number,client_id,equipment_id,status_id,problem_description,is_warranty)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (number, session["user_id"], item["id"], status["id"], description, warranty)
                )
                flash("Заявка успешно создана.", "success")
                return redirect(url_for("requests_list"))
    return render_template("request_new.html", equipment=equipment)


@app.get("/requests/<int:item_id>")
@login_required
def request_detail(item_id):
    item = db.fetch_one(
        """SELECT r.*,c.name AS client_name,e.model_name,e.equipment_type,e.serial_number,
                  s.name AS status_name,emp.full_name AS employee_name
           FROM requests r JOIN clients c ON c.id=r.client_id
           JOIN equipment e ON e.id=r.equipment_id JOIN statuses s ON s.id=r.status_id
           LEFT JOIN employees emp ON emp.id=r.employee_id WHERE r.id=%s""", (item_id,)
    )
    if not item:
        abort(404)
    if session["role"] == "client" and item["client_id"] != session["user_id"]:
        abort(403)
    if session["role"] == "employee" and item["employee_id"] not in (None, session["user_id"]):
        abort(403)
    employees = db.fetch_all("SELECT id,full_name FROM employees ORDER BY full_name") if session["role"] == "admin" else []
    statuses = db.fetch_all("SELECT id,name FROM statuses ORDER BY id") if session["role"] in {"admin", "employee"} else []
    return render_template("request_detail.html", item=item, employees=employees, statuses=statuses,
                           can_manage=session["role"] in {"admin", "employee"})


@app.post("/requests/<int:item_id>/update")
@roles_required("admin", "employee")
def request_update(item_id):
    item = db.fetch_one("SELECT * FROM requests WHERE id=%s", (item_id,))
    if not item:
        abort(404)
    if session["role"] == "employee" and item["employee_id"] not in (None, session["user_id"]):
        abort(403)
    status_id = request.form.get("status_id")
    employee_id = request.form.get("employee_id") if session["role"] == "admin" else session["user_id"]
    if not employee_id:
        employee_id = None
    labor = float(request.form.get("labor_cost") or 0)
    parts = float(request.form.get("parts_cost") or 0)
    if labor < 0 or parts < 0:
        flash("Стоимость не может быть отрицательной.", "error")
        return redirect(url_for("request_detail", item_id=item_id))
    warranty = bool(item["is_warranty"])
    total = 0 if warranty else labor + parts
    status = db.fetch_one("SELECT name FROM statuses WHERE id=%s", (status_id,))
    closing = date.today() if status and status["name"] in CLOSED_STATUSES else None
    db.execute(
        """UPDATE requests SET status_id=%s,employee_id=%s,labor_cost=%s,parts_cost=%s,
           final_cost=%s,closing_date=%s WHERE id=%s""",
        (status_id, employee_id, labor, parts, total, closing, item_id)
    )
    flash("Заявка обновлена.", "success")
    return redirect(url_for("request_detail", item_id=item_id))


@app.post("/requests/<int:item_id>/cancel")
@roles_required("client")
def request_cancel(item_id):
    item = db.fetch_one(
        """SELECT r.id,s.name AS status_name FROM requests r
           JOIN statuses s ON s.id=r.status_id WHERE r.id=%s AND r.client_id=%s""",
        (item_id, session["user_id"])
    )
    if not item:
        abort(404)
    if item["status_name"] != "Новая":
        flash("Можно отменить только новую заявку.", "warning")
    else:
        status = db.fetch_one("SELECT id FROM statuses WHERE name='Отменена'")
        db.execute("UPDATE requests SET status_id=%s,closing_date=CURRENT_DATE WHERE id=%s",
                   (status["id"], item_id))
        flash("Заявка отменена.", "success")
    return redirect(url_for("requests_list"))


@app.get("/clients")
@roles_required("admin", "employee")
def clients_list():
    rows = db.fetch_all(
        """SELECT c.id,c.name,c.contact_person,c.email,c.phone,COUNT(e.id) AS equipment_count
           FROM clients c LEFT JOIN equipment e ON e.client_id=c.id
           GROUP BY c.id ORDER BY c.name"""
    )
    return render_template("clients.html", rows=rows)


@app.get("/employees")
@roles_required("admin")
def employees_list():
    rows = db.fetch_all(
        """SELECT e.id,e.full_name,e.position,e.phone,e.email,e.specialization,COUNT(r.id) AS requests_count
           FROM employees e LEFT JOIN requests r ON r.employee_id=e.id
           GROUP BY e.id ORDER BY e.full_name"""
    )
    return render_template("employees.html", rows=rows)


@app.get("/statuses")
@roles_required("admin")
def statuses_list():
    rows = db.fetch_all("SELECT id,name,description FROM statuses ORDER BY id")
    return render_template("statuses.html", rows=rows)


@app.get("/reports")
@roles_required("admin")
def reports():
    rows = db.fetch_all(
        """SELECT s.name AS status_name,COUNT(r.id) AS requests_count
           FROM statuses s LEFT JOIN requests r ON r.status_id=s.id
           GROUP BY s.id,s.name ORDER BY requests_count DESC"""
    )
    totals = db.fetch_one(
        "SELECT COALESCE(SUM(final_cost),0) AS revenue,COUNT(*) AS total FROM requests"
    )
    return render_template("reports.html", rows=rows, totals=totals)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Недостаточно прав для просмотра этой страницы."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Запрашиваемая страница не найдена."), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Flask error: %s", error)
    return render_template("error.html", code=500, message="Внутренняя ошибка. Подробности доступны в терминале."), 500


if __name__ == "__main__":
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"),
            port=int(os.getenv("FLASK_PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG", "0") == "1")
