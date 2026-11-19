import logging
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "local-development-key-change-before-use"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
csrf = CSRFProtect(app)

ROLE_NAMES = {1: "admin", 2: "engineer", 3: "client"}
ROLE_LABELS = {"admin": "Администратор", "engineer": "Инженер", "client": "Клиент"}
STATUS_LABELS = {
    "new": "Новая",
    "accepted": "Принята",
    "diagnostics": "Диагностика",
    "in_repair": "В ремонте",
    "completed": "Завершена",
    "rejected": "Отклонена",
}
PRIORITY_LABELS = {"low": "Низкий", "medium": "Средний", "high": "Высокий", "urgent": "Срочный"}


def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "derzhava"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        cursor_factory=RealDictCursor,
        connect_timeout=5,
    )


def query_one(sql, params=()):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def query_all(sql, params=()):
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


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


@app.context_processor
def inject_labels():
    return {"status_labels": STATUS_LABELS, "priority_labels": PRIORITY_LABELS,
            "role_labels": ROLE_LABELS}


@app.get("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.get("/health")
def health():
    try:
        query_one("SELECT 1 AS ok")
        return {"status": "ok", "database": "connected"}, 200
    except psycopg2.Error:
        app.logger.exception("Проверка подключения к PostgreSQL не пройдена")
        return {"status": "error", "database": "unavailable"}, 503


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") and request.method == "GET":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            user = query_one(
                """SELECT u.user_id, u.username, u.password_hash, u.role_id,
                          u.client_id, u.employee_id, u.is_active, r.role_name
                   FROM users u
                   LEFT JOIN roles r ON r.role_id = u.role_id
                   WHERE u.username = %s""",
                (username,),
            )
        except psycopg2.Error:
            app.logger.exception("Ошибка БД во время входа")
            flash("Не удалось обратиться к базе данных. Проверьте настройки подключения.", "error")
            return render_template("login.html"), 503

        password_valid = False
        if user and user["is_active"] and user["password_hash"]:
            try:
                password_valid = check_password_hash(user["password_hash"], password)
            except (ValueError, TypeError):
                app.logger.exception("Некорректный хеш пароля для пользователя %s", username)

        role = ROLE_NAMES.get(user["role_id"]) if user else None
        if password_valid and role:
            session.clear()
            session.update(
                user_id=user["user_id"],
                username=user["username"],
                role=role,
                role_id=user["role_id"],
                client_id=user["client_id"],
                employee_id=user["employee_id"],
            )
            flash("Вы успешно вошли в систему.", "success")
            return redirect(url_for("dashboard"))

        flash("Неверный логин или пароль либо учётная запись отключена.", "error")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("Вы вышли из системы.", "success")
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    role = session["role"]

    try:
        if role == "admin":
            stats = query_one(
                """SELECT
                     (SELECT COUNT(*) FROM clients) AS clients_count,
                     (SELECT COUNT(*) FROM equipment) AS equipment_count,
                     (SELECT COUNT(*) FROM repair_requests) AS requests_count,
                     (SELECT COUNT(*) FROM repair_requests
                      WHERE request_status IN ('new','accepted','diagnostics','in_repair')) AS active_count"""
            )
            requests = query_all(
                """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                          c.company_name, e.equipment_name, emp.full_name AS engineer_name
                   FROM repair_requests rr
                   JOIN clients c ON c.client_id = rr.client_id
                   JOIN equipment e ON e.equipment_id = rr.equipment_id
                   LEFT JOIN employees emp ON emp.employee_id = rr.assigned_employee_id
                   ORDER BY rr.request_date DESC, rr.request_id DESC LIMIT 50"""
            )
            return render_template("dashboard.html", mode="admin", stats=stats, requests=requests)

        if role == "engineer":
            requests = query_all(
                """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                          c.company_name, e.equipment_name
                   FROM repair_requests rr
                   JOIN clients c ON c.client_id = rr.client_id
                   JOIN equipment e ON e.equipment_id = rr.equipment_id
                   WHERE rr.assigned_employee_id = %s
                   ORDER BY rr.request_date DESC, rr.request_id DESC""",
                (session.get("employee_id"),),
            )
            return render_template("dashboard.html", mode="engineer", requests=requests)

        if role == "client":
            equipment = query_all(
                """SELECT equipment_id, equipment_name, equipment_type, manufacturer,
                          model, serial_number, warranty_until,
                          (warranty_until >= CURRENT_DATE) AS warranty_active
                   FROM equipment WHERE client_id = %s ORDER BY equipment_id""",
                (session.get("client_id"),),
            )
            requests = query_all(
                """SELECT rr.request_id, rr.request_date, rr.priority, rr.request_status,
                          e.equipment_name
                   FROM repair_requests rr
                   JOIN equipment e ON e.equipment_id = rr.equipment_id
                   WHERE rr.client_id = %s
                   ORDER BY rr.request_date DESC, rr.request_id DESC""",
                (session.get("client_id"),),
            )
            return render_template("dashboard.html", mode="client",
                                   equipment=equipment, requests=requests)
    except psycopg2.Error:
        app.logger.exception("Ошибка БД при формировании панели пользователя %s", session.get("username"))
        return render_template("error.html", code=500,
                               message="Не удалось загрузить данные. Проверьте структуру и содержимое базы данных."), 500

    abort(403)


@app.route("/requests/new", methods=["GET", "POST"])
@roles_required("client")
def new_request():
    equipment = query_all(
        """SELECT equipment_id, equipment_name, serial_number
           FROM equipment WHERE client_id = %s ORDER BY equipment_name""",
        (session["client_id"],),
    )

    if request.method == "POST":
        try:
            equipment_id = int(request.form.get("equipment_id", ""))
        except (TypeError, ValueError):
            flash("Выберите оборудование из списка.", "error")
            return render_template("request_new.html", equipment=equipment)

        description = request.form.get("problem_description", "").strip()
        priority = request.form.get("priority", "medium")
        if len(description) < 10:
            flash("Опишите неисправность подробнее — минимум 10 символов.", "error")
        elif priority not in PRIORITY_LABELS:
            flash("Выбран неизвестный приоритет.", "error")
        else:
            try:
                with get_db() as conn, conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO repair_requests
                           (client_id, equipment_id, request_date, problem_description, priority, request_status)
                           SELECT %s, equipment_id, CURRENT_DATE, %s, %s, 'new'
                           FROM equipment
                           WHERE equipment_id = %s AND client_id = %s
                           RETURNING request_id""",
                        (session["client_id"], description, priority,
                         equipment_id, session["client_id"]),
                    )
                    created = cur.fetchone()
                    if created:
                        cur.execute(
                            """INSERT INTO request_status_history
                               (request_id, old_status, new_status, changed_at, changed_by)
                               VALUES (%s, NULL, 'new', CURRENT_TIMESTAMP, %s)""",
                            (created["request_id"], session["user_id"]),
                        )
                        flash(f"Заявка №{created['request_id']} успешно создана.", "success")
                        return redirect(url_for("dashboard"))
                flash("Оборудование не найдено или не принадлежит вашей организации.", "error")
            except psycopg2.Error:
                app.logger.exception("Не удалось создать заявку")
                flash("Не удалось сохранить заявку. Проверьте данные базы.", "error")

    return render_template("request_new.html", equipment=equipment)


@app.get("/requests/<int:request_id>")
@login_required
def request_detail(request_id):
    item = query_one(
        """SELECT rr.*, c.company_name, e.equipment_name, e.serial_number,
                  emp.full_name AS engineer_name
           FROM repair_requests rr
           JOIN clients c ON c.client_id = rr.client_id
           JOIN equipment e ON e.equipment_id = rr.equipment_id
           LEFT JOIN employees emp ON emp.employee_id = rr.assigned_employee_id
           WHERE rr.request_id = %s""",
        (request_id,),
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
           FROM request_status_history h
           LEFT JOIN users u ON u.user_id = h.changed_by
           WHERE h.request_id = %s ORDER BY h.changed_at, h.history_id""",
        (request_id,),
    )
    repair = query_one("SELECT * FROM repairs WHERE request_id = %s", (request_id,))
    employees = query_all(
        "SELECT employee_id, full_name FROM employees WHERE is_active = TRUE ORDER BY full_name"
    ) if role == "admin" else []

    return render_template(
        "request_detail.html", item=item, history=history, repair=repair,
        employees=employees, can_manage=role in {"admin", "engineer"},
    )


@app.post("/requests/<int:request_id>/assign")
@roles_required("admin")
def assign_engineer(request_id):
    raw_employee_id = request.form.get("employee_id", "").strip()
    employee_id = None

    if raw_employee_id:
        try:
            employee_id = int(raw_employee_id)
        except ValueError:
            abort(400)
        employee = query_one(
            "SELECT employee_id FROM employees WHERE employee_id = %s AND is_active = TRUE",
            (employee_id,),
        )
        if not employee:
            flash("Выбранный сотрудник не найден или неактивен.", "error")
            return redirect(url_for("request_detail", request_id=request_id))

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE repair_requests
               SET assigned_employee_id = %s, updated_at = CURRENT_TIMESTAMP
               WHERE request_id = %s RETURNING request_id""",
            (employee_id, request_id),
        )
        if not cur.fetchone():
            abort(404)

    flash("Ответственный инженер обновлён.", "success")
    return redirect(url_for("request_detail", request_id=request_id))


@app.post("/requests/<int:request_id>/status")
@roles_required("admin", "engineer")
def update_status(request_id):
    new_status = request.form.get("request_status", "")
    allowed = {"accepted", "diagnostics", "in_repair", "completed", "rejected"}
    if new_status not in allowed:
        abort(400)

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM repair_requests WHERE request_id = %s FOR UPDATE",
            (request_id,),
        )
        item = cur.fetchone()
        if not item:
            abort(404)

        if session["role"] == "engineer" and item["assigned_employee_id"] != session.get("employee_id"):
            abort(403)

        old_status = item["request_status"]
        employee_id = item["assigned_employee_id"] or session.get("employee_id")
        if new_status in {"diagnostics", "in_repair", "completed"} and not employee_id:
            flash("Сначала назначьте инженера на эту заявку.", "error")
            return redirect(url_for("request_detail", request_id=request_id))

        completion_date = date.today() if new_status in {"completed", "rejected"} else None
        cur.execute(
            """UPDATE repair_requests
               SET request_status = %s,
                   assigned_employee_id = COALESCE(assigned_employee_id, %s),
                   completion_date = %s,
                   updated_at = CURRENT_TIMESTAMP
               WHERE request_id = %s""",
            (new_status, employee_id, completion_date, request_id),
        )

        if old_status != new_status:
            cur.execute(
                """INSERT INTO request_status_history
                   (request_id, old_status, new_status, changed_at, changed_by)
                   VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)""",
                (request_id, old_status, new_status, session["user_id"]),
            )

        if new_status in {"diagnostics", "in_repair", "completed"}:
            cur.execute(
                """INSERT INTO repairs (request_id, employee_id, repair_start)
                   VALUES (%s, %s, CURRENT_TIMESTAMP)
                   ON CONFLICT (request_id) DO UPDATE
                   SET employee_id = EXCLUDED.employee_id""",
                (request_id, employee_id),
            )
        if new_status == "completed":
            cur.execute(
                "UPDATE repairs SET repair_end = CURRENT_TIMESTAMP WHERE request_id = %s",
                (request_id,),
            )
        if new_status == "in_repair":
            cur.execute(
                "UPDATE equipment SET equipment_status = 'under_repair' WHERE equipment_id = %s",
                (item["equipment_id"],),
            )
        elif new_status in {"completed", "rejected"}:
            cur.execute(
                """UPDATE equipment SET equipment_status = 'working'
                   WHERE equipment_id = %s AND equipment_status = 'under_repair'""",
                (item["equipment_id"],),
            )

    flash("Статус заявки обновлён.", "success")
    return redirect(url_for("request_detail", request_id=request_id))


@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", code=400,
                           message="Запрос содержит некорректные данные."), 400


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403,
                           message="Недостаточно прав для просмотра этой страницы."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404,
                           message="Запрашиваемая страница не найдена."), 404


@app.errorhandler(500)
def server_error(error):
    original = getattr(error, "original_exception", None)
    if original:
        app.logger.error(
            "Необработанная ошибка Flask",
            exc_info=(type(original), original, original.__traceback__),
        )
    else:
        app.logger.exception("Ошибка Flask: %s", error)
    return render_template(
        "error.html", code=500,
        message="Произошла внутренняя ошибка. Подробности записаны в терминал приложения.",
    ), 500


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )
