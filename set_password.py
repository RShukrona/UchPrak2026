"""Безопасная установка пароля существующему пользователю БД derzhava."""
import os
from getpass import getpass

import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

def main():
    username = input("Логин пользователя: ").strip()
    if not username:
        print("Логин не может быть пустым.")
        return
    password = getpass("Новый пароль (не менее 10 символов): ")
    confirm = getpass("Повторите пароль: ")
    if len(password) < 10:
        print("Пароль должен содержать минимум 10 символов.")
        return
    if password != confirm:
        print("Пароли не совпадают.")
        return
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "derzhava"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE username = %s RETURNING user_id",
                (generate_password_hash(password), username),
            )
            row = cur.fetchone()
            if row:
                print(f"Пароль обновлён для пользователя {username}.")
            else:
                print("Пользователь с таким логином не найден; изменений нет.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
