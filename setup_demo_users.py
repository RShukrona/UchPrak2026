"""Установка демонстрационных паролей для локальной учебной базы.

Запускайте только на локальном компьютере для тестовой базы данных.
Не используйте эти пароли на реальном или опубликованном сервере.
"""
import os
import sys

import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

DEMO_USERS = {
    "admin": "admin123",
    "engineer1": "engineer123",
    "engineer2": "engineer123",
    "client1": "client123",
    "client2": "client123",
    "client3": "client123",
}


def main():
    try:
        connection = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            dbname=os.getenv("DB_NAME", "derzhava"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", ""),
            connect_timeout=5,
        )
        with connection:
            with connection.cursor() as cursor:
                missing = []
                for username, password in DEMO_USERS.items():
                    cursor.execute(
                        """
                        UPDATE users
                        SET password_hash = %s
                        WHERE username = %s
                        RETURNING user_id
                        """,
                        (generate_password_hash(password), username),
                    )
                    if cursor.fetchone() is None:
                        missing.append(username)

                if missing:
                    raise RuntimeError(
                        "В таблице users не найдены: " + ", ".join(missing)
                    )

        print("Демонстрационные пароли успешно установлены.")
        print("Теперь можно войти под admin, engineer1/2 или client1/2/3.")
        print("Пароли указаны в README.md.")
    except (psycopg2.Error, RuntimeError) as error:
        print("Не удалось установить пароли:", error)
        sys.exit(1)
    finally:
        if "connection" in locals():
            connection.close()


if __name__ == "__main__":
    main()
