-- ООО «СК Держава»: схема БД, совместимая с app.py
-- ВНИМАНИЕ: скрипт удаляет таблицы и все данные в них.
BEGIN;
DROP TABLE IF EXISTS requests CASCADE;
DROP TABLE IF EXISTS equipment CASCADE;
DROP TABLE IF EXISTS statuses CASCADE;
DROP TABLE IF EXISTS employees CASCADE;
DROP TABLE IF EXISTS clients CASCADE;

CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    contact_person VARCHAR(150),
    email VARCHAR(150) NOT NULL UNIQUE,
    phone VARCHAR(30),
    password VARCHAR(255) NOT NULL,
    address TEXT,
    registration_date DATE DEFAULT CURRENT_DATE
);

CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    position VARCHAR(100) NOT NULL,
    phone VARCHAR(30),
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    specialization VARCHAR(150)
);

CREATE TABLE statuses (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE equipment (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    model_name VARCHAR(150) NOT NULL,
    equipment_type VARCHAR(100) NOT NULL,
    serial_number VARCHAR(100) NOT NULL UNIQUE,
    production_year INTEGER CHECK (production_year IS NULL OR production_year BETWEEN 1900 AND 2100),
    warranty_number VARCHAR(100),
    warranty_until DATE,
    note TEXT
);

CREATE TABLE requests (
    id SERIAL PRIMARY KEY,
    request_number VARCHAR(40) NOT NULL UNIQUE,
    creation_date DATE NOT NULL DEFAULT CURRENT_DATE,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    equipment_id INTEGER NOT NULL REFERENCES equipment(id) ON DELETE RESTRICT,
    status_id INTEGER NOT NULL REFERENCES statuses(id) ON DELETE RESTRICT,
    problem_description TEXT NOT NULL,
    is_warranty BOOLEAN NOT NULL DEFAULT FALSE,
    employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    labor_cost NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (labor_cost >= 0),
    parts_cost NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (parts_cost >= 0),
    final_cost NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (final_cost >= 0),
    closing_date DATE CHECK (closing_date IS NULL OR closing_date >= creation_date)
);

CREATE INDEX idx_equipment_client ON equipment(client_id);
CREATE INDEX idx_requests_client ON requests(client_id);
CREATE INDEX idx_requests_equipment ON requests(equipment_id);
CREATE INDEX idx_requests_status ON requests(status_id);
CREATE INDEX idx_requests_employee ON requests(employee_id);
CREATE INDEX idx_requests_date ON requests(creation_date);

INSERT INTO statuses(name,description) VALUES
('Новая','Заявка зарегистрирована и ожидает обработки'),
('Принята','Заявка принята в работу'),
('В работе','Выполняется диагностика или ремонт'),
('Ожидание запчастей','Ожидается поступление необходимых деталей'),
('Готова','Ремонт завершён, оборудование готово'),
('Закрыта','Заявка полностью завершена'),
('Отменена','Заявка отменена');
COMMIT;
