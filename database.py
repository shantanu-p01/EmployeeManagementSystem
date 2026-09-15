"""SQLite persistence for the web Employee Management System.

The database is created automatically in the process working directory so a
normal ``python3 main.py`` run produces ``./employee_management.db``.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


DATABASE_FILENAME = "employee_management.db"


class Database:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or (Path.cwd() / DATABASE_FILENAME)
        self.initialise()

    def connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialise(self) -> None:
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('Admin', 'Employee')),
                    employee_id TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    failure_count INTEGER NOT NULL,
                    first_failed_at TEXT NOT NULL,
                    locked_until TEXT
                );
                CREATE TABLE IF NOT EXISTS web_sessions (
                    browser_session_id TEXT PRIMARY KEY,
                    csrf_token TEXT NOT NULL,
                    auth_token TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS web_flashes (
                    flash_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    browser_session_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    FOREIGN KEY(browser_session_id) REFERENCES web_sessions(browser_session_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS employees (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL DEFAULT '',
                    phone TEXT NOT NULL DEFAULT '',
                    department TEXT NOT NULL DEFAULT '',
                    designation TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS attendance (
                    employee_id TEXT NOT NULL,
                    attendance_date TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('Present', 'Absent')),
                    PRIMARY KEY(employee_id, attendance_date),
                    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS leave_requests (
                    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
                    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS payroll_records (
                    employee_id TEXT NOT NULL,
                    pay_period TEXT NOT NULL,
                    basic_salary REAL NOT NULL CHECK(basic_salary >= 0),
                    allowances REAL NOT NULL CHECK(allowances >= 0),
                    deductions REAL NOT NULL CHECK(deductions >= 0),
                    PRIMARY KEY(employee_id, pay_period),
                    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS payroll_attendance (
                    employee_id TEXT NOT NULL,
                    pay_period TEXT NOT NULL,
                    days_present INTEGER NOT NULL,
                    days_absent INTEGER NOT NULL,
                    days_leave INTEGER NOT NULL,
                    late_arrivals INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(employee_id, pay_period),
                    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE
                );
            """)

    # Employee operations
    def employee_list(self, keyword: str = "") -> List[Dict[str, str]]:
        term = f"%{keyword.strip()}%"
        with self.connection() as conn:
            rows = conn.execute("""SELECT id, name, email, phone, department, designation
                FROM employees WHERE id LIKE ? OR name LIKE ? OR email LIKE ? OR department LIKE ? OR designation LIKE ?
                ORDER BY id""", (term, term, term, term, term)).fetchall()
        return [dict(row) for row in rows]

    def employee_get(self, employee_id: str) -> Optional[Dict[str, str]]:
        with self.connection() as conn:
            row = conn.execute("SELECT id, name, email, phone, department, designation FROM employees WHERE id = ? COLLATE NOCASE", (employee_id.strip(),)).fetchone()
        return dict(row) if row else None

    def employee_add(self, record: Dict[str, str]) -> Dict[str, str]:
        with self.connection() as conn:
            conn.execute("INSERT INTO employees (id, name, email, phone, department, designation) VALUES (?, ?, ?, ?, ?, ?)", tuple(record[key] for key in ("id", "name", "email", "phone", "department", "designation")))
        return record

    def employee_update(self, record: Dict[str, str]) -> bool:
        with self.connection() as conn:
            updated = conn.execute("UPDATE employees SET name=?, email=?, phone=?, department=?, designation=? WHERE id=? COLLATE NOCASE", (record["name"], record["email"], record["phone"], record["department"], record["designation"], record["id"])).rowcount
        return bool(updated)

    def employee_delete(self, employee_id: str) -> bool:
        with self.connection() as conn:
            deleted = conn.execute("DELETE FROM employees WHERE id=? COLLATE NOCASE", (employee_id.strip(),)).rowcount
        return bool(deleted)

    # Attendance and leave operations
    def attendance_add(self, employee_id: str, attendance_date: str, status: str) -> None:
        with self.connection() as conn:
            conn.execute("INSERT INTO attendance (employee_id, attendance_date, status) VALUES (?, ?, ?)", (employee_id, attendance_date, status))

    def attendance_list(self, employee_id: Optional[str] = None, attendance_date: Optional[str] = None) -> List[Dict[str, str]]:
        query, values = "SELECT employee_id, attendance_date, status FROM attendance WHERE 1=1", []
        if employee_id:
            query += " AND employee_id=?"; values.append(employee_id)
        if attendance_date:
            query += " AND attendance_date=?"; values.append(attendance_date)
        query += " ORDER BY attendance_date DESC, employee_id"
        with self.connection() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def leave_add(self, employee_id: str, start_date: str, end_date: str, reason: str) -> str:
        with self.connection() as conn:
            cursor = conn.execute("INSERT INTO leave_requests (employee_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)", (employee_id, start_date, end_date, reason))
        return f"LEAVE{cursor.lastrowid:03d}"

    def leave_list(self, employee_id: Optional[str] = None) -> List[Dict[str, str]]:
        query = "SELECT request_id, employee_id, start_date, end_date, reason, status FROM leave_requests"
        values: Iterable[str] = ()
        if employee_id:
            query += " WHERE employee_id=?"; values = (employee_id,)
        query += " ORDER BY request_id DESC"
        with self.connection() as conn:
            rows = conn.execute(query, values).fetchall()
        return [{**dict(row), "request_id": f"LEAVE{row['request_id']:03d}"} for row in rows]

    def leave_set_status(self, request_code: str, status: str) -> bool:
        if not request_code.upper().startswith("LEAVE"):
            return False
        try:
            request_id = int(request_code[5:])
        except ValueError:
            return False
        with self.connection() as conn:
            updated = conn.execute("UPDATE leave_requests SET status=? WHERE request_id=?", (status, request_id)).rowcount
        return bool(updated)

    # Payroll operations
    def payroll_upsert(self, employee_id: str, pay_period: str, basic_salary: float, allowances: float, deductions: float) -> None:
        with self.connection() as conn:
            conn.execute("""INSERT INTO payroll_records (employee_id, pay_period, basic_salary, allowances, deductions)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT(employee_id, pay_period) DO UPDATE SET
                basic_salary=excluded.basic_salary, allowances=excluded.allowances, deductions=excluded.deductions""", (employee_id, pay_period, basic_salary, allowances, deductions))

    def payroll_get(self, employee_id: str, pay_period: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT employee_id, pay_period, basic_salary, allowances, deductions FROM payroll_records WHERE employee_id=? AND pay_period=?", (employee_id, pay_period)).fetchone()
        return dict(row) if row else None

    def payroll_list(self, pay_period: Optional[str] = None) -> List[Dict[str, Any]]:
        query, values = "SELECT employee_id, pay_period, basic_salary, allowances, deductions FROM payroll_records", ()
        if pay_period:
            query += " WHERE pay_period=?"; values = (pay_period,)
        with self.connection() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def payroll_attendance_upsert(self, record: Dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute("""INSERT INTO payroll_attendance VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(employee_id, pay_period) DO UPDATE SET days_present=excluded.days_present,
                days_absent=excluded.days_absent, days_leave=excluded.days_leave, late_arrivals=excluded.late_arrivals""",
                (record["employee_id"], record["pay_period"], record["days_present"], record["days_absent"], record["days_leave"], record["late_arrivals"]))

    def payroll_attendance_get(self, employee_id: str, pay_period: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM payroll_attendance WHERE employee_id=? AND pay_period=?", (employee_id, pay_period)).fetchone()
        return dict(row) if row else None

    def payroll_attendance_list(self, pay_period: Optional[str] = None) -> List[Dict[str, Any]]:
        query, values = "SELECT * FROM payroll_attendance", ()
        if pay_period:
            query += " WHERE pay_period=?"; values = (pay_period,)
        with self.connection() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def payroll_clear(self) -> None:
        with self.connection() as conn:
            conn.executescript("DELETE FROM payroll_attendance; DELETE FROM payroll_records;")

    # Browser session data: this keeps CSRF/session state durable rather than
    # relying on a process-local dictionary.
    def web_session_get(self, session_id: str) -> Optional[Dict[str, Optional[str]]]:
        with self.connection() as conn:
            row = conn.execute("SELECT browser_session_id, csrf_token, auth_token FROM web_sessions WHERE browser_session_id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def web_session_create(self, session_id: str, csrf_token: str) -> None:
        with self.connection() as conn:
            conn.execute("INSERT INTO web_sessions VALUES (?, ?, NULL, ?)", (session_id, csrf_token, datetime.now(timezone.utc).isoformat()))

    def web_session_set_auth(self, session_id: str, auth_token: Optional[str]) -> None:
        with self.connection() as conn:
            conn.execute("UPDATE web_sessions SET auth_token=? WHERE browser_session_id=?", (auth_token, session_id))

    def flash_add(self, session_id: str, kind: str, message: str) -> None:
        with self.connection() as conn:
            conn.execute("INSERT INTO web_flashes (browser_session_id, kind, message) VALUES (?, ?, ?)", (session_id, kind, message))

    def flash_pop(self, session_id: str) -> List[Dict[str, str]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT flash_id, kind, message FROM web_flashes WHERE browser_session_id=? ORDER BY flash_id", (session_id,)).fetchall()
            conn.execute("DELETE FROM web_flashes WHERE browser_session_id=?", (session_id,))
        return [dict(row) for row in rows]


database = Database()
