"""Browser interface for the Employee Management System.

Run with ``python3 main.py`` and visit http://127.0.0.1:8000.  This module
uses only the Python standard library; the existing domain services continue
to own employee, attendance, payroll, reporting, and authentication logic.
"""

from __future__ import annotations

import html
import os
import secrets
from dataclasses import dataclass
from datetime import date, datetime
from http import cookies
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

import employee_management as employees
from attendance import AttendanceService, DuplicateAttendanceError, LeaveService, LeaveRequestNotFoundError
from auth import AuthError, AuthService, InvalidCredentialsError, Permission, Role
from payroll import PayrollError, PayslipGenerator, ReportService
from database import database


APP_NAME = "Enterprise EMS"
COOKIE_NAME = "ems_web_session"


@dataclass
class BrowserSession:
    """Server-side browser session. Authentication tokens never enter HTML."""

    csrf_token: str
    auth_token: Optional[str] = None
    session_id: str = ""


class EmployeeWebApp:
    def __init__(self) -> None:
        self.auth = AuthService(session_duration_minutes=30)
        self.attendance = AttendanceService()
        self.leaves = LeaveService()

    # ---------------------------- HTTP helpers ----------------------------
    def __call__(self, environ: dict, start_response: Callable):
        request = self._request(environ)
        browser_id, browser_session, new_session = self._browser_session(environ)
        current = self._current_user(browser_session)
        try:
            response = self._dispatch(request, browser_session, current)
        except Exception:
            # Do not leak implementation details in browser responses.
            response = self._page("Unexpected error", "<p>We could not complete that request. Please try again.</p>", current, browser_session, status="500 Internal Server Error")

        status, headers, body = response
        if not any(header.lower() == "content-type" for header, _ in headers):
            headers.append(("Content-Type", "text/html; charset=utf-8"))
        headers.extend([
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "same-origin"),
            ("Content-Security-Policy", "default-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"),
            ("Cache-Control", "no-store"),
        ])
        if new_session:
            secure = "; Secure" if os.getenv("EMS_COOKIE_SECURE") == "1" else ""
            headers.append(("Set-Cookie", f"{COOKIE_NAME}={browser_id}; Path=/; HttpOnly; SameSite=Strict{secure}"))
        body_bytes = body.encode("utf-8")
        headers.append(("Content-Length", str(len(body_bytes))))
        start_response(status, headers)
        return [body_bytes]

    @staticmethod
    def _request(environ: dict) -> dict:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length).decode("utf-8", "replace") if length else ""
        query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        form = parse_qs(raw, keep_blank_values=True) if environ.get("REQUEST_METHOD") == "POST" else {}
        return {"method": environ.get("REQUEST_METHOD", "GET"), "path": environ.get("PATH_INFO", "/"), "query": query, "form": form}

    def _browser_session(self, environ: dict) -> Tuple[str, BrowserSession, bool]:
        jar = cookies.SimpleCookie(environ.get("HTTP_COOKIE", ""))
        candidate = jar.get(COOKIE_NAME)
        session_id = candidate.value if candidate else ""
        row = database.web_session_get(session_id) if session_id else None
        if row:
            return session_id, BrowserSession(str(row["csrf_token"]), row["auth_token"], session_id), False
        session_id = secrets.token_urlsafe(32)
        session = BrowserSession(csrf_token=secrets.token_urlsafe(32))
        session.session_id = session_id
        database.web_session_create(session_id, session.csrf_token)
        return session_id, session, True

    def _current_user(self, session: BrowserSession):
        if not session.auth_token:
            return None
        try:
            return self.auth.get_current_user(session.auth_token)
        except AuthError:
            session.auth_token = None
            database.web_session_set_auth(session.session_id, None)
            return None

    @staticmethod
    def _value(request: dict, key: str, default: str = "") -> str:
        return request["form"].get(key, [default])[0].strip()

    def _csrf_ok(self, request: dict, session: BrowserSession) -> bool:
        return request["method"] == "POST" and secrets.compare_digest(self._value(request, "csrf"), session.csrf_token)

    def _flash(self, session: BrowserSession, kind: str, message: str) -> None:
        database.flash_add(session.session_id, kind, message)

    def _redirect(self, location: str, session: BrowserSession, message: Optional[str] = None, kind: str = "success"):
        if message:
            self._flash(session, kind, message)
        return "303 See Other", [("Location", location)], ""

    def _require(self, session: BrowserSession, current, permission: Optional[Permission] = None):
        if not current:
            self._flash(session, "error", "Please sign in to continue.")
            return self._redirect("/login", session)
        if permission and not self.auth.has_permission(session.auth_token or "", permission):
            self._flash(session, "error", "You do not have permission for that action.")
            return self._redirect("/", session)
        return None

    # ----------------------------- Page layout -----------------------------
    @staticmethod
    def _e(value: object) -> str:
        return html.escape(str(value), quote=True)

    def _page(self, title: str, content: str, current, session: BrowserSession, status: str = "200 OK"):
        nav = ""
        if current:
            nav = """<nav><a href='/'>Overview</a><a href='/employees'>Employees</a><a href='/attendance'>Attendance &amp; leave</a><a href='/payroll'>Payroll</a>"""
            if self.auth.has_permission(session.auth_token or "", Permission.VIEW_REPORTS):
                nav += "<a href='/reports'>Reports</a>"
            if self.auth.has_permission(session.auth_token or "", Permission.ADD_EMPLOYEE):
                nav += "<a href='/users'>User accounts</a>"
            nav += "</nav>"
            user = f"<span class='user'>{self._e(current.username)} · {self._e(current.role)}</span><form class='inline' method='post' action='/logout'>{self._csrf(session)}<button class='quiet'>Sign out</button></form>"
        else:
            user = "<a class='button quiet' href='/login'>Sign in</a>"
        notices = "".join(f"<div class='notice {self._e(item['kind'])}'>{self._e(item['message'])}</div>" for item in database.flash_pop(session.session_id))
        page = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{self._e(title)} · {APP_NAME}</title><link rel='stylesheet' href='/assets/app.css'></head><body><header><a class='brand' href='/'>{APP_NAME}</a>{nav}<div class='account'>{user}</div></header><main><div class='title'><h1>{self._e(title)}</h1></div>{notices}{content}</main></body></html>"""
        return status, [], page

    def _csrf(self, session: BrowserSession) -> str:
        return f"<input type='hidden' name='csrf' value='{self._e(session.csrf_token)}'>"

    def _form_error(self, session: BrowserSession):
        self._flash(session, "error", "The form could not be verified. Refresh the page and try again.")
        return self._redirect("/", session)

    @staticmethod
    def _table(headers: List[str], rows: List[List[object]]) -> str:
        head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
        body = "".join("<tr>" + "".join(f"<td>{cell if isinstance(cell, str) and cell.startswith('<') else html.escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
        return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body or '<tr><td colspan='+str(len(headers))+'>No records found.</td></tr>'}</tbody></table></div>"

    # ------------------------------ Routing ---------------------------------
    def _dispatch(self, request: dict, session: BrowserSession, current):
        path = request["path"]
        if path == "/assets/app.css":
            return "200 OK", [("Content-Type", "text/css; charset=utf-8"), ("Cache-Control", "public, max-age=3600")], CSS
        if path == "/login":
            return self._login(request, session, current)
        if path == "/logout":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            if session.auth_token:
                self.auth.logout(session.auth_token)
            session.auth_token = None
            database.web_session_set_auth(session.session_id, None)
            return self._redirect("/login", session, "You have been signed out.")
        if path == "/":
            denied = self._require(session, current)
            return denied or self._dashboard(current, session)
        if path == "/employees":
            return self._employees(request, session, current)
        if path == "/attendance":
            return self._attendance(request, session, current)
        if path == "/payroll":
            return self._payroll(request, session, current)
        if path == "/reports":
            return self._reports(request, session, current)
        if path == "/download":
            return self._download(request, session, current)
        if path == "/users":
            return self._users(request, session, current)
        return self._page("Page not found", "<p>The requested page does not exist.</p>", current, session, status="404 Not Found")

    def _login(self, request: dict, session: BrowserSession, current):
        if current:
            return self._redirect("/", session)
        if request["method"] == "POST":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            try:
                logged_in = self.auth.login(self._value(request, "username"), self._value(request, "password"))
                session.auth_token = logged_in.session_token
                database.web_session_set_auth(session.session_id, logged_in.session_token)
                return self._redirect("/", session, "Signed in successfully.")
            except (AuthError, ValueError):
                # A single response protects usernames, account state, and lock status.
                self._flash(session, "error", "Unable to sign in with those credentials.")
                return self._redirect("/login", session)
        content = f"""<section class='auth-card'><p class='lead'>Secure access to employee, attendance, and payroll operations.</p><form method='post' class='stack'>{self._csrf(session)}<label>Username<input name='username' autocomplete='username' required maxlength='50'></label><label>Password<input name='password' type='password' autocomplete='current-password' required></label><button>Sign in</button></form><p class='hint'>After five failed attempts, sign-in is temporarily locked for 15 minutes. Sessions expire after 30 minutes.</p></section>"""
        return self._page("Sign in", content, None, session)

    def _dashboard(self, current, session: BrowserSession):
        records = employees.get_all_employees()
        counts = [("Employees", len(records)), ("Attendance entries", len(self.attendance.get_all_attendance())), ("Leave requests", len(self.leaves.get_leave_requests()))]
        cards = "".join(f"<div class='card'><span>{label}</span><strong>{count}</strong></div>" for label, count in counts)
        allowed = ", ".join(current.permissions) or "No permissions"
        content = f"<p class='lead'>Welcome back, {self._e(current.username)}. Your session is protected server-side and your role controls every action.</p><section class='cards'>{cards}</section><section class='panel'><h2>Your access</h2><p><b>{self._e(current.role)}</b> role</p><p class='permissions'>{self._e(allowed)}</p></section>"
        return self._page("Overview", content, current, session)

    # --------------------------- Employee records ---------------------------
    def _employees(self, request: dict, session: BrowserSession, current):
        denied = self._require(session, current, Permission.VIEW_EMPLOYEE)
        if denied:
            return denied
        if request["method"] == "POST":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            action = self._value(request, "action")
            emp_id = self._value(request, "employee_id")
            try:
                if action == "add":
                    permission = Permission.ADD_EMPLOYEE
                    if (blocked := self._require(session, current, permission)):
                        return blocked
                    name = self._value(request, "name")
                    if not name:
                        raise ValueError("Employee name is required.")
                    record = employees.add_employee(name, self._value(request, "email"), self._value(request, "phone"), self._value(request, "department"), self._value(request, "designation"), emp_id or None)
                    return self._redirect("/employees", session, f"Employee {record['id']} was added.")
                if action == "update":
                    if (blocked := self._require(session, current, Permission.UPDATE_EMPLOYEE)):
                        return blocked
                    if not employees.update_employee(emp_id, self._value(request, "name"), self._value(request, "email"), self._value(request, "phone"), self._value(request, "department"), self._value(request, "designation")):
                        raise ValueError("Employee was not found.")
                    return self._redirect("/employees", session, "Employee details were updated.")
                if action == "delete":
                    if (blocked := self._require(session, current, Permission.DELETE_EMPLOYEE)):
                        return blocked
                    if not employees.delete_employee(emp_id):
                        raise ValueError("Employee was not found.")
                    return self._redirect("/employees", session, "Employee was removed.")
                raise ValueError("Unsupported employee action.")
            except ValueError as exc:
                return self._redirect("/employees", session, str(exc), "error")
        keyword = request["query"].get("q", [""])[0]
        data = employees.search_employees(keyword)
        is_admin = self.auth.has_permission(session.auth_token or "", Permission.ADD_EMPLOYEE)
        if not is_admin:
            data = [item for item in data if item["id"] == current.employee_id]
        rows = []
        for item in data:
            action = ""
            if is_admin:
                action = f"<details><summary>Edit</summary><form method='post' class='compact'>{self._csrf(session)}<input name='action' value='update' type='hidden'><input name='employee_id' value='{self._e(item['id'])}' type='hidden'><input name='name' value='{self._e(item['name'])}' required><input name='email' value='{self._e(item['email'])}'><input name='phone' value='{self._e(item['phone'])}'><input name='department' value='{self._e(item['department'])}'><input name='designation' value='{self._e(item['designation'])}'><button>Save</button></form><form method='post' class='inline'>{self._csrf(session)}<input name='action' value='delete' type='hidden'><input name='employee_id' value='{self._e(item['id'])}' type='hidden'><button class='danger' onclick=\"return confirm('Remove this employee?')\">Remove</button></form></details>"
            rows.append([item["id"], item["name"], item["email"], item["phone"], item["department"], item["designation"], action])
        add_form = ""
        if is_admin:
            add_form = f"""<section class='panel'><h2>Add employee</h2><form method='post' class='grid-form'>{self._csrf(session)}<input type='hidden' name='action' value='add'><label>Employee ID <input name='employee_id' placeholder='Auto-generated if blank'></label><label>Name <input name='name' required></label><label>Email <input name='email' type='email'></label><label>Phone <input name='phone'></label><label>Department <input name='department' required></label><label>Designation <input name='designation' required></label><button>Add employee</button></form></section>"""
        content = f"<form class='search' method='get'><input name='q' value='{self._e(keyword)}' placeholder='Search name, ID, department…'><button>Search</button></form>{add_form}<section class='panel'><h2>Employee directory</h2>{self._table(['ID', 'Name', 'Email', 'Phone', 'Department', 'Designation', 'Actions'], rows)}</section>"
        return self._page("Employees", content, current, session)

    # ------------------------ Attendance and leave --------------------------
    def _employee_options(self, selected: Optional[str] = None) -> str:
        return "".join(f"<option value='{self._e(item['id'])}'{' selected' if item['id'] == selected else ''}>{self._e(item['id'])} — {self._e(item['name'])}</option>" for item in employees.get_all_employees())

    def _attendance(self, request: dict, session: BrowserSession, current):
        allowed = self.auth.has_permission(session.auth_token or "", Permission.MARK_ATTENDANCE) or self.auth.has_permission(session.auth_token or "", Permission.APPLY_LEAVE)
        if not current or not allowed:
            return self._require(session, current, Permission.MARK_ATTENDANCE)
        is_admin = self.auth.has_permission(session.auth_token or "", Permission.APPROVE_LEAVE)
        if request["method"] == "POST":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            action = self._value(request, "action")
            try:
                if action == "mark":
                    if (blocked := self._require(session, current, Permission.MARK_ATTENDANCE)):
                        return blocked
                    employee_id = self._value(request, "employee_id") if is_admin else (current.employee_id or "")
                    if not employees.get_employee_by_id(employee_id):
                        raise ValueError("Select a valid employee record.")
                    self.attendance.mark_attendance(employee_id, datetime.strptime(self._value(request, "attendance_date"), "%Y-%m-%d").date(), self._value(request, "status"))
                    return self._redirect("/attendance", session, "Attendance was recorded.")
                if action == "leave":
                    if (blocked := self._require(session, current, Permission.APPLY_LEAVE)):
                        return blocked
                    employee_id = current.employee_id or ""
                    if not employees.get_employee_by_id(employee_id):
                        raise ValueError("Your account must be linked to a valid employee ID before applying for leave.")
                    self.leaves.apply_leave(employee_id, datetime.strptime(self._value(request, "start_date"), "%Y-%m-%d").date(), datetime.strptime(self._value(request, "end_date"), "%Y-%m-%d").date(), self._value(request, "reason"))
                    return self._redirect("/attendance", session, "Leave request submitted.")
                if action in {"approve", "reject"}:
                    if (blocked := self._require(session, current, Permission.APPROVE_LEAVE if action == "approve" else Permission.REJECT_LEAVE)):
                        return blocked
                    request_id = self._value(request, "request_id")
                    (self.leaves.approve_leave if action == "approve" else self.leaves.reject_leave)(request_id)
                    return self._redirect("/attendance", session, f"Leave request {action}d.")
                raise ValueError("Unsupported attendance action.")
            except (ValueError, DuplicateAttendanceError, LeaveRequestNotFoundError) as exc:
                return self._redirect("/attendance", session, str(exc), "error")
        attendance_data = self.attendance.get_all_attendance()
        leave_data = self.leaves.get_leave_requests()
        if not is_admin:
            attendance_data = [item for item in attendance_data if item.employee_id == current.employee_id]
            leave_data = [item for item in leave_data if item.employee_id == current.employee_id]
        attendance_rows = [[record.employee_id, self._employee_name(record.employee_id), record.date, record.status] for record in attendance_data]
        leave_rows = []
        for record in leave_data:
            actions = ""
            if is_admin and record.status == "Pending":
                actions = f"<form method='post' class='inline'>{self._csrf(session)}<input type='hidden' name='action' value='approve'><input type='hidden' name='request_id' value='{self._e(record.request_id)}'><button>Approve</button></form><form method='post' class='inline'>{self._csrf(session)}<input type='hidden' name='action' value='reject'><input type='hidden' name='request_id' value='{self._e(record.request_id)}'><button class='danger'>Reject</button></form>"
            leave_rows.append([record.request_id, record.employee_id, record.start_date, record.end_date, record.reason, record.status, actions])
        mark_form = ""
        if self.auth.has_permission(session.auth_token or "", Permission.MARK_ATTENDANCE):
            select = f"<select name='employee_id'>{self._employee_options()}</select>" if is_admin else f"<b>{self._e(current.employee_id or 'Unlinked account')}</b>"
            mark_form = f"<section class='panel'><h2>Record attendance</h2><form method='post' class='grid-form'>{self._csrf(session)}<input type='hidden' name='action' value='mark'><label>Employee {select}</label><label>Date <input name='attendance_date' type='date' value='{date.today().isoformat()}' required></label><label>Status <select name='status'><option>Present</option><option>Absent</option></select></label><button>Record attendance</button></form></section>"
        leave_form = ""
        if self.auth.has_permission(session.auth_token or "", Permission.APPLY_LEAVE):
            leave_form = f"<section class='panel'><h2>Apply for leave</h2><form method='post' class='grid-form'>{self._csrf(session)}<input type='hidden' name='action' value='leave'><label>Start date <input name='start_date' type='date' value='{date.today().isoformat()}' required></label><label>End date <input name='end_date' type='date' value='{date.today().isoformat()}' required></label><label class='wide'>Reason <input name='reason' maxlength='300' required></label><button>Submit leave request</button></form></section>"
        content = f"{mark_form}{leave_form}<section class='panel'><h2>Attendance log</h2>{self._table(['Employee ID', 'Employee', 'Date', 'Status'], attendance_rows)}</section><section class='panel'><h2>Leave requests</h2>{self._table(['Request', 'Employee', 'Start', 'End', 'Reason', 'Status', 'Actions'], leave_rows)}</section>"
        return self._page("Attendance & leave", content, current, session)

    # ----------------------------- Payroll ----------------------------------
    def _payroll(self, request: dict, session: BrowserSession, current):
        can_process = current and self.auth.has_permission(session.auth_token or "", Permission.VIEW_PAYROLL)
        can_view = current and self.auth.has_permission(session.auth_token or "", Permission.VIEW_PAYSLIP)
        if not current or not (can_process or can_view):
            return self._require(session, current, Permission.VIEW_PAYSLIP)
        result = ""
        if request["method"] == "POST":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            if not can_process:
                return self._redirect("/payroll", session, "You do not have permission to process payroll.", "error")
            try:
                employee_id = self._value(request, "employee_id")
                person = employees.get_employee_by_id(employee_id)
                if not person:
                    raise ValueError("Select a valid employee.")
                payslip, _ = PayslipGenerator.generate_payslip(employee_id, person["name"], self._value(request, "pay_period"), float(self._value(request, "basic_salary")), float(self._value(request, "allowances") or "0"), float(self._value(request, "deductions") or "0"), currency="INR")
                database.payroll_upsert(employee_id, payslip.pay_period, payslip.basic_salary, payslip.allowances, payslip.deductions)
                result = self._payslip_html(payslip) + self._payslip_download_link(payslip)
                self._flash(session, "success", "Payslip generated and payroll record saved.")
            except (ValueError, PayrollError) as exc:
                self._flash(session, "error", str(exc))
        requested = request["query"].get("employee_id", [""])[0]
        if can_view and requested:
            if requested != current.employee_id:
                self._flash(session, "error", "You can only view your own payslip.")
            else:
                try:
                    record = database.payroll_get(requested, request["query"].get("period", [date.today().strftime("%Y-%m")])[0])
                    person = employees.get_employee_by_id(requested)
                    if not record or not person:
                        raise PayrollError("Payslip not found.")
                    payslip, _ = PayslipGenerator.generate_payslip(requested, person["name"], record["pay_period"], record["basic_salary"], record["allowances"], record["deductions"], currency="INR")
                    result = self._payslip_html(payslip) + self._payslip_download_link(payslip)
                except PayrollError:
                    self._flash(session, "error", "No payslip was found for that pay period.")
        processor = ""
        if can_process:
            processor = f"""<section class='panel'><h2>Generate payslip</h2><form method='post' class='grid-form'>{self._csrf(session)}<label>Employee <select name='employee_id'>{self._employee_options()}</select></label><label>Pay period <input name='pay_period' value='{date.today().strftime('%Y-%m')}' pattern='[0-9]{{4}}-[0-9]{{2}}' required></label><label>Basic salary (₹) <input name='basic_salary' type='number' min='0' step='.01' required></label><label>Allowances (₹) <input name='allowances' type='number' min='0' step='.01' value='0'></label><label>Deductions (₹) <input name='deductions' type='number' min='0' step='.01' value='0'></label><button>Generate payslip</button></form></section>"""
        own = ""
        if can_view:
            own = f"<section class='panel'><h2>My payslip</h2><form method='get' class='search'><input type='hidden' name='employee_id' value='{self._e(current.employee_id or '')}'><label>Pay period <input name='period' value='{date.today().strftime('%Y-%m')}' pattern='[0-9]{{4}}-[0-9]{{2}}'></label><button>View payslip</button></form></section>"
        content = f"{processor}{own}{result}"
        return self._page("Payroll & payslips", content, current, session)

    def _payslip_html(self, payslip) -> str:
        values = [("Employee", payslip.employee_name), ("Employee ID", payslip.employee_id), ("Pay period", payslip.pay_period), ("Basic salary", f"₹ {payslip.basic_salary:,.2f}"), ("Allowances", f"₹ {payslip.allowances:,.2f}"), ("Gross salary", f"₹ {payslip.gross_salary:,.2f}"), ("Deductions", f"₹ {payslip.deductions:,.2f}"), ("Net salary", f"₹ {payslip.net_salary:,.2f}")]
        return "<section class='panel payslip'><h2>Payslip</h2>" + "".join(f"<div><span>{self._e(key)}</span><b>{self._e(value)}</b></div>" for key, value in values) + "</section>"

    def _payslip_download_link(self, payslip) -> str:
        return f"<a class='button' href='/download?type=payslip&amp;employee_id={self._e(payslip.employee_id)}&amp;period={self._e(payslip.pay_period)}'>Download payslip (.txt)</a>"

    # -------------------------- Reports and users ---------------------------
    def _reports(self, request: dict, session: BrowserSession, current):
        denied = self._require(session, current, Permission.VIEW_REPORTS)
        if denied:
            return denied
        report_type = request["query"].get("type", ["headcount"])[0]
        try:
            if report_type == "attendance":
                text = ReportService.format_attendance_report(ReportService.generate_attendance_report(self._attendance_report_records()))
                title = "Attendance analytics"
            elif report_type == "salary":
                text = ReportService.format_salary_report(ReportService.generate_salary_report(database.payroll_list(), currency="INR"))
                title = "Salary analytics"
            else:
                text = ReportService.format_employee_report(ReportService.generate_employee_report(employees.get_all_employees()))
                title = "Headcount & demographics"
        except PayrollError as exc:
            text, title = str(exc), "Report unavailable"
        controls = f"<div class='tabs'><a href='/reports?type=headcount'>Headcount</a><a href='/reports?type=attendance'>Attendance</a><a href='/reports?type=salary'>Salary</a><a href='/download?type=report&amp;report={self._e(report_type)}'>Download report (.txt)</a></div>"
        return self._page("Reports", f"{controls}<section class='panel'><h2>{self._e(title)}</h2><pre>{self._e(text)}</pre></section>", current, session)

    def _download(self, request: dict, session: BrowserSession, current):
        """Return text documents with the same RBAC rules as their browser views."""
        if not current:
            return self._require(session, current)
        document_type = request["query"].get("type", [""])[0]
        try:
            if document_type == "report":
                if (denied := self._require(session, current, Permission.VIEW_REPORTS)):
                    return denied
                report_type = request["query"].get("report", ["headcount"])[0]
                if report_type == "attendance":
                    text = ReportService.format_attendance_report(ReportService.generate_attendance_report(self._attendance_report_records()))
                elif report_type == "salary":
                    text = ReportService.format_salary_report(ReportService.generate_salary_report(database.payroll_list(), currency="INR"))
                else:
                    text = ReportService.format_employee_report(ReportService.generate_employee_report(employees.get_all_employees()))
                filename = f"ems-{report_type}-report.txt"
            elif document_type == "payslip":
                employee_id = request["query"].get("employee_id", [""])[0]
                period = request["query"].get("period", [""])[0]
                is_payroll_admin = self.auth.has_permission(session.auth_token or "", Permission.VIEW_PAYROLL)
                is_owner = self.auth.has_permission(session.auth_token or "", Permission.VIEW_PAYSLIP) and employee_id == current.employee_id
                if not (is_payroll_admin or is_owner):
                    return self._redirect("/payroll", session, "You do not have permission to download that payslip.", "error")
                record = database.payroll_get(employee_id, period)
                person = employees.get_employee_by_id(employee_id)
                if not record or not person:
                    raise PayrollError("Payslip not found.")
                _, text = PayslipGenerator.generate_payslip(employee_id, person["name"], period, record["basic_salary"], record["allowances"], record["deductions"], currency="INR")
                filename = f"payslip-{employee_id}-{period}.txt"
            else:
                raise ValueError("Unknown document type.")
        except (ValueError, PayrollError):
            return self._redirect("/", session, "The requested document is not available.", "error")
        safe_filename = filename.replace('"', "")
        return "200 OK", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Disposition", f'attachment; filename="{safe_filename}"')], text

    def _users(self, request: dict, session: BrowserSession, current):
        denied = self._require(session, current, Permission.ADD_EMPLOYEE)
        if denied:
            return denied
        if request["method"] == "POST":
            if not self._csrf_ok(request, session):
                return self._form_error(session)
            try:
                employee_id = self._value(request, "employee_id")
                if not employees.get_employee_by_id(employee_id):
                    raise ValueError("Create the employee record before creating its account.")
                # Browser users are deliberately created as Employee accounts;
                # administrative privilege is never self-service.
                user = self.auth.register_user(self._value(request, "username"), self._value(request, "password"), Role.EMPLOYEE, employee_id)
                return self._redirect("/users", session, f"Account for {user.username} was created.")
            except (AuthError, ValueError) as exc:
                return self._redirect("/users", session, str(exc), "error")
        rows = [[user.username, user.role, user.employee_id or "—", "Active" if user.is_active else "Disabled"] for user in self.auth.list_all_users()]
        form = f"""<section class='panel'><h2>Create employee account</h2><form method='post' class='grid-form'>{self._csrf(session)}<label>Employee <select name='employee_id'>{self._employee_options()}</select></label><label>Username <input name='username' pattern='[A-Za-z0-9_.-]{{3,50}}' required></label><label class='wide'>Temporary password <input name='password' type='password' minlength='12' required><small>At least 12 characters and three of: lowercase, uppercase, number, symbol.</small></label><button>Create employee account</button></form></section>"""
        return self._page("User accounts", form + f"<section class='panel'><h2>Accounts</h2>{self._table(['Username', 'Role', 'Employee ID', 'Status'], rows)}</section>", current, session)

    # --------------------------- Service setup ------------------------------
    def _employee_name(self, employee_id: str) -> str:
        record = employees.get_employee_by_id(employee_id)
        return record["name"] if record else "Unknown"

    def _attendance_report_records(self) -> List[Dict[str, object]]:
        """Convert persisted daily marks into the report service's monthly shape."""
        grouped: Dict[Tuple[str, str], Dict[str, object]] = {}
        for row in database.attendance_list():
            key = (row["employee_id"], row["attendance_date"][:7])
            item = grouped.setdefault(key, {"employee_id": key[0], "pay_period": key[1], "days_present": 0, "days_absent": 0, "days_leave": 0, "late_arrivals": 0})
            if row["status"] == "Present":
                item["days_present"] = int(item["days_present"]) + 1
            else:
                item["days_absent"] = int(item["days_absent"]) + 1
        return list(grouped.values())


CSS = """
:root{--ink:#172033;--brand:#172b4d;--blue:#1769aa;--line:#dbe3ee;--bg:#f4f7fb;--danger:#b42318;--good:#047857}*{box-sizing:border-box}body{margin:0;background:var(--bg);font:15px system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:var(--ink)}header{min-height:64px;background:var(--brand);color:white;display:flex;align-items:center;padding:0 4vw;gap:24px}.brand{font-weight:800;font-size:18px;color:white;text-decoration:none}nav{display:flex;gap:16px;flex:1}nav a{color:#dbeafe;text-decoration:none;font-size:14px}.account{display:flex;align-items:center;gap:10px}.user{font-size:13px}.inline{display:inline}.quiet{background:transparent;border:1px solid #8da0ba;color:white}.button{display:inline-block;padding:9px 13px;border-radius:7px;text-decoration:none}main{max-width:1180px;margin:0 auto;padding:28px 20px 48px}.title h1{font-size:27px;margin:0 0 18px}.lead{font-size:17px;line-height:1.55}.panel,.auth-card{background:white;border:1px solid var(--line);border-radius:10px;padding:20px;margin:18px 0;box-shadow:0 1px 2px #12213a0b}.auth-card{max-width:470px;margin:46px auto}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{background:white;border:1px solid var(--line);padding:20px;border-radius:10px}.card span{display:block;color:#58657a}.card strong{display:block;font-size:31px;margin-top:5px}.stack label,.grid-form label{display:flex;flex-direction:column;gap:6px;font-weight:650}.stack{display:grid;gap:15px}.grid-form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;align-items:end}.wide{grid-column:span 2}input,select,button{font:inherit;border-radius:6px;padding:9px 10px;border:1px solid #aebdce;background:white;color:var(--ink)}button{background:var(--blue);border-color:var(--blue);color:white;cursor:pointer;font-weight:700;width:max-content}.danger{background:var(--danger);border-color:var(--danger)}.notice{padding:11px 14px;border-radius:7px;margin:12px 0}.notice.success{background:#e8f7ef;color:#075c39}.notice.error{background:#fff0ef;color:#8e1b12}.search{display:flex;gap:9px;align-items:end;margin-bottom:16px}.search input{min-width:280px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:#536174;text-transform:uppercase;letter-spacing:.04em}details{min-width:350px}.compact{display:grid;grid-template-columns:repeat(2,1fr);gap:5px;margin:8px 0}.compact button{grid-column:span 2}small,.hint,.permissions{color:#5f6b7a;font-size:13px}.tabs{display:flex;gap:10px}.tabs a{background:white;border:1px solid var(--line);padding:8px 12px;border-radius:6px;text-decoration:none;color:var(--blue);font-weight:700}pre{white-space:pre-wrap;overflow:auto;background:#111c2d;color:#d9ebff;padding:18px;border-radius:7px}.payslip{max-width:560px}.payslip div{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:10px 0}.payslip div:last-child{font-size:18px;color:var(--good)}@media(max-width:760px){header{flex-wrap:wrap;padding:14px 20px;gap:12px}nav{order:3;flex-basis:100%;overflow:auto}.cards,.grid-form{grid-template-columns:1fr}.wide{grid-column:span 1}.search{align-items:stretch;flex-direction:column}.search input{min-width:0}.user{display:none}}
"""


def main() -> None:
    host = os.getenv("EMS_HOST", "127.0.0.1")
    port = int(os.getenv("EMS_PORT", "8000"))
    print(f"{APP_NAME} is running at http://{host}:{port}")
    with make_server(host, port, EmployeeWebApp()) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
