"""Browser interface for the Employee Management System.

Run with ``python3 main.py`` and visit http://127.0.0.1:8000.  This module
uses only the Python standard library; the existing domain services continue
to own employee, attendance, payroll, reporting, and authentication logic.
Styled with modern, responsive, monochrome black-and-white Tailwind CSS via CDN.
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
            response = self._page(
                "Unexpected error",
                "<div class='bg-white rounded-2xl border border-zinc-200 p-8 text-center max-w-md mx-auto shadow-xs'>"
                "<h3 class='text-base font-bold text-zinc-900'>Something went wrong</h3>"
                "<p class='text-zinc-600 text-sm mt-1.5'>We could not complete that request. Please try again.</p>"
                "<a href='/' class='inline-block mt-4 bg-black hover:bg-zinc-800 text-white text-xs font-medium px-4 py-2 rounded-lg transition'>Return to Home</a>"
                "</div>",
                current,
                browser_session,
                status="500 Internal Server Error",
            )

        status, headers, body = response
        if not any(header.lower() == "content-type" for header, _ in headers):
            headers.append(("Content-Type", "text/html; charset=utf-8"))
        headers.extend([
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "same-origin"),
            (
                "Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
                "font-src 'self' https://fonts.gstatic.com data:; "
                "img-src 'self' data:; "
                "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            ),
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
            def nav_link(href: str, label: str, active: bool) -> str:
                if active:
                    return f"<a href='{href}' class='bg-zinc-800 text-white px-3 py-1.5 rounded-lg text-xs md:text-sm font-medium transition shadow-xs'>{label}</a>"
                return f"<a href='{href}' class='text-zinc-400 hover:text-white hover:bg-zinc-900 px-3 py-1.5 rounded-lg text-xs md:text-sm font-medium transition'>{label}</a>"

            links = [
                nav_link("/employees", "Employees", title == "Employees"),
                nav_link("/attendance", "Attendance & Leave", title == "Attendance & leave"),
                nav_link("/payroll", "Payroll", title == "Payroll & payslips"),
            ]
            if self.auth.has_permission(session.auth_token or "", Permission.VIEW_REPORTS):
                links.append(nav_link("/reports", "Reports", title == "Reports"))
            if self.auth.has_permission(session.auth_token or "", Permission.ADD_EMPLOYEE):
                links.append(nav_link("/users", "User Accounts", title == "User accounts"))

            nav = f"<nav class='hidden md:flex items-center gap-1.5 flex-1'>{''.join(links)}</nav>"

            role_badge_dropdown = (
                "bg-zinc-900 text-white border-zinc-700"
                if current.role == "Admin"
                else "bg-zinc-100 text-zinc-800 border-zinc-300"
            )

            # Custom profile dropdown: shows details and houses the sign-out button exclusively
            user = f"""
            <div class='relative' id='user-profile-menu'>
              <details class='group relative list-none'>
                <summary class='cursor-pointer flex items-center gap-2.5 px-3 py-1.5 rounded-xl hover:bg-zinc-900 border border-transparent hover:border-zinc-800 transition select-none list-none [&::-webkit-details-marker]:hidden'>
                  <span class='w-7 h-7 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-200 text-xs font-bold flex items-center justify-center'>{self._e(current.username[:1].upper())}</span>
                  <div class='text-left hidden sm:block'>
                    <div class='text-xs font-semibold text-zinc-200 leading-tight'>{self._e(current.username)}</div>
                    <div class='text-[10px] text-zinc-400 leading-tight capitalize'>{self._e(current.role)}</div>
                  </div>
                  <svg class='w-3.5 h-3.5 text-zinc-400 group-open:rotate-180 transition-transform duration-200 ml-0.5' fill='none' stroke='currentColor' viewBox='0 0 24 24'>
                    <path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/>
                  </svg>
                </summary>
                <div class='absolute right-0 top-full mt-2 w-60 bg-white text-zinc-900 rounded-2xl border border-zinc-200 shadow-xl py-2 z-50 divide-y divide-zinc-100'>
                  <div class='px-4 py-3'>
                    <p class='text-[10px] font-semibold text-zinc-400 uppercase tracking-wider'>Signed in as</p>
                    <p class='text-sm font-bold text-zinc-900 truncate mt-0.5'>{self._e(current.username)}</p>
                    <div class='flex items-center gap-2 mt-2'>
                      <span class='text-[10px] font-semibold px-2 py-0.5 rounded-full border {role_badge_dropdown}'>{self._e(current.role)}</span>
                      {f"<span class='text-[11px] text-zinc-500 font-mono'>{self._e(current.employee_id)}</span>" if current.employee_id else ""}
                    </div>
                  </div>
                  <div class='py-1'>
                    <form method='post' action='/logout' class='w-full'>
                      {self._csrf(session)}
                      <button class='w-full text-left flex items-center gap-2 px-4 py-2 text-xs font-medium text-red-600 hover:bg-red-50 hover:text-red-700 transition'>
                        <svg class='w-4 h-4' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1'/></svg>
                        Sign out
                      </button>
                    </form>
                  </div>
                </div>
              </details>
            </div>
            """
        else:
            user = "<a class='text-xs md:text-sm font-medium text-zinc-200 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 px-3.5 py-1.5 rounded-lg transition' href='/login'>Sign in</a>"

        # Notices / Flash alerts
        notices_list = []
        for item in database.flash_pop(session.session_id):
            is_success = item["kind"] == "success"
            bg_color = "bg-emerald-50 border-emerald-200 text-emerald-900" if is_success else "bg-rose-50 border-rose-200 text-rose-900"
            icon = (
                """<svg class='w-5 h-5 flex-shrink-0 text-emerald-600' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M5 13l4 4L19 7'/></svg>"""
                if is_success
                else """<svg class='w-5 h-5 flex-shrink-0 text-rose-600' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z'/></svg>"""
            )
            notices_list.append(
                f"<div class='mb-6 p-4 rounded-xl border flex items-center gap-3 text-sm font-medium shadow-xs {bg_color}'>"
                f"{icon}<span>{self._e(item['message'])}</span></div>"
            )
        notices = "".join(notices_list)

        # Mobile navigation links
        mobile_nav = ""
        if current:
            mobile_links = [
                f"<a href='/employees' class='text-xs font-medium text-zinc-300 hover:text-white px-2 py-1'>Employees</a>",
                f"<a href='/attendance' class='text-xs font-medium text-zinc-300 hover:text-white px-2 py-1'>Attendance</a>",
                f"<a href='/payroll' class='text-xs font-medium text-zinc-300 hover:text-white px-2 py-1'>Payroll</a>",
            ]
            if self.auth.has_permission(session.auth_token or "", Permission.VIEW_REPORTS):
                mobile_links.append("<a href='/reports' class='text-xs font-medium text-zinc-300 hover:text-white px-2 py-1'>Reports</a>")
            if self.auth.has_permission(session.auth_token or "", Permission.ADD_EMPLOYEE):
                mobile_links.append("<a href='/users' class='text-xs font-medium text-zinc-300 hover:text-white px-2 py-1'>Users</a>")
            mobile_nav = f"<div class='flex md:hidden items-center gap-2 overflow-x-auto py-2 border-t border-zinc-800 mt-2.5 w-full'>{''.join(mobile_links)}</div>"

        page = f"""<!doctype html>
<html lang='en' class='h-full bg-zinc-50'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{self._e(title)} · {APP_NAME}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {{
      theme: {{
        extend: {{
          fontFamily: {{
            sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          }},
        }}
      }}
    }}
  </script>
  <link rel='stylesheet' href='/assets/app.css'>
</head>
<body class='min-h-full flex flex-col font-sans text-zinc-900 antialiased bg-zinc-50'>
  <header class='sticky top-0 z-40 bg-black border-b border-zinc-800 text-white shadow-xs'>
    <div class='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8'>
      <div class='flex items-center justify-between h-16 gap-4'>
        <div class='flex items-center gap-4 md:gap-8'>
          <a href='/' class='flex items-center gap-2 text-base md:text-lg font-bold text-white tracking-tight hover:opacity-95 transition'>
            <span class='w-7 h-7 md:w-8 md:h-8 rounded-lg bg-white text-black flex items-center justify-center text-xs md:text-sm font-black shadow-inner'>EMS</span>
            <span>{APP_NAME}</span>
          </a>
          {nav}
        </div>
        <div class='flex items-center gap-3'>
          {user}
        </div>
      </div>
      {mobile_nav}
    </div>
  </header>

  <main class='flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8'>
    <div class='border-b border-zinc-200 pb-5 mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2'>
      <h1 class='text-2xl font-bold tracking-tight text-zinc-900'>{self._e(title)}</h1>
    </div>
    {notices}
    {content}
  </main>

  <footer class='border-t border-zinc-200 bg-white py-6 mt-12 text-center text-xs text-zinc-500'>
    <div class='max-w-7xl mx-auto px-4'>
      <p>{APP_NAME} &middot; Enterprise Human Resources &amp; Workforce Management Platform &middot; All records secured via server-side RBAC.</p>
    </div>
  </footer>

  <script>
    document.addEventListener('click', function(e) {{
      const menu = document.querySelector('#user-profile-menu details');
      if (menu && menu.open && !menu.contains(e.target)) {{
        menu.removeAttribute('open');
      }}
    }});
  </script>
</body>
</html>"""
        return status, [], page

    def _csrf(self, session: BrowserSession) -> str:
        return f"<input type='hidden' name='csrf' value='{self._e(session.csrf_token)}'>"

    def _form_error(self, session: BrowserSession):
        self._flash(session, "error", "The form could not be verified. Refresh the page and try again.")
        return self._redirect("/", session)

    @staticmethod
    def _table(headers: List[str], rows: List[List[object]]) -> str:
        head = "".join(f"<th class='px-4 py-3 text-left text-xs font-semibold text-zinc-500 uppercase tracking-wider'>{html.escape(header)}</th>" for header in headers)
        body = "".join(
            "<tr class='hover:bg-zinc-50/70 transition-colors'>"
            + "".join(
                f"<td class='px-4 py-3.5 text-zinc-700 whitespace-nowrap'>{cell if isinstance(cell, str) and cell.startswith('<') else html.escape(str(cell))}</td>"
                for cell in row
            )
            + "</tr>"
            for row in rows
        )
        empty_row = f"<tr><td colspan='{len(headers)}' class='px-6 py-10 text-center text-zinc-400 italic text-sm'>No records found.</td></tr>"
        return f"""
        <div class='overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-xs'>
          <div class='overflow-x-auto'>
            <table class='min-w-full divide-y divide-zinc-200 text-sm'>
              <thead class='bg-zinc-50/80'>
                <tr>{head}</tr>
              </thead>
              <tbody class='divide-y divide-zinc-100 bg-white'>
                {body or empty_row}
              </tbody>
            </table>
          </div>
        </div>
        """

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
        return self._page(
            "Page not found",
            "<div class='bg-white rounded-2xl border border-zinc-200 p-8 text-center max-w-md mx-auto shadow-xs'>"
            "<h3 class='text-lg font-bold text-zinc-900'>404 &middot; Not Found</h3>"
            "<p class='text-zinc-600 text-sm mt-1.5'>The requested page does not exist.</p>"
            "<a href='/' class='inline-block mt-4 bg-black text-white text-xs font-medium px-4 py-2 rounded-lg'>Go Home</a>"
            "</div>",
            current,
            session,
            status="404 Not Found",
        )

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
        content = f"""
        <div class='min-h-[calc(100vh-220px)] flex items-center justify-center py-6'>
          <div class='w-full max-w-md bg-white rounded-2xl border border-zinc-200 p-8 shadow-sm'>
            <div class='text-center mb-6'>
              <div class='inline-flex items-center justify-center w-12 h-12 rounded-xl bg-black text-white font-black text-lg mb-3 shadow-sm'>EMS</div>
              <h2 class='text-xl font-bold text-zinc-900 tracking-tight'>Sign in to your workspace</h2>
              <p class='text-xs text-zinc-500 mt-1'>Secure access to employee, attendance, and payroll operations.</p>
            </div>
            <form method='post' class='space-y-4'>
              {self._csrf(session)}
              <div>
                <label class='block text-xs font-semibold text-zinc-700 uppercase tracking-wider mb-1.5'>Username</label>
                <input name='username' autocomplete='username' required maxlength='50' class='w-full px-3.5 py-2.5 rounded-lg border border-zinc-300 text-zinc-900 placeholder-zinc-400 focus:ring-2 focus:ring-black focus:border-black focus:outline-none transition text-sm' placeholder='e.g. admin'>
              </div>
              <div>
                <label class='block text-xs font-semibold text-zinc-700 uppercase tracking-wider mb-1.5'>Password</label>
                <input name='password' type='password' autocomplete='current-password' required class='w-full px-3.5 py-2.5 rounded-lg border border-zinc-300 text-zinc-900 placeholder-zinc-400 focus:ring-2 focus:ring-black focus:border-black focus:outline-none transition text-sm' placeholder='••••••••'>
              </div>
              <button class='w-full bg-black hover:bg-zinc-800 text-white font-medium py-2.5 px-4 rounded-lg shadow-sm transition text-sm'>Sign in</button>
            </form>
            <div class='mt-6 pt-5 border-t border-zinc-100 flex items-start gap-2.5 text-xs text-zinc-500 bg-zinc-50 p-3.5 rounded-xl border border-zinc-200/60'>
              <svg class='w-4 h-4 text-zinc-400 flex-shrink-0 mt-0.5' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z'/></svg>
              <div>
                <p class='font-semibold text-zinc-700'>Default Seed Credentials</p>
                <p class='mt-0.5'>Administrator: <code class='font-mono font-bold text-zinc-900'>admin</code> / <code class='font-mono font-bold text-zinc-900'>admin</code></p>
                <p class='mt-0.5 text-zinc-400'>5 failed attempts locks sign-in for 15 minutes. Sessions expire after 30 minutes.</p>
              </div>
            </div>
          </div>
        </div>
        """
        return self._page("Sign in", content, None, session)

    def _dashboard(self, current, session: BrowserSession):
        records = employees.get_all_employees()
        counts = [
            ("Total Employees", len(records), "Active workforce records in directory", "bg-zinc-100 text-zinc-800 border-zinc-200"),
            ("Attendance Entries", len(self.attendance.get_all_attendance()), "Recorded daily presence / absence logs", "bg-zinc-100 text-zinc-800 border-zinc-200"),
            ("Leave Requests", len(self.leaves.get_leave_requests()), "Pending, approved, & historic requests", "bg-zinc-100 text-zinc-800 border-zinc-200"),
        ]
        cards = "".join(
            f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs hover:border-zinc-300 transition'>
              <div class='flex items-center justify-between'>
                <span class='text-xs font-semibold uppercase tracking-wider text-zinc-500'>{label}</span>
                <span class='text-[10px] font-semibold px-2 py-0.5 rounded-full border {badge_style}'>Live Database</span>
              </div>
              <div class='text-3xl font-extrabold text-zinc-900 tracking-tight mt-3'>{count}</div>
              <p class='text-xs text-zinc-500 mt-1.5'>{sub}</p>
            </div>
            """
            for label, count, sub, badge_style in counts
        )

        perm_tags = "".join(
            f"<span class='inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-zinc-50 text-zinc-800 border border-zinc-200'><svg class='w-3.5 h-3.5 text-zinc-700' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M5 13l4 4L19 7'/></svg>{self._e(p)}</span>"
            for p in current.permissions
        ) or "<span class='text-xs text-zinc-400 italic'>No specific permissions assigned.</span>"

        role_badge = "bg-zinc-900 text-white border-zinc-700" if current.role == "Admin" else "bg-zinc-100 text-zinc-800 border-zinc-300"

        content = f"""
        <div class='space-y-8'>
          <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4'>
            <div>
              <h2 class='text-lg font-bold text-zinc-900 tracking-tight'>Welcome back, {self._e(current.username)}!</h2>
              <p class='text-xs text-zinc-500 mt-1'>Logged in as <span class='font-semibold text-zinc-800'>{self._e(current.role)}</span>. All requests are protected by server-side RBAC validation and strict CSRF tokens.</p>
            </div>
            <div class='flex items-center gap-2'>
              <a href='/employees' class='bg-black hover:bg-zinc-800 text-white text-xs font-medium px-4 py-2 rounded-lg transition shadow-xs'>Employee Directory</a>
              <a href='/attendance' class='bg-white hover:bg-zinc-50 text-zinc-800 border border-zinc-300 text-xs font-medium px-4 py-2 rounded-lg transition shadow-xs'>Attendance & Leave</a>
            </div>
          </div>

          <div class='grid grid-cols-1 md:grid-cols-3 gap-5'>
            {cards}
          </div>

          <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs'>
            <div class='flex items-center justify-between pb-4 border-b border-zinc-100'>
              <div>
                <h3 class='text-sm font-bold text-zinc-900 uppercase tracking-wider'>Your Access & Permissions</h3>
                <p class='text-xs text-zinc-500 mt-0.5'>Active role security profile evaluated by server-side authorizer.</p>
              </div>
              <span class='px-3 py-1 rounded-full text-xs font-semibold border {role_badge}'>{self._e(current.role)} Role</span>
            </div>
            <div class='mt-4 flex flex-wrap gap-2'>
              {perm_tags}
            </div>
          </div>
        </div>
        """
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
                    record = employees.add_employee(
                        name,
                        self._value(request, "email"),
                        self._value(request, "phone"),
                        self._value(request, "department"),
                        self._value(request, "designation"),
                        emp_id or None,
                    )
                    return self._redirect("/employees", session, f"Employee {record['id']} was added successfully.")
                if action == "update":
                    if (blocked := self._require(session, current, Permission.UPDATE_EMPLOYEE)):
                        return blocked
                    if not employees.update_employee(
                        emp_id,
                        self._value(request, "name"),
                        self._value(request, "email"),
                        self._value(request, "phone"),
                        self._value(request, "department"),
                        self._value(request, "designation"),
                    ):
                        raise ValueError("Employee was not found.")
                    return self._redirect("/employees", session, "Employee details were updated.")
                if action == "delete":
                    if (blocked := self._require(session, current, Permission.DELETE_EMPLOYEE)):
                        return blocked
                    if not employees.delete_employee(emp_id):
                        raise ValueError("Employee was not found.")
                    return self._redirect("/employees", session, "Employee record was removed.")
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
                action = f"""
                <details class='relative inline-block text-left'>
                  <summary class='cursor-pointer inline-flex items-center gap-1 text-xs font-semibold text-zinc-800 bg-zinc-100 hover:bg-zinc-200 px-2.5 py-1 rounded-md transition select-none'>
                    Edit &middot; Actions
                  </summary>
                  <div class='absolute right-0 top-full mt-2 w-72 bg-white rounded-xl border border-zinc-200 shadow-xl p-4 z-20'>
                    <form method='post' class='space-y-2.5'>
                      {self._csrf(session)}
                      <input name='action' value='update' type='hidden'>
                      <input name='employee_id' value='{self._e(item['id'])}' type='hidden'>
                      <div>
                        <label class='block text-[11px] font-semibold text-zinc-600 mb-0.5'>Full Name</label>
                        <input name='name' value='{self._e(item['name'])}' required class='w-full px-2.5 py-1.5 text-xs rounded-md border border-zinc-300 focus:ring-1 focus:ring-black focus:outline-none'>
                      </div>
                      <div>
                        <label class='block text-[11px] font-semibold text-zinc-600 mb-0.5'>Email</label>
                        <input name='email' value='{self._e(item['email'])}' class='w-full px-2.5 py-1.5 text-xs rounded-md border border-zinc-300 focus:ring-1 focus:ring-black focus:outline-none'>
                      </div>
                      <div>
                        <label class='block text-[11px] font-semibold text-zinc-600 mb-0.5'>Phone</label>
                        <input name='phone' value='{self._e(item['phone'])}' class='w-full px-2.5 py-1.5 text-xs rounded-md border border-zinc-300 focus:ring-1 focus:ring-black focus:outline-none'>
                      </div>
                      <div>
                        <label class='block text-[11px] font-semibold text-zinc-600 mb-0.5'>Department</label>
                        <input name='department' value='{self._e(item['department'])}' class='w-full px-2.5 py-1.5 text-xs rounded-md border border-zinc-300 focus:ring-1 focus:ring-black focus:outline-none'>
                      </div>
                      <div>
                        <label class='block text-[11px] font-semibold text-zinc-600 mb-0.5'>Designation</label>
                        <input name='designation' value='{self._e(item['designation'])}' class='w-full px-2.5 py-1.5 text-xs rounded-md border border-zinc-300 focus:ring-1 focus:ring-black focus:outline-none'>
                      </div>
                      <div class='flex items-center justify-between pt-2 border-t border-zinc-100'>
                        <button class='bg-black hover:bg-zinc-800 text-white text-xs font-medium px-3 py-1.5 rounded-md transition'>Save Updates</button>
                      </div>
                    </form>
                    <form method='post' class='mt-2 pt-2 border-t border-zinc-100 flex justify-end'>
                      {self._csrf(session)}
                      <input name='action' value='delete' type='hidden'>
                      <input name='employee_id' value='{self._e(item['id'])}' type='hidden'>
                      <button class='text-xs font-medium text-rose-600 hover:text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 px-2.5 py-1 rounded-md transition' onclick=\"return confirm('Permanently remove employee {self._e(item['id'])}?')\">Delete Record</button>
                    </form>
                  </div>
                </details>
                """
            emp_badge = f"<span class='font-mono text-xs font-semibold px-2 py-0.5 rounded bg-zinc-100 text-zinc-800 border border-zinc-200'>{self._e(item['id'])}</span>"
            dept_badge = f"<span class='inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-zinc-100 text-zinc-800 border border-zinc-200'>{self._e(item['department'])}</span>"
            rows.append([emp_badge, item["name"], item["email"] or "—", item["phone"] or "—", dept_badge, item["designation"], action])

        add_form = ""
        if is_admin:
            add_form = f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs mb-8'>
              <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-4 flex items-center gap-2'>
                <span class='w-2 h-2 rounded-full bg-black'></span>
                Add New Employee
              </h2>
              <form method='post' class='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4'>
                {self._csrf(session)}
                <input type='hidden' name='action' value='add'>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Employee ID</label>
                  <input name='employee_id' placeholder='Auto-generated if blank' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Full Name *</label>
                  <input name='name' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none' placeholder='e.g. Ananya Sharma'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Email Address</label>
                  <input name='email' type='email' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none' placeholder='name@company.com'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Phone Number</label>
                  <input name='phone' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none' placeholder='+91 98765 43210'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Department *</label>
                  <input name='department' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none' placeholder='e.g. Engineering'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Designation *</label>
                  <input name='designation' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none' placeholder='e.g. Senior Software Engineer'>
                </div>
                <div class='sm:col-span-2 lg:col-span-3 pt-2'>
                  <button class='bg-black hover:bg-zinc-800 text-white font-medium px-5 py-2.5 rounded-lg text-sm transition shadow-xs'>Save Employee Record</button>
                </div>
              </form>
            </div>
            """

        search_bar = f"""
        <div class='flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 mb-6'>
          <form class='flex items-center gap-2 max-w-md w-full' method='get'>
            <div class='relative flex-1'>
              <input name='q' value='{self._e(keyword)}' placeholder='Search by name, ID, department...' class='w-full pl-9 pr-3 py-2 rounded-lg border border-zinc-300 text-sm focus:ring-2 focus:ring-black focus:outline-none'>
              <svg class='w-4 h-4 text-zinc-400 absolute left-3 top-2.5' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'/></svg>
            </div>
            <button class='bg-black hover:bg-zinc-800 text-white px-4 py-2 rounded-lg text-sm font-medium transition'>Search</button>
            {f"<a href='/employees' class='text-xs text-zinc-500 hover:text-zinc-800 underline px-2'>Reset</a>" if keyword else ""}
          </form>
          <div class='text-xs font-medium text-zinc-500'>Showing {len(data)} employee record(s)</div>
        </div>
        """

        content = f"{search_bar}{add_form}<div class='space-y-3'><h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider'>Directory Listing</h2>{self._table(['ID', 'Name', 'Email', 'Phone', 'Department', 'Designation', 'Actions'], rows)}</div>"
        return self._page("Employees", content, current, session)

    # ------------------------ Attendance and leave --------------------------
    def _employee_options(self, selected: Optional[str] = None) -> str:
        return "".join(
            f"<option value='{self._e(item['id'])}'{' selected' if item['id'] == selected else ''}>{self._e(item['id'])} &mdash; {self._e(item['name'])}</option>"
            for item in employees.get_all_employees()
        )

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
                    self.attendance.mark_attendance(
                        employee_id,
                        datetime.strptime(self._value(request, "attendance_date"), "%Y-%m-%d").date(),
                        self._value(request, "status"),
                    )
                    return self._redirect("/attendance", session, "Attendance entry recorded successfully.")
                if action == "leave":
                    if (blocked := self._require(session, current, Permission.APPLY_LEAVE)):
                        return blocked
                    employee_id = current.employee_id or ""
                    if not employees.get_employee_by_id(employee_id):
                        raise ValueError("Your account must be linked to a valid employee ID before applying for leave.")
                    self.leaves.apply_leave(
                        employee_id,
                        datetime.strptime(self._value(request, "start_date"), "%Y-%m-%d").date(),
                        datetime.strptime(self._value(request, "end_date"), "%Y-%m-%d").date(),
                        self._value(request, "reason"),
                    )
                    return self._redirect("/attendance", session, "Leave application submitted.")
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

        attendance_rows = []
        for record in attendance_data:
            st = record.status
            st_badge = (
                "<span class='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200'>Present</span>"
                if st == "Present"
                else "<span class='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200'>Absent</span>"
            )
            attendance_rows.append([
                f"<span class='font-mono text-xs font-medium text-zinc-700'>{record.employee_id}</span>",
                self._employee_name(record.employee_id),
                str(record.date),
                st_badge,
            ])

        leave_rows = []
        for record in leave_data:
            actions = ""
            if is_admin and record.status == "Pending":
                actions = f"""
                <div class='flex items-center gap-1.5'>
                  <form method='post' class='inline'>
                    {self._csrf(session)}
                    <input type='hidden' name='action' value='approve'>
                    <input type='hidden' name='request_id' value='{self._e(record.request_id)}'>
                    <button class='bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium px-2.5 py-1 rounded-md transition shadow-xs'>Approve</button>
                  </form>
                  <form method='post' class='inline'>
                    {self._csrf(session)}
                    <input type='hidden' name='action' value='reject'>
                    <input type='hidden' name='request_id' value='{self._e(record.request_id)}'>
                    <button class='bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium px-2.5 py-1 rounded-md transition shadow-xs'>Reject</button>
                  </form>
                </div>
                """
            st = record.status
            if st == "Approved":
                st_badge = "<span class='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200'>Approved</span>"
            elif st == "Rejected":
                st_badge = "<span class='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200'>Rejected</span>"
            else:
                st_badge = "<span class='inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-200'>Pending</span>"

            leave_rows.append([
                f"<span class='font-mono text-xs font-semibold text-zinc-700'>{record.request_id}</span>",
                self._employee_name(record.employee_id),
                str(record.start_date),
                str(record.end_date),
                record.reason,
                st_badge,
                actions,
            ])

        mark_form = ""
        if self.auth.has_permission(session.auth_token or "", Permission.MARK_ATTENDANCE):
            select = (
                f"<select name='employee_id' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 bg-white focus:ring-2 focus:ring-black focus:outline-none'>{self._employee_options()}</select>"
                if is_admin
                else f"<div class='px-3 py-2 bg-zinc-50 border border-zinc-200 rounded-lg text-sm font-medium text-zinc-800'>{self._e(current.employee_id or 'Unlinked account')}</div>"
            )
            mark_form = f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs'>
              <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-4 flex items-center gap-2'>
                <span class='w-2 h-2 rounded-full bg-black'></span>
                Record Attendance
              </h2>
              <form method='post' class='space-y-4'>
                {self._csrf(session)}
                <input type='hidden' name='action' value='mark'>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Employee</label>
                  {select}
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Date</label>
                  <input name='attendance_date' type='date' value='{date.today().isoformat()}' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Status</label>
                  <select name='status' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 bg-white focus:ring-2 focus:ring-black focus:outline-none'>
                    <option value='Present'>Present</option>
                    <option value='Absent'>Absent</option>
                  </select>
                </div>
                <button class='w-full bg-black hover:bg-zinc-800 text-white font-medium py-2.5 px-4 rounded-lg text-sm transition shadow-xs'>Mark Attendance</button>
              </form>
            </div>
            """

        leave_form = ""
        if self.auth.has_permission(session.auth_token or "", Permission.APPLY_LEAVE):
            leave_form = f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs'>
              <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-4 flex items-center gap-2'>
                <span class='w-2 h-2 rounded-full bg-black'></span>
                Apply for Leave
              </h2>
              <form method='post' class='space-y-4'>
                {self._csrf(session)}
                <input type='hidden' name='action' value='leave'>
                <div class='grid grid-cols-2 gap-3'>
                  <div>
                    <label class='block text-xs font-semibold text-zinc-700 mb-1'>Start Date</label>
                    <input name='start_date' type='date' value='{date.today().isoformat()}' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                  </div>
                  <div>
                    <label class='block text-xs font-semibold text-zinc-700 mb-1'>End Date</label>
                    <input name='end_date' type='date' value='{date.today().isoformat()}' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                  </div>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Reason for Leave</label>
                  <input name='reason' maxlength='300' required placeholder='e.g. Medical appointment, family event' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <button class='w-full bg-black hover:bg-zinc-800 text-white font-medium py-2.5 px-4 rounded-lg text-sm transition shadow-xs'>Submit Leave Request</button>
              </form>
            </div>
            """

        content = f"""
        <div class='space-y-8'>
          <div class='grid grid-cols-1 lg:grid-cols-2 gap-8'>
            {mark_form}
            {leave_form}
          </div>
          <div class='space-y-3'>
            <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider'>Attendance History</h2>
            {self._table(['Employee ID', 'Employee Name', 'Date', 'Status'], attendance_rows)}
          </div>
          <div class='space-y-3'>
            <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider'>Leave Applications & Approvals</h2>
            {self._table(['Request ID', 'Employee', 'Start Date', 'End Date', 'Reason', 'Status', 'Actions'], leave_rows)}
          </div>
        </div>
        """
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
                payslip, _ = PayslipGenerator.generate_payslip(
                    employee_id,
                    person["name"],
                    self._value(request, "pay_period"),
                    float(self._value(request, "basic_salary")),
                    float(self._value(request, "allowances") or "0"),
                    float(self._value(request, "deductions") or "0"),
                    currency="INR",
                )
                database.payroll_upsert(employee_id, payslip.pay_period, payslip.basic_salary, payslip.allowances, payslip.deductions)
                result = self._payslip_html(payslip) + self._payslip_download_link(payslip)
                self._flash(session, "success", "Payslip generated and payroll record recorded successfully.")
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
                    payslip, _ = PayslipGenerator.generate_payslip(
                        requested,
                        person["name"],
                        record["pay_period"],
                        record["basic_salary"],
                        record["allowances"],
                        record["deductions"],
                        currency="INR",
                    )
                    result = self._payslip_html(payslip) + self._payslip_download_link(payslip)
                except PayrollError:
                    self._flash(session, "error", "No payslip was found for that pay period.")

        processor = ""
        if can_process:
            processor = f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs mb-8'>
              <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-4 flex items-center gap-2'>
                <span class='w-2 h-2 rounded-full bg-black'></span>
                Generate &amp; Record Payslip
              </h2>
              <form method='post' class='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4'>
                {self._csrf(session)}
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Select Employee</label>
                  <select name='employee_id' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 bg-white focus:ring-2 focus:ring-black focus:outline-none'>{self._employee_options()}</select>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Pay Period (YYYY-MM)</label>
                  <input name='pay_period' value='{date.today().strftime('%Y-%m')}' pattern='[0-9]{{4}}-[0-9]{{2}}' required class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Basic Salary (₹)</label>
                  <input name='basic_salary' type='number' min='0' step='.01' required placeholder='65000' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Allowances (₹)</label>
                  <input name='allowances' type='number' min='0' step='.01' value='0' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div>
                  <label class='block text-xs font-semibold text-zinc-700 mb-1'>Deductions (₹)</label>
                  <input name='deductions' type='number' min='0' step='.01' value='0' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <div class='sm:col-span-2 lg:col-span-1 flex items-end'>
                  <button class='w-full bg-black hover:bg-zinc-800 text-white font-medium py-2.5 px-4 rounded-lg text-sm transition shadow-xs'>Compute &amp; Save</button>
                </div>
              </form>
            </div>
            """

        own = ""
        if can_view:
            own = f"""
            <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs mb-8'>
              <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-3'>View My Digital Payslip</h2>
              <form method='get' class='flex flex-col sm:flex-row items-stretch sm:items-center gap-3'>
                <input type='hidden' name='employee_id' value='{self._e(current.employee_id or '')}'>
                <div class='flex items-center gap-2'>
                  <label class='text-xs font-semibold text-zinc-700'>Pay Period:</label>
                  <input name='period' value='{date.today().strftime('%Y-%m')}' pattern='[0-9]{{4}}-[0-9]{{2}}' class='px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
                </div>
                <button class='bg-black hover:bg-zinc-800 text-white text-sm font-medium px-4 py-2 rounded-lg transition'>Fetch Statement</button>
              </form>
            </div>
            """
        content = f"{processor}{own}{result}"
        return self._page("Payroll & payslips", content, current, session)

    def _payslip_html(self, payslip) -> str:
        values = [
            ("Employee Name", payslip.employee_name),
            ("Employee ID", payslip.employee_id),
            ("Pay Period", payslip.pay_period),
            ("Basic Salary", f"₹ {payslip.basic_salary:,.2f}"),
            ("Allowances", f"₹ {payslip.allowances:,.2f}"),
            ("Gross Salary", f"₹ {payslip.gross_salary:,.2f}"),
            ("Deductions", f"₹ {payslip.deductions:,.2f}"),
        ]
        items_html = "".join(
            f"<div class='flex justify-between py-2 border-b border-zinc-100 text-sm'><span class='text-zinc-500'>{self._e(k)}</span><span class='font-medium text-zinc-800'>{self._e(v)}</span></div>"
            for k, v in values
        )
        return f"""
        <div class='bg-white rounded-2xl border border-zinc-200 shadow-xs p-6 max-w-lg mb-6'>
          <div class='flex items-center justify-between pb-4 border-b border-zinc-200'>
            <div>
              <span class='text-xs font-semibold text-zinc-400 uppercase tracking-wider'>Official Pay Statement</span>
              <h3 class='text-lg font-bold text-zinc-900'>Employee Payslip</h3>
            </div>
            <span class='px-2.5 py-1 rounded-full text-xs font-semibold bg-zinc-100 text-zinc-800 border border-zinc-200'>{self._e(payslip.pay_period)}</span>
          </div>
          <div class='mt-4 divide-y divide-zinc-100'>
            {items_html}
          </div>
          <div class='mt-4 pt-3 border-t border-zinc-200 flex justify-between items-center'>
            <span class='text-base font-bold text-zinc-900'>Net Payable Salary</span>
            <span class='text-xl font-black text-black'>₹ {payslip.net_salary:,.2f}</span>
          </div>
        </div>
        """

    def _payslip_download_link(self, payslip) -> str:
        return f"""
        <div class='mb-8'>
          <a class='inline-flex items-center gap-2 bg-black hover:bg-zinc-800 text-white text-xs font-semibold px-4 py-2.5 rounded-lg transition shadow-xs' href='/download?type=payslip&amp;employee_id={self._e(payslip.employee_id)}&amp;period={self._e(payslip.pay_period)}'>
            <svg class='w-4 h-4' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4'/></svg>
            Download Payslip Document (.txt)
          </a>
        </div>
        """

    # -------------------------- Reports and users ---------------------------
    def _reports(self, request: dict, session: BrowserSession, current):
        denied = self._require(session, current, Permission.VIEW_REPORTS)
        if denied:
            return denied
        report_type = request["query"].get("type", ["headcount"])[0]
        try:
            if report_type == "attendance":
                text = ReportService.format_attendance_report(ReportService.generate_attendance_report(self._attendance_report_records()))
                title = "Monthly Attendance Analytics"
            elif report_type == "salary":
                text = ReportService.format_salary_report(ReportService.generate_salary_report(database.payroll_list(), currency="INR"))
                title = "Financial Salary Analytics"
            else:
                text = ReportService.format_employee_report(ReportService.generate_employee_report(employees.get_all_employees()))
                title = "Headcount & Workforce Demographics"
        except PayrollError as exc:
            text, title = str(exc), "Report unavailable"

        controls = f"""
        <div class='flex flex-wrap items-center justify-between gap-3 mb-6'>
          <div class='flex flex-wrap gap-2'>
            <a href='/reports?type=headcount' class='px-3.5 py-1.5 rounded-lg text-xs font-semibold transition {'bg-black text-white shadow-xs' if report_type == 'headcount' else 'bg-white text-zinc-700 border border-zinc-300 hover:bg-zinc-50'}'>👥 Headcount & Demographics</a>
            <a href='/reports?type=attendance' class='px-3.5 py-1.5 rounded-lg text-xs font-semibold transition {'bg-black text-white shadow-xs' if report_type == 'attendance' else 'bg-white text-zinc-700 border border-zinc-300 hover:bg-zinc-50'}'>🗓️ Attendance Analytics</a>
            <a href='/reports?type=salary' class='px-3.5 py-1.5 rounded-lg text-xs font-semibold transition {'bg-black text-white shadow-xs' if report_type == 'salary' else 'bg-white text-zinc-700 border border-zinc-300 hover:bg-zinc-50'}'>💵 Financial Salary Analytics</a>
          </div>
          <a href='/download?type=report&amp;report={self._e(report_type)}' class='inline-flex items-center gap-1.5 bg-white hover:bg-zinc-50 border border-zinc-300 text-zinc-700 text-xs font-semibold px-3.5 py-1.5 rounded-lg transition shadow-xs'>
            <svg class='w-3.5 h-3.5 text-zinc-500' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4'/></svg>
            Download Report (.txt)
          </a>
        </div>
        """
        viewer = f"""
        <div class='bg-black rounded-2xl border border-zinc-800 p-6 shadow-lg'>
          <div class='flex items-center justify-between pb-3 mb-4 border-b border-zinc-800 text-xs text-zinc-400'>
            <span class='font-semibold text-zinc-200 flex items-center gap-2'>
              <span class='w-2 h-2 rounded-full bg-zinc-400'></span>
              {self._e(title)}
            </span>
            <span>Generated live from SQLite database</span>
          </div>
          <pre class='text-zinc-100 font-mono text-xs md:text-sm leading-relaxed overflow-x-auto'>{self._e(text)}</pre>
        </div>
        """
        return self._page("Reports", f"{controls}{viewer}", current, session)

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
                _, text = PayslipGenerator.generate_payslip(
                    employee_id,
                    person["name"],
                    period,
                    record["basic_salary"],
                    record["allowances"],
                    record["deductions"],
                    currency="INR",
                )
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
                # Browser users are created as Employee accounts
                user = self.auth.register_user(self._value(request, "username"), self._value(request, "password"), Role.EMPLOYEE, employee_id)
                return self._redirect("/users", session, f"Account for {user.username} was created.")
            except (AuthError, ValueError) as exc:
                return self._redirect("/users", session, str(exc), "error")

        rows = []
        for user in self.auth.list_all_users():
            status_badge = (
                "<span class='inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200'>Active</span>"
                if user.is_active
                else "<span class='inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-zinc-100 text-zinc-500 border border-zinc-200'>Disabled</span>"
            )
            role_badge = (
                "<span class='inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-zinc-900 text-white border border-zinc-700'>Admin</span>"
                if user.role == "Admin"
                else "<span class='inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-zinc-100 text-zinc-800 border border-zinc-300'>Employee</span>"
            )
            rows.append([
                f"<span class='font-medium text-zinc-900'>{user.username}</span>",
                role_badge,
                f"<span class='font-mono text-xs text-zinc-700'>{user.employee_id or '—'}</span>",
                status_badge,
            ])

        form = f"""
        <div class='bg-white p-6 rounded-2xl border border-zinc-200 shadow-xs mb-8'>
          <h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider mb-4 flex items-center gap-2'>
            <span class='w-2 h-2 rounded-full bg-black'></span>
            Create Employee Account
          </h2>
          <form method='post' class='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4'>
            {self._csrf(session)}
            <div>
              <label class='block text-xs font-semibold text-zinc-700 mb-1'>Link to Employee</label>
              <select name='employee_id' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 bg-white focus:ring-2 focus:ring-black focus:outline-none'>{self._employee_options()}</select>
            </div>
            <div>
              <label class='block text-xs font-semibold text-zinc-700 mb-1'>Username *</label>
              <input name='username' pattern='[A-Za-z0-9_.-]{{3,50}}' required placeholder='e.g. asharma' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
            </div>
            <div>
              <label class='block text-xs font-semibold text-zinc-700 mb-1'>Temporary Password *</label>
              <input name='password' type='password' minlength='12' required placeholder='12+ chars, mixed' class='w-full px-3 py-2 text-sm rounded-lg border border-zinc-300 focus:ring-2 focus:ring-black focus:outline-none'>
            </div>
            <div class='sm:col-span-2 lg:col-span-3 flex items-center justify-between pt-2'>
              <p class='text-xs text-zinc-500'>Password policy: 12+ characters and at least three of: lowercase, uppercase, number, symbol.</p>
              <button class='bg-black hover:bg-zinc-800 text-white font-medium px-5 py-2.5 rounded-lg text-sm transition shadow-xs'>Create Account</button>
            </div>
          </form>
        </div>
        """
        content = f"{form}<div class='space-y-3'><h2 class='text-sm font-bold text-zinc-900 uppercase tracking-wider'>User Accounts</h2>{self._table(['Username', 'Role', 'Linked Employee', 'Status'], rows)}</div>"
        return self._page("User accounts", content, current, session)

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
/* Enhanced companion utilities for Tailwind CDN */
html {
  scroll-behavior: smooth;
}
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: #d4d4d8;
  border-radius: 9999px;
}
::-webkit-scrollbar-thumb:hover {
  background: #a1a1aa;
}
details > summary::-webkit-details-marker {
  display: none;
}
details > summary::after {
  content: "";
}
pre {
  tab-size: 2;
}
@media print {
  header, footer, nav, button {
    display: none !important;
  }
  body {
    background: white !important;
  }
}
"""


def main() -> None:
    host = os.getenv("EMS_HOST", "127.0.0.1")
    port = int(os.getenv("EMS_PORT", "8000"))
    print(f"{APP_NAME} is running at http://{host}:{port}")
    with make_server(host, port, EmployeeWebApp()) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
