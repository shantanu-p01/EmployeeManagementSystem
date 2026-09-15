# Enterprise Employee Management System — Web Edition

The desktop Tkinter interface has been replaced by a browser-based web UI.

## Run locally

```bash
python3 main.py
```

Open `http://127.0.0.1:8000` in your browser. No third-party packages are required.

On the first start, the application creates `employee_management.db` in the
current directory and creates the requested initial administrator: username
`admin`, password `admin`. Change this password before exposing the application
to anyone else.

## Security controls

- Server-side login sessions in `HttpOnly`, `SameSite=Strict` cookies.
- Per-form CSRF tokens, so a third-party site cannot submit actions as a user.
- Passwords are salted PBKDF2-SHA256 hashes (310,000 iterations; bcrypt is used
  automatically if installed).
- Password policy: 12+ characters and at least three character groups.
- Five failed logins lock the username for 15 minutes; errors stay generic.
- Every backend operation performs RBAC permission checks. Employee accounts
  can only see their own employee, attendance, leave, and payslip data.
- Security headers prevent framing, MIME sniffing, and browser caching.

For a deployment behind HTTPS, set `EMS_COOKIE_SECURE=1`. You can configure
the bind address and port with `EMS_HOST` and `EMS_PORT`; avoid binding to a
public interface without a production WSGI server, HTTPS reverse proxy, audit
logging, persistent database, and secret management.

## Current data storage

All application reads and writes use SQLite. Employee details, attendance,
leave requests, payroll records, accounts, login lockout state, and server-side
authentication sessions persist in `employee_management.db` across restarts.
The first database contains no dummy employees, attendance, leave, or payroll
records.
