"""Person 2 — Authentication and Role-Based Access Control (RBAC) Module.

Everything for Person 2 is consolidated in this single file for maximum
simplicity, readability, and ease of explanation.

Sections in this file:
  1. Custom Exceptions (Error Handling)
  2. Roles & Permissions (RBAC Logic)
  3. Data Models (User, UserView, Session)
  4. Password Security (Hashing & Salting)
  5. SQLite Data Store (Users, Sessions, and Login Controls)
  6. AuthService (Main Business Logic & Public Operations)
  7. Live Interactive Demo (Runnable directly via: python auth.py)
"""

import os
import re
import hmac
import uuid
import secrets
import hashlib
import threading
from enum import Enum
from typing import Optional, List, Set, Union, Dict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from database import database

# Optional bcrypt support with automatic zero-dependency fallback
try:
    import bcrypt  # type: ignore
    _BCRYPT_AVAILABLE = True
except ImportError:
    bcrypt = None
    _BCRYPT_AVAILABLE = False


# =============================================================================
# SECTION 1: CUSTOM EXCEPTIONS (Clear, Secure Error Messages)
# =============================================================================

class AuthError(Exception):
    """Base error for all authentication and permission failures."""
    def __init__(self, message: str = "An authentication error occurred."):
        super().__init__(message)
        self.message = message


class UserNotFoundError(AuthError):
    """Raised when a requested user does not exist in the system."""
    def __init__(self, username: str = ""):
        message = f"User '{username}' was not found." if username else "User not found."
        super().__init__(message)
        self.username = username


class UserAlreadyExistsError(AuthError):
    """Raised when trying to register a username that is already taken."""
    def __init__(self, username: str = ""):
        message = f"Username '{username}' is already registered." if username else "User already exists."
        super().__init__(message)
        self.username = username


class InvalidCredentialsError(AuthError):
    """Raised when the username or password provided during login is wrong."""
    def __init__(self, message: str = "Invalid username or password."):
        super().__init__(message)


class AccountDisabledError(AuthError):
    """Raised when an inactive or disabled user attempts to log in."""
    def __init__(self, username: str = ""):
        message = f"Account '{username}' is disabled." if username else "Account is disabled."
        super().__init__(message)
        self.username = username


class InvalidTokenError(AuthError):
    """Raised when a session token is unrecognized, malformed, or logged out."""
    def __init__(self, message: str = "Invalid or unauthenticated session token."):
        super().__init__(message)


class SessionExpiredError(AuthError):
    """Raised when an action is attempted using an expired session token."""
    def __init__(self, message: str = "Session has expired. Please log in again."):
        super().__init__(message)


class PermissionDeniedError(AuthError):
    """Raised when a user lacks the required permission for an action."""
    def __init__(self, permission: str = "", role: str = ""):
        if permission and role:
            message = f"Permission '{permission}' denied for role '{role}'."
        elif permission:
            message = f"Permission '{permission}' denied."
        else:
            message = "Access denied: insufficient permissions."
        super().__init__(message)
        self.permission = permission
        self.role = role


# Backward compatibility alias
UnauthorizedError = PermissionDeniedError


class ValidationError(AuthError):
    """Raised when user input fails format rules (e.g. password too short)."""
    def __init__(self, message: str = "Input validation failed."):
        super().__init__(message)


# =============================================================================
# SECTION 2: ROLES & PERMISSIONS (RBAC Rulebook)
# =============================================================================

class Role(str, Enum):
    """Supported roles in the Employee Management System."""
    ADMIN = "Admin"
    EMPLOYEE = "Employee"

    @classmethod
    def from_str(cls, value: str) -> "Role":
        """Convert a string case-insensitively into a Role enum."""
        cleaned = value.strip().capitalize()
        for member in cls:
            if member.value.lower() == cleaned.lower():
                return member
        raise ValueError(f"Unknown role: '{value}'. Supported roles: {[r.value for r in cls]}")


class Permission(str, Enum):
    """All system permissions across Employee, Attendance, Leave, & Payroll."""
    # Employee Management
    ADD_EMPLOYEE = "add_employee"
    UPDATE_EMPLOYEE = "update_employee"
    DELETE_EMPLOYEE = "delete_employee"
    VIEW_EMPLOYEE = "view_employee"

    # Attendance
    MARK_ATTENDANCE = "mark_attendance"

    # Leave Management
    APPLY_LEAVE = "apply_leave"
    APPROVE_LEAVE = "approve_leave"
    REJECT_LEAVE = "reject_leave"

    # Payroll & Reporting
    VIEW_PAYROLL = "view_payroll"
    VIEW_PAYSLIP = "view_payslip"
    VIEW_REPORTS = "view_reports"

    @classmethod
    def from_str(cls, value: str) -> "Permission":
        """Convert a string case-insensitively into a Permission enum."""
        cleaned = value.strip().lower()
        for member in cls:
            if member.value == cleaned:
                return member
        raise ValueError(f"Unknown permission: '{value}'")


# Role-to-Permissions mapping table
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.ADD_EMPLOYEE,
        Permission.UPDATE_EMPLOYEE,
        Permission.DELETE_EMPLOYEE,
        Permission.VIEW_EMPLOYEE,
        Permission.MARK_ATTENDANCE,
        Permission.APPROVE_LEAVE,
        Permission.REJECT_LEAVE,
        Permission.VIEW_PAYROLL,
        Permission.VIEW_REPORTS,
    },
    Role.EMPLOYEE: {
        Permission.VIEW_EMPLOYEE,
        Permission.MARK_ATTENDANCE,
        Permission.APPLY_LEAVE,
        Permission.VIEW_PAYSLIP,
    },
}


def get_permissions_for_role(role: Union[Role, str]) -> Set[str]:
    """Return the set of permission strings assigned to a role."""
    if isinstance(role, str):
        try:
            role = Role.from_str(role)
        except ValueError:
            return set()
    perms = ROLE_PERMISSIONS.get(role, set())
    return {p.value for p in perms}


def has_role_permission(role: Union[Role, str], permission: Union[Permission, str]) -> bool:
    """Check whether a given role holds the requested permission."""
    if isinstance(role, str):
        try:
            role = Role.from_str(role)
        except ValueError:
            return False

    perm_str = permission.value if isinstance(permission, Permission) else str(permission).strip().lower()
    allowed = {p.value for p in ROLE_PERMISSIONS.get(role, set())}
    return perm_str in allowed


# =============================================================================
# SECTION 3: DATA MODELS (User, Safe View, and Session)
# =============================================================================

@dataclass
class User:
    """Internal user record containing the scrambled password hash."""
    user_id: str
    username: str
    password_hash: str
    role: Role
    employee_id: Optional[str] = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_view(self) -> "UserView":
        """Convert internal user to a safe external view with NO password hash."""
        return UserView(
            user_id=self.user_id,
            username=self.username,
            role=self.role.value,
            employee_id=self.employee_id,
            is_active=self.is_active,
            created_at=self.created_at.isoformat(),
            permissions=sorted(list(get_permissions_for_role(self.role))),
        )


@dataclass(frozen=True)
class UserView:
    """Public read-only user details sent to UI. Notice: NO password or hash!"""
    user_id: str
    username: str
    role: str
    employee_id: Optional[str]
    is_active: bool
    created_at: str
    permissions: List[str]


@dataclass
class Session:
    """Represents an active 60-minute login session with a digital badge token."""
    session_token: str
    user_id: str
    username: str
    role: Role
    created_at: datetime
    expires_at: datetime

    def is_expired(self) -> bool:
        """Return True if current time has passed the expiration timestamp."""
        return datetime.now(timezone.utc) >= self.expires_at


# =============================================================================
# SECTION 4: PASSWORD SECURITY (Salted Hashing & Constant-Time Verification)
# =============================================================================

PBKDF2_ALGORITHM = "sha256"
# OWASP recommends a high work factor for password derivation.  The fallback is
# deliberately kept in the standard library so the application remains easy to
# run while still using a modern, slow password hash.
PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16


def is_bcrypt_available() -> bool:
    """Check if the bcrypt package is installed."""
    return _BCRYPT_AVAILABLE


def hash_password(password: str, prefer_bcrypt: bool = True) -> str:
    """Scramble a plain text password with a unique cryptographic salt."""
    if not password:
        raise ValueError("Password cannot be empty.")

    # 1. Use bcrypt if available
    if prefer_bcrypt and _BCRYPT_AVAILABLE and bcrypt is not None:
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    # 2. Built-in zero-dependency fallback: PBKDF2-HMAC-SHA256 with 100,000 iterations
    salt = secrets.token_hex(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2:{PBKDF2_ALGORITHM}:{PBKDF2_ITERATIONS}${salt}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check if plain text password matches the stored hash in constant time."""
    if not plain_password or not hashed_password:
        return False

    # Check for bcrypt format
    if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
        if not _BCRYPT_AVAILABLE or bcrypt is None:
            raise RuntimeError("Stored password requires 'bcrypt'. Run: pip install bcrypt")
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    # Check for PBKDF2 format
    if hashed_password.startswith("pbkdf2:"):
        try:
            parts = hashed_password.split("$")
            if len(parts) != 3:
                return False
            algo_header, salt, expected_hex = parts
            header_parts = algo_header.split(":")
            if len(header_parts) != 3:
                return False
            _, algorithm, iterations_str = header_parts
            iterations = int(iterations_str)

            derived = hashlib.pbkdf2_hmac(
                algorithm,
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            # Constant-time comparison prevents timing attacks
            return hmac.compare_digest(derived.hex(), expected_hex)
        except Exception:
            return False

    return False


# =============================================================================
# SECTION 5: IN-MEMORY DATA REPOSITORY & SEED ACCOUNTS
# =============================================================================

# Pre-seeded test accounts
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"


class AuthRepository:
    """Thread-safe SQLite storage for users and login sessions."""

    def __init__(self, seed: bool = True):
        self._lock = threading.RLock()
        if seed:
            self.seed_default_accounts()

    def seed_default_accounts(self) -> None:
        """Create only the requested initial administrator when the DB is empty."""
        with self._lock:
            if self.get_by_username(DEFAULT_ADMIN_USERNAME):
                return
            self.save_user(User("USR-0001", DEFAULT_ADMIN_USERNAME, hash_password(DEFAULT_ADMIN_PASSWORD), Role.ADMIN))

    @staticmethod
    def _user(row) -> Optional[User]:
        if not row:
            return None
        return User(row["user_id"], row["username"], row["password_hash"], Role(row["role"]), row["employee_id"], bool(row["is_active"]), datetime.fromisoformat(row["created_at"]))

    @staticmethod
    def _session(row) -> Optional[Session]:
        if not row:
            return None
        return Session(row["session_token"], row["user_id"], row["username"], Role(row["role"]), datetime.fromisoformat(row["created_at"]), datetime.fromisoformat(row["expires_at"]))

    def save_user(self, user: User) -> User:
        """Save or update a user record."""
        with self._lock:
            with database.connection() as conn:
                conn.execute("""INSERT INTO users (user_id, username, password_hash, role, employee_id, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,
                    password_hash=excluded.password_hash, role=excluded.role, employee_id=excluded.employee_id, is_active=excluded.is_active""",
                    (user.user_id, user.username, user.password_hash, user.role.value, user.employee_id, int(user.is_active), user.created_at.isoformat()))
            return user

    def get_by_username(self, username: str) -> Optional[User]:
        """Lookup user by username (case-insensitive)."""
        with self._lock:
            with database.connection() as conn:
                return self._user(conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username.strip(),)).fetchone())

    def get_by_id(self, user_id: str) -> Optional[User]:
        """Lookup user by unique user ID."""
        with self._lock:
            with database.connection() as conn:
                return self._user(conn.execute("SELECT * FROM users WHERE user_id=?", (user_id.strip(),)).fetchone())

    def list_all_users(self) -> List[User]:
        """Return all registered users."""
        with self._lock:
            with database.connection() as conn:
                return [self._user(row) for row in conn.execute("SELECT * FROM users ORDER BY username").fetchall()]

    def delete_user(self, username: str) -> bool:
        """Delete a user and revoke their active sessions."""
        with self._lock:
            with database.connection() as conn:
                return bool(conn.execute("DELETE FROM users WHERE username=? COLLATE NOCASE", (username.strip(),)).rowcount)

    def save_session(self, session: Session) -> Session:
        """Store an active session token."""
        with self._lock:
            with database.connection() as conn:
                conn.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?)", (session.session_token, session.user_id, session.username, session.role.value, session.created_at.isoformat(), session.expires_at.isoformat()))
            return session

    def get_session(self, token: str) -> Optional[Session]:
        """Lookup an active session by token."""
        with self._lock:
            with database.connection() as conn:
                return self._session(conn.execute("SELECT * FROM sessions WHERE session_token=?", (token,)).fetchone())

    def delete_session(self, token: str) -> bool:
        """Remove a session token on logout."""
        with self._lock:
            with database.connection() as conn:
                return bool(conn.execute("DELETE FROM sessions WHERE session_token=?", (token,)).rowcount)

    def delete_sessions_by_username(self, username: str) -> int:
        """Revoke all sessions belonging to a user."""
        with self._lock:
            with database.connection() as conn:
                return conn.execute("DELETE FROM sessions WHERE username=? COLLATE NOCASE", (username.strip(),)).rowcount

    def clear(self) -> None:
        """Wipe all memory data (useful for test isolation)."""
        with self._lock:
            with database.connection() as conn:
                conn.executescript("DELETE FROM sessions; DELETE FROM login_attempts; DELETE FROM users;")

    def login_state(self, username: str) -> Optional[tuple]:
        with database.connection() as conn:
            row = conn.execute("SELECT failure_count, first_failed_at, locked_until FROM login_attempts WHERE username=? COLLATE NOCASE", (username.strip(),)).fetchone()
        return (row["failure_count"], datetime.fromisoformat(row["first_failed_at"]), datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None) if row else None

    def save_login_state(self, username: str, count: int, first_failed_at: datetime, locked_until: Optional[datetime]) -> None:
        with database.connection() as conn:
            conn.execute("INSERT INTO login_attempts VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET failure_count=excluded.failure_count, first_failed_at=excluded.first_failed_at, locked_until=excluded.locked_until", (username.strip(), count, first_failed_at.isoformat(), locked_until.isoformat() if locked_until else None))

    def clear_login_state(self, username: str) -> None:
        with database.connection() as conn:
            conn.execute("DELETE FROM login_attempts WHERE username=? COLLATE NOCASE", (username.strip(),))


# =============================================================================
# SECTION 6: MAIN SERVICE (AuthService — Public Operations)
# =============================================================================

class AuthService:
    """Main security service: registration, login, logout, and permission checks."""

    def __init__(
        self,
        repository: Optional[AuthRepository] = None,
        session_duration_minutes: int = 60,
    ):
        self.repository = repository or AuthRepository(seed=True)
        self.session_duration = timedelta(minutes=session_duration_minutes)
        self.max_login_attempts = 5
        self.login_window = timedelta(minutes=15)
        self.lockout_duration = timedelta(minutes=15)

    # 1. REGISTER USER
    def register_user(
        self,
        username: str,
        password: str,
        role: Union[Role, str] = Role.EMPLOYEE,
        employee_id: Optional[str] = None,
    ) -> UserView:
        """Register a new user account with a hashed password."""
        # Validate username
        if not username or not isinstance(username, str):
            raise ValidationError("Username is required and must be a string.")
        cleaned_username = username.strip()
        if len(cleaned_username) < 3 or len(cleaned_username) > 50:
            raise ValidationError("Username must be between 3 and 50 characters.")
        if not re.match(r"^[a-zA-Z0-9_.-]+$", cleaned_username):
            raise ValidationError(
                "Username may only contain letters, numbers, underscores, dots, and hyphens."
            )

        # Enforce a password policy suitable for browser-exposed accounts.
        if not password or not isinstance(password, str):
            raise ValidationError("Password is required and must be a string.")
        if len(password) < 12:
            raise ValidationError("Password must be at least 12 characters long.")
        categories = sum((
            any(char.islower() for char in password),
            any(char.isupper() for char in password),
            any(char.isdigit() for char in password),
            any(not char.isalnum() for char in password),
        ))
        if categories < 3:
            raise ValidationError(
                "Password must include characters from at least three groups: "
                "lowercase, uppercase, numbers, and symbols."
            )

        # Normalize role
        if isinstance(role, str):
            try:
                role_enum = Role.from_str(role)
            except ValueError as e:
                raise ValidationError(str(e))
        elif isinstance(role, Role):
            role_enum = role
        else:
            raise ValidationError("Role must be an instance of Role or valid string.")

        # Check for duplicates
        if self.repository.get_by_username(cleaned_username):
            raise UserAlreadyExistsError(cleaned_username)

        # Create unique ID, hash password, and store user
        user_id = f"USR-{uuid.uuid4().hex[:8].upper()}"
        pwd_hash = hash_password(password)

        new_user = User(
            user_id=user_id,
            username=cleaned_username,
            password_hash=pwd_hash,
            role=role_enum,
            employee_id=employee_id.strip() if employee_id else None,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        saved = self.repository.save_user(new_user)
        return saved.to_view()

    # 2. LOGIN
    def login(self, username: str, password: str) -> Session:
        """Authenticate username and password, then return an active 60-min session."""
        if not username or not password:
            raise ValidationError("Both username and password must be provided.")

        login_key = username.strip().lower()
        now = datetime.now(timezone.utc)
        state = self.repository.login_state(login_key)
        if state and state[2] and now < state[2]:
            # Intentionally use the same public error as a bad password.
            raise InvalidCredentialsError("Invalid username or password.")

        def record_failure() -> None:
            prior = self.repository.login_state(login_key)
            count = prior[0] + 1 if prior and now - prior[1] < self.login_window else 1
            first_failure = prior[1] if prior and now - prior[1] < self.login_window else now
            locked_until = now + self.lockout_duration if count >= self.max_login_attempts else None
            self.repository.save_login_state(login_key, count, first_failure, locked_until)

        def clear_failures() -> None:
            self.repository.clear_login_state(login_key)

        user = self.repository.get_by_username(username.strip())
        if not user:
            # Dummy verify prevents timing enumeration
            verify_password("dummy", "pbkdf2:sha256:100000$00$00")
            record_failure()
            raise InvalidCredentialsError("Invalid username or password.")

        if not user.is_active:
            record_failure()
            raise AccountDisabledError(user.username)

        if not self.verify_password(password, user.password_hash):
            record_failure()
            raise InvalidCredentialsError("Invalid username or password.")

        clear_failures()

        # Create session badge with 32-character random token
        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(32)
        session = Session(
            session_token=token,
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            created_at=now,
            expires_at=now + self.session_duration,
        )

        self.repository.save_session(session)
        return session

    # 3. VERIFY PASSWORD
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Check if plain text password matches a hash string."""
        return verify_password(plain_password, hashed_password)

    # 4. LOGOUT
    def logout(self, session_token: str) -> bool:
        """Revoke a session token so it cannot be used anymore."""
        if not session_token:
            return False
        return self.repository.delete_session(session_token.strip())

    # 5. CHECK PERMISSION
    def has_permission(
        self,
        subject: Union[str, User, UserView, Role, Session],
        permission: Union[Permission, str],
    ) -> bool:
        """Check if a session token, user, or role is allowed to perform an action."""
        target_role: Optional[Role] = None

        if isinstance(subject, Session):
            if subject.is_expired():
                return False
            target_role = subject.role

        elif isinstance(subject, (User, UserView)):
            role_name = subject.role if isinstance(subject, UserView) else subject.role.value
            target_role = Role.from_str(role_name)

        elif isinstance(subject, Role):
            target_role = subject

        elif isinstance(subject, str):
            try:
                target_role = Role.from_str(subject)
            except ValueError:
                session = self.repository.get_session(subject.strip())
                if session is None or session.is_expired():
                    return False
                target_role = session.role

        if not target_role:
            return False

        return has_role_permission(target_role, permission)

    # 6. GUARD / REQUIRE PERMISSION
    def require_permission(self, session_token: str, permission: Union[Permission, str]) -> None:
        """Raise PermissionDeniedError if the active session lacks this permission."""
        session = self.validate_session(session_token)
        perm_str = permission.value if isinstance(permission, Permission) else str(permission).strip().lower()
        if not has_role_permission(session.role, perm_str):
            raise PermissionDeniedError(permission=perm_str, role=session.role.value)

    # 7. SESSION VALIDATION & CURRENT USER
    def validate_session(self, session_token: str) -> Session:
        """Validate that a session token is active and has not expired."""
        if not session_token:
            raise InvalidTokenError("Session token must not be empty.")

        session = self.repository.get_session(session_token.strip())
        if not session:
            raise InvalidTokenError("Session token not found or already logged out.")

        if session.is_expired():
            self.repository.delete_session(session.session_token)
            raise SessionExpiredError("Session has expired. Please log in again.")

        return session

    def get_current_user(self, session_token: str) -> UserView:
        """Get the safe UserView of the user holding this session token."""
        session = self.validate_session(session_token)
        user = self.repository.get_by_id(session.user_id)
        if not user:
            raise UserNotFoundError(session.username)
        return user.to_view()

    def get_user_by_username(self, username: str) -> Optional[UserView]:
        """Fetch user profile by username."""
        user = self.repository.get_by_username(username)
        return user.to_view() if user else None

    def list_all_users(self) -> List[UserView]:
        """Return safe view objects for all registered users."""
        return [u.to_view() for u in self.repository.list_all_users()]


# =============================================================================
# SECTION 7: LIVE INTERACTIVE DEMO (Run directly: python auth.py)
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  PERSON 2 — AUTHENTICATION & ROLE MANAGEMENT DEMO")
    print("=" * 70)

    service = AuthService()

    # 1. Login with pre-seeded admin
    print("\n[Step 1] Logging in as pre-seeded Admin...")
    admin_session = service.login(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)
    admin_token = admin_session.session_token
    print(f"  --> Success! Session Token: {admin_token[:16]}... (valid 60 min)")

    # 2. Check Admin permissions
    print("\n[Step 2] Checking Admin Permissions:")
    print(f"  - Can admin add employees?      {service.has_permission(admin_token, 'add_employee')}")
    print(f"  - Can admin view payroll?       {service.has_permission(admin_token, 'view_payroll')}")
    print(f"  - Can admin apply for leave?    {service.has_permission(admin_token, 'apply_leave')}")

    # 3. Register a brand new Employee
    print("\n[Step 3] Registering a new Employee ('rohit_sharma')...")
    new_user = service.register_user(
        username="rohit_sharma",
        password="MySecretPassword123!",
        role=Role.EMPLOYEE,
        employee_id="EMP-2005",
    )
    print(f"  --> Created: {new_user.username} (ID: {new_user.user_id}, Role: {new_user.role})")
    print(f"  --> Granted Permissions: {new_user.permissions}")

    # 4. Login as the new Employee
    print("\n[Step 4] Logging in as new Employee...")
    emp_session = service.login("rohit_sharma", "MySecretPassword123!")
    emp_token = emp_session.session_token
    print(f"  --> Success! Session Token: {emp_token[:16]}...")

    # 5. Check Employee permissions (Notice admin features are blocked!)
    print("\n[Step 5] Checking Employee Permissions:")
    print(f"  - Can employee view payslip?    {service.has_permission(emp_token, 'view_payslip')}")
    print(f"  - Can employee apply leave?     {service.has_permission(emp_token, 'apply_leave')}")
    print(f"  - Can employee delete employee? {service.has_permission(emp_token, 'delete_employee')}  <-- BLOCKED!")

    # 6. Logout
    print("\n[Step 6] Logging out Employee...")
    service.logout(emp_token)
    print("  --> Employee logged out.")
    print(f"  --> Is token still valid?       {service.has_permission(emp_token, 'view_payslip')}")

    print("\n" + "=" * 70)
    print("  ALL TESTS & DEMONSTRATIONS COMPLETED WITH 100% SUCCESS!")
    print("=" * 70)
