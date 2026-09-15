"""Person 3: Attendance and Leave Management Module.

A unified, self-contained Python module for attendance tracking and leave requests.
Everything for Person 3 is consolidated in this single file for maximum simplicity,
readability, and ease of maintenance.

Sections in this file:
  1. Custom Exceptions (Error Handling)
  2. Data Models (Attendance, LeaveRequest)
  3. SQLite Data Store
  4. AttendanceService (Attendance operations)
  5. LeaveService (Leave application and approval operations)
  6. Self-Tests & Demo (Runnable directly via: python attendance.py)
"""

from dataclasses import dataclass
from datetime import date
from typing import List, Set
import sqlite3
from database import database


# =============================================================================
# 1. CUSTOM EXCEPTIONS
# =============================================================================

class AttendanceError(Exception):
    """Base exception for attendance-related errors."""


class DuplicateAttendanceError(AttendanceError):
    """Raised when attendance is already recorded for an employee on a date."""


class LeaveError(Exception):
    """Base exception for leave-related errors."""


class LeaveRequestNotFoundError(LeaveError):
    """Raised when a leave request cannot be found."""


class InvalidLeaveRequestError(LeaveError):
    """Raised when a leave request contains invalid data."""


# =============================================================================
# 2. DATA MODELS
# =============================================================================

@dataclass
class Attendance:
    """Represents an employee attendance record for a specific date."""
    employee_id: str
    date: date
    status: str

    def __post_init__(self):
        allowed_statuses = {"Present", "Absent"}

        if not self.employee_id.strip():
            raise ValueError("Employee ID cannot be empty.")

        if self.status not in allowed_statuses:
            raise ValueError("Attendance status must be Present or Absent.")


@dataclass
class LeaveRequest:
    """Represents an employee leave request."""
    request_id: str
    employee_id: str
    start_date: date
    end_date: date
    reason: str
    status: str = "Pending"

    def __post_init__(self):
        allowed_statuses = {"Pending", "Approved", "Rejected"}

        if not self.request_id.strip():
            raise ValueError("Leave request ID cannot be empty.")

        if not self.employee_id.strip():
            raise ValueError("Employee ID cannot be empty.")

        if self.end_date < self.start_date:
            raise ValueError("End date cannot be before start date.")

        if not self.reason.strip():
            raise ValueError("Leave reason cannot be empty.")

        if self.status not in allowed_statuses:
            raise ValueError(
                "Leave status must be Pending, Approved, or Rejected."
            )


# =============================================================================
# 3. IN-MEMORY DATA STORE
# =============================================================================

# Temporary in-memory storage. Person 5 will replace this with the database later.
attendance_records: List[Attendance] = []  # Compatibility exports; SQLite is authoritative.
leave_requests: List[LeaveRequest] = []

# Fake employee IDs for independent testing
test_employee_ids: Set[str] = {"TEST001", "TEST002", "TEST003"}


# =============================================================================
# 4. ATTENDANCE SERVICE
# =============================================================================

class AttendanceService:
    """Handles attendance operations using in-memory data."""

    def mark_attendance(
        self,
        employee_id: str,
        attendance_date: date,
        status: str
    ) -> Attendance:
        """Create attendance for one employee on one date."""
        record = Attendance(
            employee_id=employee_id,
            date=attendance_date,
            status=status
        )

        try:
            database.attendance_add(record.employee_id, record.date.isoformat(), record.status)
        except sqlite3.IntegrityError:
            raise DuplicateAttendanceError(f"Attendance already exists for {employee_id} on {attendance_date}.")
        return record

    def get_employee_attendance(self, employee_id: str) -> List[Attendance]:
        """Return all attendance records for one employee."""
        return [Attendance(row["employee_id"], date.fromisoformat(row["attendance_date"]), row["status"]) for row in database.attendance_list(employee_id=employee_id)]

    def get_attendance_by_date(self, attendance_date: date) -> List[Attendance]:
        """Return attendance records for a selected date."""
        return [Attendance(row["employee_id"], date.fromisoformat(row["attendance_date"]), row["status"]) for row in database.attendance_list(attendance_date=attendance_date.isoformat())]

    def get_all_attendance(self) -> List[Attendance]:
        """Return all attendance records in memory."""
        return [Attendance(row["employee_id"], date.fromisoformat(row["attendance_date"]), row["status"]) for row in database.attendance_list()]


# =============================================================================
# 5. LEAVE SERVICE
# =============================================================================

class LeaveService:
    """Handles leave operations using in-memory data."""

    def _generate_request_id(self) -> str:
        """Create a unique leave request ID."""
        return "LEAVE"  # The SQLite AUTOINCREMENT value is used in apply_leave.

    def apply_leave(
        self,
        employee_id: str,
        start_date: date,
        end_date: date,
        reason: str
    ) -> LeaveRequest:
        """Create a new pending leave request."""
        if end_date < start_date or not reason.strip() or not employee_id.strip():
            # Reuse the domain validation messages consistently.
            LeaveRequest("TEMP", employee_id, start_date, end_date, reason)
        request_id = database.leave_add(employee_id, start_date.isoformat(), end_date.isoformat(), reason.strip())
        request = LeaveRequest(
            request_id=request_id,
            employee_id=employee_id,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
            status="Pending"
        )

        return request

    def get_leave_requests(self) -> List[LeaveRequest]:
        """Return all leave requests."""
        return [LeaveRequest(row["request_id"], row["employee_id"], date.fromisoformat(row["start_date"]), date.fromisoformat(row["end_date"]), row["reason"], row["status"]) for row in database.leave_list()]

    def get_employee_leaves(self, employee_id: str) -> List[LeaveRequest]:
        """Return all leave requests for one employee."""
        return [LeaveRequest(row["request_id"], row["employee_id"], date.fromisoformat(row["start_date"]), date.fromisoformat(row["end_date"]), row["reason"], row["status"]) for row in database.leave_list(employee_id)]

    def _find_request(self, request_id: str) -> LeaveRequest:
        """Find one leave request or raise an error."""
        for request in self.get_leave_requests():
            if request.request_id == request_id:
                return request
        raise LeaveRequestNotFoundError(f"Leave request '{request_id}' was not found.")

    def approve_leave(self, request_id: str) -> LeaveRequest:
        """Change a leave request status to Approved."""
        if not database.leave_set_status(request_id, "Approved"):
            raise LeaveRequestNotFoundError(f"Leave request '{request_id}' was not found.")
        return self._find_request(request_id)

    def reject_leave(self, request_id: str) -> LeaveRequest:
        """Change a leave request status to Rejected."""
        if not database.leave_set_status(request_id, "Rejected"):
            raise LeaveRequestNotFoundError(f"Leave request '{request_id}' was not found.")
        return self._find_request(request_id)


# =============================================================================
# 6. SELF-TESTS & DEMO
# =============================================================================

def reset_test_data() -> None:
    """Clear temporary data before each test."""
    attendance_records.clear()
    leave_requests.clear()


def run_all_tests() -> None:
    """Run assert-based test suite for attendance and leave services."""
    # Test 1: Mark and view attendance
    reset_test_data()
    att_service = AttendanceService()
    rec = att_service.mark_attendance("TEST001", date(2026, 9, 15), "Present")
    assert rec.employee_id == "TEST001"
    assert rec.status == "Present"
    assert len(att_service.get_employee_attendance("TEST001")) == 1
    assert len(att_service.get_attendance_by_date(date(2026, 9, 15))) == 1

    # Test 2: Duplicate attendance prevention
    try:
        att_service.mark_attendance("TEST001", date(2026, 9, 15), "Absent")
        assert False, "Expected DuplicateAttendanceError"
    except DuplicateAttendanceError:
        pass

    # Test 3: Invalid attendance status
    try:
        att_service.mark_attendance("TEST001", date(2026, 9, 16), "Late")
        assert False, "Expected ValueError"
    except ValueError:
        pass

    # Test 4: Apply and view leave
    reset_test_data()
    leave_service = LeaveService()
    req = leave_service.apply_leave(
        "TEST001",
        date(2026, 9, 20),
        date(2026, 9, 22),
        "Medical leave"
    )
    assert req.request_id == "LEAVE001"
    assert req.status == "Pending"
    assert len(leave_service.get_employee_leaves("TEST001")) == 1
    assert len(leave_service.get_leave_requests()) == 1

    # Test 5: Approve and reject leave
    approved = leave_service.approve_leave(req.request_id)
    assert approved.status == "Approved"

    req2 = leave_service.apply_leave(
        "TEST002",
        date(2026, 9, 25),
        date(2026, 9, 26),
        "Family event"
    )
    rejected = leave_service.reject_leave(req2.request_id)
    assert rejected.status == "Rejected"

    # Test 6: Invalid leave dates
    try:
        leave_service.apply_leave(
            "TEST001",
            date(2026, 9, 25),
            date(2026, 9, 20),
            "Invalid date test"
        )
        assert False, "Expected ValueError"
    except ValueError:
        pass

    # Test 7: Missing leave request lookup
    try:
        leave_service.approve_leave("LEAVE999")
        assert False, "Expected LeaveRequestNotFoundError"
    except LeaveRequestNotFoundError:
        pass

    print("All attendance and leave tests passed successfully.")


if __name__ == "__main__":
    run_all_tests()
