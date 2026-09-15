"""Person 4: Payroll, Payslip, and Reports Module.

A unified, self-contained Python module for the Employee Management System:
1. Salary Calculation: Gross = Basic + Allowances, Net = Gross - Deductions, with strict validation.
2. Payslip Generation: Structured data (dataclass/dict) and clean formatted ASCII text output.
3. Independent Backend Reports: Employee distribution, Attendance summaries, and Salary financial analytics.
4. SQLite Store: persistent employee, attendance, and payroll records.

Can be run directly:
    python person4_payroll/payroll.py
"""

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from statistics import median
from typing import Any, Dict, List, Optional, Tuple, Union
from database import database


# ==============================================================================
# 1. CUSTOM EXCEPTIONS
# ==============================================================================

class PayrollError(Exception):
    """Base exception class for all payroll module related errors."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class InvalidSalaryValueError(PayrollError, ValueError):
    """Raised when basic salary, allowances, or deductions have negative or non-numeric values."""

    def __init__(self, field_name: str, value: object, message: Optional[str] = None) -> None:
        default_message = f"Invalid salary value for '{field_name}': {value}. Value must be a non-negative number."
        super().__init__(
            message=message or default_message,
            details={"field_name": field_name, "value": value},
        )
        self.field_name = field_name
        self.value = value


class InvalidDeductionError(PayrollError, ValueError):
    """Raised when deductions exceed gross salary and excess deductions are not permitted."""

    def __init__(self, deductions: float, gross_salary: float, message: Optional[str] = None) -> None:
        default_message = (
            f"Deductions ({deductions:.2f}) cannot exceed gross salary ({gross_salary:.2f}). "
            "Net salary cannot be negative."
        )
        super().__init__(
            message=message or default_message,
            details={"deductions": deductions, "gross_salary": gross_salary},
        )
        self.deductions = deductions
        self.gross_salary = gross_salary


class EmployeeNotFoundError(PayrollError, KeyError):
    """Raised when an employee or payroll record is not found."""

    def __init__(self, employee_id: str, pay_period: Optional[str] = None) -> None:
        period_str = f" for pay period '{pay_period}'" if pay_period else ""
        super().__init__(
            message=f"Employee '{employee_id}' not found{period_str}.",
            details={"employee_id": employee_id, "pay_period": pay_period},
        )
        self.employee_id = employee_id
        self.pay_period = pay_period


class DuplicateRecordError(PayrollError, ValueError):
    """Raised when attempting to add a duplicate record."""

    def __init__(self, record_type: str, employee_id: str, pay_period: str) -> None:
        super().__init__(
            message=f"Duplicate {record_type} record already exists for employee '{employee_id}' and pay period '{pay_period}'.",
            details={"record_type": record_type, "employee_id": employee_id, "pay_period": pay_period},
        )
        self.record_type = record_type
        self.employee_id = employee_id
        self.pay_period = pay_period


class ReportGenerationError(PayrollError, RuntimeError):
    """Raised when report generation encounters unsupported item types."""

    def __init__(self, report_type: str, reason: str) -> None:
        super().__init__(
            message=f"Failed to generate {report_type} report: {reason}",
            details={"report_type": report_type, "reason": reason},
        )
        self.report_type = report_type
        self.reason = reason


# ==============================================================================
# 2. DATA MODELS
# ==============================================================================

@dataclass(frozen=True)
class SalaryBreakdown:
    """Financial breakdown of employee earnings and deductions."""
    basic_salary: float
    allowances: float
    deductions: float
    gross_salary: float
    net_salary: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "basic_salary": round(self.basic_salary, 2),
            "allowances": round(self.allowances, 2),
            "deductions": round(self.deductions, 2),
            "gross_salary": round(self.gross_salary, 2),
            "net_salary": round(self.net_salary, 2),
        }


@dataclass
class PayslipData:
    """Structured data container for an employee's payslip."""
    employee_id: str
    employee_name: str
    pay_period: str
    basic_salary: float
    allowances: float
    gross_salary: float
    deductions: float
    net_salary: float
    generated_at: str
    currency: str = "USD"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmployeeRecord:
    """In-memory representation of an employee."""
    employee_id: str
    name: str
    department: str
    designation: str
    status: str = "ACTIVE"
    joined_date: str = "2025-01-15"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttendanceRecord:
    """In-memory representation of monthly attendance."""
    employee_id: str
    pay_period: str
    days_present: int
    days_absent: int
    days_leave: int
    late_arrivals: int = 0

    @property
    def total_working_days(self) -> int:
        return self.days_present + self.days_absent + self.days_leave

    @property
    def attendance_rate(self) -> float:
        if self.total_working_days == 0:
            return 0.0
        return round((self.days_present / self.total_working_days) * 100, 2)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["total_working_days"] = self.total_working_days
        data["attendance_rate"] = self.attendance_rate
        return data


@dataclass
class PayrollRecord:
    """In-memory representation of payroll components."""
    employee_id: str
    pay_period: str
    basic_salary: float
    allowances: float
    deductions: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 3. SALARY CALCULATOR
# ==============================================================================

class SalaryCalculator:
    """Calculates gross and net salaries with input validations."""

    @staticmethod
    def validate_amount(field_name: str, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidSalaryValueError(
                field_name=field_name,
                value=value,
                message=f"Field '{field_name}' must be a numeric value (int or float), got {type(value).__name__}.",
            )
        if value < 0:
            raise InvalidSalaryValueError(
                field_name=field_name,
                value=value,
                message=f"Field '{field_name}' cannot be negative (received: {value}).",
            )
        return round(float(value), 2)

    @classmethod
    def calculate_gross(cls, basic_salary: float, allowances: float) -> float:
        valid_basic = cls.validate_amount("basic_salary", basic_salary)
        valid_allowances = cls.validate_amount("allowances", allowances)
        return round(valid_basic + valid_allowances, 2)

    @classmethod
    def calculate_net(
        cls,
        gross_salary: float,
        deductions: float,
        allow_excess_deductions: bool = False,
    ) -> float:
        valid_gross = cls.validate_amount("gross_salary", gross_salary)
        valid_deductions = cls.validate_amount("deductions", deductions)

        if not allow_excess_deductions and valid_deductions > valid_gross:
            raise InvalidDeductionError(
                deductions=valid_deductions,
                gross_salary=valid_gross,
            )
        return round(valid_gross - valid_deductions, 2)

    @classmethod
    def calculate(
        cls,
        basic_salary: float,
        allowances: float,
        deductions: float,
        allow_excess_deductions: bool = False,
    ) -> SalaryBreakdown:
        gross = cls.calculate_gross(basic_salary, allowances)
        net = cls.calculate_net(
            gross_salary=gross,
            deductions=deductions,
            allow_excess_deductions=allow_excess_deductions,
        )
        return SalaryBreakdown(
            basic_salary=round(float(basic_salary), 2),
            allowances=round(float(allowances), 2),
            deductions=round(float(deductions), 2),
            gross_salary=gross,
            net_salary=net,
        )


# ==============================================================================
# 4. PAYSLIP GENERATOR
# ==============================================================================

class PayslipGenerator:
    """Generates structured and formatted text payslips."""

    @staticmethod
    def _validate_metadata(employee_id: str, employee_name: str, pay_period: str) -> None:
        if not employee_id or not str(employee_id).strip():
            raise ValueError("Employee ID must be a non-empty string.")
        if not employee_name or not str(employee_name).strip():
            raise ValueError("Employee Name must be a non-empty string.")
        if not pay_period or not str(pay_period).strip():
            raise ValueError("Pay Period must be a non-empty string.")

    @classmethod
    def generate_payslip_data(
        cls,
        employee_id: str,
        employee_name: str,
        pay_period: str,
        basic_salary: float,
        allowances: float,
        deductions: float,
        currency: str = "USD",
        allow_excess_deductions: bool = False,
    ) -> PayslipData:
        cls._validate_metadata(employee_id, employee_name, pay_period)
        breakdown = SalaryCalculator.calculate(
            basic_salary=basic_salary,
            allowances=allowances,
            deductions=deductions,
            allow_excess_deductions=allow_excess_deductions,
        )
        return PayslipData(
            employee_id=str(employee_id).strip(),
            employee_name=str(employee_name).strip(),
            pay_period=str(pay_period).strip(),
            basic_salary=breakdown.basic_salary,
            allowances=breakdown.allowances,
            gross_salary=breakdown.gross_salary,
            deductions=breakdown.deductions,
            net_salary=breakdown.net_salary,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            currency=currency.strip().upper(),
        )

    @staticmethod
    def format_payslip_text(payslip: PayslipData) -> str:
        curr = payslip.currency
        width = 62
        divider = "=" * width
        thin_divider = "-" * width

        lines = [
            divider,
            f"{'OFFICIAL SALARY PAYSLIP':^{width}}",
            f"{'CONFIDENTIAL':^{width}}",
            divider,
            f"  Employee ID   : {payslip.employee_id}",
            f"  Employee Name : {payslip.employee_name}",
            f"  Pay Period    : {payslip.pay_period}",
            f"  Generated On  : {payslip.generated_at}",
            thin_divider,
            f"  {'EARNINGS & ALLOWANCES':<35} {'AMOUNT (' + curr + ')':>23}",
            thin_divider,
            f"  Basic Salary  : {' ':20} {payslip.basic_salary:>19.2f}",
            f"  Allowances    : {' ':20} {payslip.allowances:>19.2f}",
            thin_divider,
            f"  Gross Salary  : {' ':20} {payslip.gross_salary:>19.2f}",
            thin_divider,
            f"  {'DEDUCTIONS':<35} {'AMOUNT (' + curr + ')':>23}",
            thin_divider,
            f"  Total Deductions : {' ':17} {payslip.deductions:>19.2f}",
            divider,
            f"  NET SALARY PAYABLE : {' ':14} {curr} {payslip.net_salary:>15.2f}",
            divider,
            f"{'Thank you for your valued contribution!':^{width}}",
            divider,
        ]
        return "\n".join(lines)

    @classmethod
    def generate_payslip(
        cls,
        employee_id: str,
        employee_name: str,
        pay_period: str,
        basic_salary: float,
        allowances: float,
        deductions: float,
        currency: str = "USD",
        allow_excess_deductions: bool = False,
    ) -> Tuple[PayslipData, str]:
        data = cls.generate_payslip_data(
            employee_id=employee_id,
            employee_name=employee_name,
            pay_period=pay_period,
            basic_salary=basic_salary,
            allowances=allowances,
            deductions=deductions,
            currency=currency,
            allow_excess_deductions=allow_excess_deductions,
        )
        text = cls.format_payslip_text(data)
        return data, text


# ==============================================================================
# 5. STORE COMPATIBILITY
# ==============================================================================

MOCK_EMPLOYEES: List[EmployeeRecord] = []
MOCK_ATTENDANCE: List[AttendanceRecord] = []
MOCK_PAYROLL: List[PayrollRecord] = []


class InMemoryPayrollStore:
    """Compatibility name for the SQLite-backed payroll repository."""

    def __init__(self, seed_mock_data: bool = False) -> None:
        if seed_mock_data:
            self.seed_defaults()

    def _make_period_key(self, employee_id: str, pay_period: str) -> str:
        return f"{employee_id.strip().upper()}#{pay_period.strip()}"

    def seed_defaults(self) -> None:
        for emp in MOCK_EMPLOYEES:
            self.add_employee(deepcopy(emp))
        for att in MOCK_ATTENDANCE:
            self.add_attendance(deepcopy(att))
        for pay in MOCK_PAYROLL:
            self.add_payroll_record(deepcopy(pay))

    def add_employee(self, record: EmployeeRecord, overwrite: bool = True) -> None:
        emp_id = record.employee_id.strip().upper()
        if not overwrite and database.employee_get(emp_id):
            raise DuplicateRecordError("Employee", emp_id, "N/A")
        existing = database.employee_get(emp_id)
        database.employee_add({"id": emp_id, "name": record.name, "email": existing["email"] if existing else "", "phone": existing["phone"] if existing else "", "department": record.department, "designation": record.designation}) if not existing else database.employee_update({"id": emp_id, "name": record.name, "email": existing["email"], "phone": existing["phone"], "department": record.department, "designation": record.designation})

    def get_employee(self, employee_id: str) -> Optional[EmployeeRecord]:
        item = database.employee_get(employee_id)
        return EmployeeRecord(item["id"], item["name"], item["department"], item["designation"]) if item else None

    def get_all_employees(self) -> List[EmployeeRecord]:
        return [EmployeeRecord(item["id"], item["name"], item["department"], item["designation"]) for item in database.employee_list()]

    def add_attendance(self, record: AttendanceRecord, overwrite: bool = True) -> None:
        if not overwrite and database.payroll_attendance_get(record.employee_id, record.pay_period):
            raise DuplicateRecordError("Attendance", record.employee_id, record.pay_period)
        database.payroll_attendance_upsert(record.to_dict())

    def get_attendance(self, employee_id: str, pay_period: str) -> Optional[AttendanceRecord]:
        item = database.payroll_attendance_get(employee_id, pay_period)
        return AttendanceRecord(item["employee_id"], item["pay_period"], item["days_present"], item["days_absent"], item["days_leave"], item["late_arrivals"]) if item else None

    def get_all_attendance(self, pay_period: Optional[str] = None) -> List[AttendanceRecord]:
        return [AttendanceRecord(item["employee_id"], item["pay_period"], item["days_present"], item["days_absent"], item["days_leave"], item["late_arrivals"]) for item in database.payroll_attendance_list(pay_period)]

    def add_payroll_record(self, record: PayrollRecord, overwrite: bool = True) -> None:
        if not overwrite and database.payroll_get(record.employee_id, record.pay_period):
            raise DuplicateRecordError("Payroll", record.employee_id, record.pay_period)
        database.payroll_upsert(record.employee_id, record.pay_period, record.basic_salary, record.allowances, record.deductions)

    def get_payroll_record(self, employee_id: str, pay_period: str) -> Optional[PayrollRecord]:
        item = database.payroll_get(employee_id, pay_period)
        return PayrollRecord(item["employee_id"], item["pay_period"], item["basic_salary"], item["allowances"], item["deductions"]) if item else None

    def get_all_payroll_records(self, pay_period: Optional[str] = None) -> List[PayrollRecord]:
        return [PayrollRecord(item["employee_id"], item["pay_period"], item["basic_salary"], item["allowances"], item["deductions"]) for item in database.payroll_list(pay_period)]

    def clear(self) -> None:
        database.payroll_clear()


# Alias for backward compatibility
PayrollStore = InMemoryPayrollStore


# ==============================================================================
# 6. PAYROLL SERVICE
# ==============================================================================

class PayrollService:
    """Coordinates payroll processing and storage lookups."""

    def __init__(self, store: Optional[InMemoryPayrollStore] = None) -> None:
        self.store = store if store is not None else InMemoryPayrollStore(seed_mock_data=False)

    def process_payroll(
        self,
        employee_id: str,
        employee_name: str,
        pay_period: str,
        basic_salary: float,
        allowances: float,
        deductions: float,
        currency: str = "USD",
        persist: bool = True,
    ) -> PayslipData:
        payslip_data = PayslipGenerator.generate_payslip_data(
            employee_id=employee_id,
            employee_name=employee_name,
            pay_period=pay_period,
            basic_salary=basic_salary,
            allowances=allowances,
            deductions=deductions,
            currency=currency,
        )
        if persist:
            self.store.add_payroll_record(
                PayrollRecord(
                    employee_id=payslip_data.employee_id,
                    pay_period=payslip_data.pay_period,
                    basic_salary=payslip_data.basic_salary,
                    allowances=payslip_data.allowances,
                    deductions=payslip_data.deductions,
                )
            )
        return payslip_data

    def batch_process(
        self,
        records: List[Union[PayrollRecord, Dict[str, Union[str, float]]]],
        persist: bool = True,
    ) -> List[PayslipData]:
        results: List[PayslipData] = []
        for item in records:
            if isinstance(item, PayrollRecord):
                emp_id = item.employee_id
                period = item.pay_period
                basic = item.basic_salary
                allow = item.allowances
                deduct = item.deductions
            elif isinstance(item, dict):
                emp_id = str(item["employee_id"])
                period = str(item["pay_period"])
                basic = float(item["basic_salary"])
                allow = float(item.get("allowances", 0.0))
                deduct = float(item.get("deductions", 0.0))
            else:
                raise PayrollError(f"Unsupported record format in batch process: {type(item).__name__}")

            emp = self.store.get_employee(emp_id)
            emp_name = emp.name if emp else f"Employee {emp_id}"

            payslip = self.process_payroll(
                employee_id=emp_id,
                employee_name=emp_name,
                pay_period=period,
                basic_salary=basic,
                allowances=allow,
                deductions=deduct,
                persist=persist,
            )
            results.append(payslip)
        return results

    def get_payslip(self, employee_id: str, pay_period: str) -> Tuple[PayslipData, str]:
        emp = self.store.get_employee(employee_id)
        if not emp:
            raise EmployeeNotFoundError(employee_id=employee_id)

        payroll_rec = self.store.get_payroll_record(employee_id, pay_period)
        if not payroll_rec:
            raise EmployeeNotFoundError(employee_id=employee_id, pay_period=pay_period)

        return PayslipGenerator.generate_payslip(
            employee_id=emp.employee_id,
            employee_name=emp.name,
            pay_period=pay_period,
            basic_salary=payroll_rec.basic_salary,
            allowances=payroll_rec.allowances,
            deductions=payroll_rec.deductions,
        )


# ==============================================================================
# 7. REPORT SERVICE
# ==============================================================================

class ReportService:
    """Backend reporting service for employees, attendance, and salary analytics."""

    # 1. Employee Report
    @classmethod
    def generate_employee_report(
        cls,
        employees: List[Union[EmployeeRecord, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        total = len(employees)
        if total == 0:
            return {
                "total_employees": 0,
                "active_employees": 0,
                "inactive_employees": 0,
                "active_percentage": 0.0,
                "departments": {},
                "department_percentages": {},
                "designations": {},
            }

        active_count = 0
        departments: Dict[str, int] = {}
        designations: Dict[str, int] = {}

        for emp in employees:
            if isinstance(emp, EmployeeRecord):
                status = emp.status.upper()
                dept = emp.department
                desig = emp.designation
            elif isinstance(emp, dict):
                status = str(emp.get("status", "ACTIVE")).upper()
                dept = str(emp.get("department", "Unassigned"))
                desig = str(emp.get("designation", "Unspecified"))
            else:
                raise ReportGenerationError("Employee", f"Unsupported item type: {type(emp).__name__}")

            if status == "ACTIVE":
                active_count += 1
            departments[dept] = departments.get(dept, 0) + 1
            designations[desig] = designations.get(desig, 0) + 1

        inactive_count = total - active_count
        dept_pct = {
            dept: round((count / total) * 100, 2)
            for dept, count in sorted(departments.items(), key=lambda x: x[1], reverse=True)
        }

        return {
            "total_employees": total,
            "active_employees": active_count,
            "inactive_employees": inactive_count,
            "active_percentage": round((active_count / total) * 100, 2),
            "departments": dict(sorted(departments.items(), key=lambda x: x[1], reverse=True)),
            "department_percentages": dept_pct,
            "designations": dict(sorted(designations.items(), key=lambda x: x[1], reverse=True)),
        }

    @staticmethod
    def format_employee_report(report: Dict[str, Any]) -> str:
        width = 65
        divider = "=" * width
        thin_divider = "-" * width

        total = report["total_employees"]
        active = report["active_employees"]
        inactive = report["inactive_employees"]
        active_pct = report["active_percentage"]

        lines = [
            divider,
            f"{'EXECUTIVE EMPLOYEE HEADCOUNT REPORT':^{width}}",
            divider,
            f"  Total Headcount    : {total:>6}",
            f"  Active Employees   : {active:>6} ({active_pct:.1f}%)",
            f"  Inactive Employees : {inactive:>6} ({100 - active_pct:.1f}%)",
            thin_divider,
            f"  {'DEPARTMENT':<35} {'COUNT':>10} {'SHARE':>14}",
            thin_divider,
        ]

        if not report["departments"]:
            lines.append(f"{'No department records available.':^{width}}")
        else:
            for dept, count in report["departments"].items():
                pct = report["department_percentages"].get(dept, 0.0)
                lines.append(f"  {dept:<35} {count:>10} {pct:>13.1f}%")

        lines.extend([
            thin_divider,
            f"  {'DESIGNATION / ROLE':<45} {'HEADCOUNT':>16}",
            thin_divider,
        ])

        if not report["designations"]:
            lines.append(f"{'No designation records available.':^{width}}")
        else:
            for desig, count in report["designations"].items():
                lines.append(f"  {desig:<45} {count:>16}")

        lines.append(divider)
        return "\n".join(lines)

    # 2. Attendance Report
    @classmethod
    def generate_attendance_report(
        cls,
        records: List[Union[AttendanceRecord, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        total_records = len(records)
        if total_records == 0:
            return {
                "total_records": 0,
                "total_working_days": 0,
                "total_present_days": 0,
                "total_absent_days": 0,
                "total_leave_days": 0,
                "total_late_arrivals": 0,
                "overall_attendance_rate": 0.0,
                "perfect_attendance_employees": [],
                "employee_breakdown": [],
            }

        tot_present = 0
        tot_absent = 0
        tot_leave = 0
        tot_late = 0
        perfect_attendance: List[str] = []
        breakdown: List[Dict[str, Any]] = []

        for rec in records:
            if isinstance(rec, AttendanceRecord):
                emp_id = rec.employee_id
                period = rec.pay_period
                present = rec.days_present
                absent = rec.days_absent
                leave = rec.days_leave
                late = rec.late_arrivals
                working_days = rec.total_working_days
                rate = rec.attendance_rate
            elif isinstance(rec, dict):
                emp_id = str(rec["employee_id"])
                period = str(rec.get("pay_period", "N/A"))
                present = int(rec.get("days_present", 0))
                absent = int(rec.get("days_absent", 0))
                leave = int(rec.get("days_leave", 0))
                late = int(rec.get("late_arrivals", 0))
                working_days = present + absent + leave
                rate = round((present / working_days) * 100, 2) if working_days > 0 else 0.0
            else:
                raise ReportGenerationError("Attendance", f"Unsupported record type: {type(rec).__name__}")

            tot_present += present
            tot_absent += absent
            tot_leave += leave
            tot_late += late

            if absent == 0 and leave == 0:
                perfect_attendance.append(emp_id)

            breakdown.append({
                "employee_id": emp_id,
                "pay_period": period,
                "days_present": present,
                "days_absent": absent,
                "days_leave": leave,
                "late_arrivals": late,
                "working_days": working_days,
                "attendance_rate": rate,
            })

        tot_working = tot_present + tot_absent + tot_leave
        overall_rate = round((tot_present / tot_working) * 100, 2) if tot_working > 0 else 0.0

        return {
            "total_records": total_records,
            "total_working_days": tot_working,
            "total_present_days": tot_present,
            "total_absent_days": tot_absent,
            "total_leave_days": tot_leave,
            "total_late_arrivals": tot_late,
            "overall_attendance_rate": overall_rate,
            "perfect_attendance_employees": perfect_attendance,
            "employee_breakdown": breakdown,
        }

    @staticmethod
    def format_attendance_report(report: Dict[str, Any]) -> str:
        width = 72
        divider = "=" * width
        thin_divider = "-" * width

        lines = [
            divider,
            f"{'MONTHLY ATTENDANCE & PUNCTUALITY REPORT':^{width}}",
            divider,
            f"  Total Employees Recorded  : {report['total_records']:>6}",
            f"  Total Working Days Tracked: {report['total_working_days']:>6}",
            f"  Total Present Days        : {report['total_present_days']:>6}",
            f"  Total Absent Days         : {report['total_absent_days']:>6}",
            f"  Total Leave Days          : {report['total_leave_days']:>6}",
            f"  Total Late Arrivals       : {report['total_late_arrivals']:>6}",
            f"  Overall Attendance Rate   : {report['overall_attendance_rate']:>6.2f}%",
            thin_divider,
            f"  {'EMP ID':<10} {'PRESENT':>8} {'ABSENT':>8} {'LEAVE':>7} {'LATE':>6} {'ATTN RATE':>12}",
            thin_divider,
        ]

        if not report["employee_breakdown"]:
            lines.append(f"{'No individual attendance records available.':^{width}}")
        else:
            for item in report["employee_breakdown"]:
                lines.append(
                    f"  {item['employee_id']:<10} "
                    f"{item['days_present']:>8} "
                    f"{item['days_absent']:>8} "
                    f"{item['days_leave']:>7} "
                    f"{item['late_arrivals']:>6} "
                    f"{item['attendance_rate']:>11.1f}%"
                )

        lines.extend([
            thin_divider,
            f"  Employees with 100% Attendance: "
            f"{', '.join(report['perfect_attendance_employees']) if report['perfect_attendance_employees'] else 'None'}",
            divider,
        ])
        return "\n".join(lines)

    # 3. Salary Report
    @classmethod
    def generate_salary_report(
        cls,
        records: List[Union[PayslipData, PayrollRecord, Dict[str, Any]]],
        currency: str = "USD",
    ) -> Dict[str, Any]:
        total_records = len(records)
        if total_records == 0:
            return {
                "total_records": 0,
                "currency": currency,
                "total_basic_salary": 0.0,
                "total_allowances": 0.0,
                "total_gross_payout": 0.0,
                "total_deductions": 0.0,
                "total_net_payout": 0.0,
                "average_gross_salary": 0.0,
                "average_net_salary": 0.0,
                "median_net_salary": 0.0,
                "highest_earners": [],
                "lowest_earners": [],
                "entries": [],
            }

        entries: List[Dict[str, Any]] = []

        for rec in records:
            if isinstance(rec, PayslipData):
                emp_id = rec.employee_id
                emp_name = rec.employee_name
                basic = rec.basic_salary
                allow = rec.allowances
                gross = rec.gross_salary
                deduct = rec.deductions
                net = rec.net_salary
            elif isinstance(rec, PayrollRecord):
                emp_id = rec.employee_id
                emp_name = f"Employee {rec.employee_id}"
                basic = rec.basic_salary
                allow = rec.allowances
                deduct = rec.deductions
                gross = SalaryCalculator.calculate_gross(basic, allow)
                net = SalaryCalculator.calculate_net(gross, deduct, allow_excess_deductions=True)
            elif isinstance(rec, dict):
                emp_id = str(rec["employee_id"])
                emp_name = str(rec.get("employee_name", f"Employee {emp_id}"))
                basic = float(rec["basic_salary"])
                allow = float(rec.get("allowances", 0.0))
                deduct = float(rec.get("deductions", 0.0))
                gross = float(rec.get("gross_salary", SalaryCalculator.calculate_gross(basic, allow)))
                net = float(
                    rec.get(
                        "net_salary",
                        SalaryCalculator.calculate_net(gross, deduct, allow_excess_deductions=True),
                    )
                )
            else:
                raise ReportGenerationError("Salary", f"Unsupported salary record: {type(rec).__name__}")

            entries.append({
                "employee_id": emp_id,
                "employee_name": emp_name,
                "basic_salary": round(basic, 2),
                "allowances": round(allow, 2),
                "gross_salary": round(gross, 2),
                "deductions": round(deduct, 2),
                "net_salary": round(net, 2),
            })

        tot_basic = round(sum(e["basic_salary"] for e in entries), 2)
        tot_allow = round(sum(e["allowances"] for e in entries), 2)
        tot_gross = round(sum(e["gross_salary"] for e in entries), 2)
        tot_deduct = round(sum(e["deductions"] for e in entries), 2)
        tot_net = round(sum(e["net_salary"] for e in entries), 2)

        net_salaries = [e["net_salary"] for e in entries]
        avg_gross = round(tot_gross / total_records, 2)
        avg_net = round(tot_net / total_records, 2)
        med_net = round(float(median(net_salaries)), 2)

        sorted_by_net = sorted(entries, key=lambda x: x["net_salary"], reverse=True)
        max_net = sorted_by_net[0]["net_salary"]
        min_net = sorted_by_net[-1]["net_salary"]

        highest_earners = [e for e in sorted_by_net if e["net_salary"] == max_net]
        lowest_earners = [e for e in sorted_by_net if e["net_salary"] == min_net]

        return {
            "total_records": total_records,
            "currency": currency,
            "total_basic_salary": tot_basic,
            "total_allowances": tot_allow,
            "total_gross_payout": tot_gross,
            "total_deductions": tot_deduct,
            "total_net_payout": tot_net,
            "average_gross_salary": avg_gross,
            "average_net_salary": avg_net,
            "median_net_salary": med_net,
            "highest_earners": highest_earners,
            "lowest_earners": lowest_earners,
            "entries": sorted_by_net,
        }

    @staticmethod
    def format_salary_report(report: Dict[str, Any]) -> str:
        width = 72
        divider = "=" * width
        thin_divider = "-" * width
        curr = report["currency"]

        highest_str = ", ".join(
            f"{h['employee_id']} ({h['employee_name']}): {curr} {h['net_salary']:.2f}"
            for h in report["highest_earners"]
        ) if report["highest_earners"] else "N/A"

        lowest_str = ", ".join(
            f"{l['employee_id']} ({l['employee_name']}): {curr} {l['net_salary']:.2f}"
            for l in report["lowest_earners"]
        ) if report["lowest_earners"] else "N/A"

        lines = [
            divider,
            f"{'EXECUTIVE SALARY & PAYROLL FINANCIAL REPORT':^{width}}",
            divider,
            f"  Total Processed Records : {report['total_records']:>8}",
            f"  Total Basic Salaries    : {curr:>5} {report['total_basic_salary']:>14.2f}",
            f"  Total Allowances        : {curr:>5} {report['total_allowances']:>14.2f}",
            f"  TOTAL GROSS PAYOUT      : {curr:>5} {report['total_gross_payout']:>14.2f}",
            f"  Total Deductions        : {curr:>5} {report['total_deductions']:>14.2f}",
            f"  TOTAL NET DISBURSEMENT  : {curr:>5} {report['total_net_payout']:>14.2f}",
            thin_divider,
            f"  Average Net Salary      : {curr:>5} {report['average_net_salary']:>14.2f}",
            f"  Median Net Salary       : {curr:>5} {report['median_net_salary']:>14.2f}",
            f"  Average Gross Salary    : {curr:>5} {report['average_gross_salary']:>14.2f}",
            thin_divider,
            f"  Highest Earner(s) : {highest_str}",
            f"  Lowest Earner(s)  : {lowest_str}",
            thin_divider,
            f"  {'EMP ID':<10} {'NAME':<20} {'GROSS (' + curr + ')':>16} {'NET (' + curr + ')':>17}",
            thin_divider,
        ]

        if not report["entries"]:
            lines.append(f"{'No payroll records found.':^{width}}")
        else:
            for e in report["entries"]:
                lines.append(
                    f"  {e['employee_id']:<10} {e['employee_name'][:18]:<20} "
                    f"{e['gross_salary']:>16.2f} {e['net_salary']:>17.2f}"
                )

        lines.append(divider)
        return "\n".join(lines)


# ==============================================================================
# 8. INTERACTIVE CLI (USER INPUT MODE)
# ==============================================================================

def _get_float_input(prompt: str) -> float:
    """Safely prompt user for a non-negative float value."""
    while True:
        val_str = input(prompt).strip()
        try:
            val = float(val_str)
            if val < 0:
                print("   [!] Value cannot be negative. Please enter a non-negative number.")
                continue
            return val
        except ValueError:
            print("   [!] Invalid number. Please enter a valid numerical value (e.g. 5000 or 5000.50).")


def _get_int_input(prompt: str) -> int:
    """Safely prompt user for a non-negative integer."""
    while True:
        val_str = input(prompt).strip()
        try:
            val = int(val_str)
            if val < 0:
                print("   [!] Value cannot be negative. Please enter 0 or a positive whole number.")
                continue
            return val
        except ValueError:
            print("   [!] Invalid integer. Please enter a valid whole number.")


def _get_str_input(prompt: str, default: str = "") -> str:
    """Safely prompt user for a non-empty string."""
    while True:
        prompt_text = f"{prompt} [{default}]: " if default else f"{prompt}: "
        val = input(prompt_text).strip()
        if not val and default:
            return default
        if val:
            return val
        print("   [!] This field cannot be empty. Please enter a value.")


def interactive_cli() -> None:
    """Launch the interactive Employee Management System console for Person 4."""
    store = InMemoryPayrollStore(seed_mock_data=False)
    service = PayrollService(store=store)

    print("\n" + "=" * 70)
    print("   EMPLOYEE MANAGEMENT SYSTEM - PAYROLL & REPORTS (PERSON 4)")
    print("=" * 70)
    print("Welcome! You can enter employee records, calculate salaries,")
    print("generate payslips, and run independent reports interactively.\n")

    while True:
        print("-" * 70)
        print(" MAIN MENU - Choose an option:")
        print("  1. Calculate Salary & Generate Payslip (Enter your own data)")
        print("  2. Add an Employee Record")
        print("  3. Add Attendance Record")
        print("  4. View Employee Headcount Report")
        print("  5. View Monthly Attendance Report")
        print("  6. View Salary & Financial Analytics Report")
        print("  7. Load Sample Mock Data (TEST001 - TEST005)")
        print("  8. Exit")
        print("-" * 70)

        choice = input("Enter choice (1-8): ").strip()

        # 1. Calculate Salary & Payslip
        if choice == "1":
            print("\n--- [1] SALARY CALCULATION & PAYSLIP GENERATION ---")
            emp_id = _get_str_input("Enter Employee ID (e.g. EMP001)")
            emp_name = _get_str_input("Enter Employee Full Name")
            pay_period = _get_str_input("Enter Pay Period (e.g. 2026-09)", default="2026-09")
            basic = _get_float_input("Enter Basic Salary (e.g. 5000): ")
            allowances = _get_float_input("Enter Allowances (e.g. 1000): ")
            deductions = _get_float_input("Enter Deductions (e.g. 500): ")
            currency = _get_str_input("Enter Currency code", default="USD")

            try:
                # Ensure employee exists in store
                if not store.get_employee(emp_id):
                    store.add_employee(
                        EmployeeRecord(
                            employee_id=emp_id,
                            name=emp_name,
                            department="General",
                            designation="Staff",
                        )
                    )

                payslip_data, payslip_text = service.get_payslip(emp_id, pay_period) if False else (None, None)
                payslip_data = service.process_payroll(
                    employee_id=emp_id,
                    employee_name=emp_name,
                    pay_period=pay_period,
                    basic_salary=basic,
                    allowances=allowances,
                    deductions=deductions,
                    currency=currency,
                    persist=True,
                )
                payslip_text = PayslipGenerator.format_payslip_text(payslip_data)

                print("\n" + payslip_text + "\n")
                print(f"[OK] Payslip successfully generated and recorded for {emp_name} ({emp_id}).")

            except (InvalidSalaryValueError, InvalidDeductionError) as err:
                print(f"\n[!] Calculation Error: {err}\n")
            except Exception as e:
                print(f"\n[!] Unexpected Error: {e}\n")

        # 2. Add Employee Record
        elif choice == "2":
            print("\n--- [2] ADD EMPLOYEE RECORD ---")
            emp_id = _get_str_input("Enter Employee ID (e.g. EMP002)")
            name = _get_str_input("Enter Full Name")
            department = _get_str_input("Enter Department (e.g. Engineering, Sales, HR)")
            designation = _get_str_input("Enter Designation / Role")
            status = _get_str_input("Enter Status [ACTIVE / INACTIVE]", default="ACTIVE").upper()

            rec = EmployeeRecord(
                employee_id=emp_id,
                name=name,
                department=department,
                designation=designation,
                status="ACTIVE" if status.startswith("A") else "INACTIVE",
            )
            store.add_employee(rec, overwrite=True)
            print(f"\n[OK] Successfully added employee: {name} ({emp_id}) in {department}.\n")

        # 3. Add Attendance Record
        elif choice == "3":
            print("\n--- [3] ADD ATTENDANCE RECORD ---")
            emp_id = _get_str_input("Enter Employee ID")
            pay_period = _get_str_input("Enter Pay Period (e.g. 2026-09)", default="2026-09")
            present = _get_int_input("Enter Days Present: ")
            absent = _get_int_input("Enter Days Absent: ")
            leave = _get_int_input("Enter Days on Leave: ")
            late = _get_int_input("Enter Late Arrivals count: ")

            att = AttendanceRecord(
                employee_id=emp_id,
                pay_period=pay_period,
                days_present=present,
                days_absent=absent,
                days_leave=leave,
                late_arrivals=late,
            )
            store.add_attendance(att, overwrite=True)
            print(f"\n[OK] Attendance recorded: {att.days_present} days present ({att.attendance_rate:.1f}% attendance rate).\n")

        # 4. View Employee Report
        elif choice == "4":
            employees = store.get_all_employees()
            if not employees:
                print("\n[!] No employee records entered yet. Add employees (Option 2) or load sample data (Option 7).\n")
            else:
                rep = ReportService.generate_employee_report(employees)
                print("\n" + ReportService.format_employee_report(rep) + "\n")

        # 5. View Attendance Report
        elif choice == "5":
            attendance_records = store.get_all_attendance()
            if not attendance_records:
                print("\n[!] No attendance records entered yet. Add attendance (Option 3) or load sample data (Option 7).\n")
            else:
                rep = ReportService.generate_attendance_report(attendance_records)
                print("\n" + ReportService.format_attendance_report(rep) + "\n")

        # 6. View Salary & Financial Report
        elif choice == "6":
            payroll_records = store.get_all_payroll_records()
            if not payroll_records:
                print("\n[!] No payroll records entered yet. Generate payslips (Option 1) or load sample data (Option 7).\n")
            else:
                rep = ReportService.generate_salary_report(payroll_records, currency="USD")
                print("\n" + ReportService.format_salary_report(rep) + "\n")

        # 7. Load Mock Data
        elif choice == "7":
            store.seed_defaults()
            print("\n[OK] Loaded sample test records (TEST001 - TEST005) into system!\n")

        # 8. Exit
        elif choice == "8":
            print("\nExiting Employee Management System. Have a great day!\n")
            break

        else:
            print("\n[!] Invalid selection. Please enter a number between 1 and 8.\n")


if __name__ == "__main__":
    interactive_cli()
