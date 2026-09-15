"""Desktop Tkinter GUI and Core Logic for Employee Management System.

Consolidates employee CRUD data store, logic, and GUI into a self-contained module.
Can be imported by main.py or run directly via:
    python3 employee_management.py
"""

import sys
from typing import Any, Dict, List, Optional
from database import database

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:
    tk = None  # type: ignore
    messagebox = None  # type: ignore
    ttk = None  # type: ignore


# =============================================================================
# 1. CORE DATA STORE & CRUD OPERATIONS
# =============================================================================

# Pre-seeded employee records synchronized with attendance and payroll
employees: List[Dict[str, Any]] = []  # Compatibility name; data lives in SQLite.


def generate_employee_id() -> str:
    """Generates a simple unique ID like EMP104, EMP105, etc."""
    existing_nums = [int(item["id"][3:]) for item in database.employee_list() if item["id"].upper().startswith("EMP") and item["id"][3:].isdigit()]
    return f"EMP{max(existing_nums, default=100) + 1}"


def add_employee(
    name: str,
    email: str,
    phone: str,
    department: str,
    designation: str,
    emp_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Adds a new employee dictionary to the employees list."""
    assigned_id = emp_id.strip().upper() if emp_id and emp_id.strip() else generate_employee_id()

    if database.employee_get(assigned_id) is not None:
        raise ValueError(f"Employee with ID '{assigned_id}' already exists.")

    new_emp: Dict[str, Any] = {
        "id": assigned_id,
        "name": name.strip(),
        "email": email.strip(),
        "phone": phone.strip(),
        "department": department.strip(),
        "designation": designation.strip(),
    }

    return database.employee_add(new_emp)


def get_all_employees() -> List[Dict[str, Any]]:
    """Returns a copy of all employee records."""
    return database.employee_list()


def get_employee_by_id(emp_id: str) -> Optional[Dict[str, Any]]:
    """Finds and returns a single employee by their ID (case-insensitive)."""
    return database.employee_get(emp_id)


def search_employees(keyword: str) -> List[Dict[str, Any]]:
    """Searches employees by matching keyword in ID, name, email, department, or designation."""
    return database.employee_list(keyword)


def update_employee(
    emp_id: str,
    name: Optional[str] = None,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    department: Optional[str] = None,
    designation: Optional[str] = None,
) -> bool:
    """Updates the details of an existing employee."""
    emp = get_employee_by_id(emp_id)
    if not emp:
        return False

    updated = {"id": emp["id"], "name": name.strip() if name is not None else emp["name"], "email": email.strip() if email is not None else emp["email"], "phone": phone.strip() if phone is not None else emp["phone"], "department": department.strip() if department is not None else emp["department"], "designation": designation.strip() if designation is not None else emp["designation"]}
    return database.employee_update(updated)


def delete_employee(emp_id: str) -> bool:
    """Deletes an employee by their ID."""
    return database.employee_delete(emp_id)


# =============================================================================
# 2. STANDALONE EMPLOYEE GUI
# =============================================================================

class EmployeeGUI:
    """Standalone or embedded Employee Management GUI view."""

    def __init__(self, root, on_change_callback=None):
        self.root = root
        self.on_change_callback = on_change_callback
        self.selected_emp_id: Optional[str] = None

        # Content Frame
        content_frame = tk.Frame(self.root, padx=15, pady=10)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Left: Form Frame
        form_frame = tk.LabelFrame(content_frame, text=" Employee Details ", padx=10, pady=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        # Fields
        tk.Label(form_frame, text="Employee ID:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.entry_id = tk.Entry(form_frame, width=22)
        self.entry_id.grid(row=0, column=1, pady=4)

        tk.Label(form_frame, text="Name:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.entry_name = tk.Entry(form_frame, width=22)
        self.entry_name.grid(row=1, column=1, pady=4)

        tk.Label(form_frame, text="Email:").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.entry_email = tk.Entry(form_frame, width=22)
        self.entry_email.grid(row=2, column=1, pady=4)

        tk.Label(form_frame, text="Phone:").grid(row=3, column=0, sticky=tk.W, pady=4)
        self.entry_phone = tk.Entry(form_frame, width=22)
        self.entry_phone.grid(row=3, column=1, pady=4)

        tk.Label(form_frame, text="Department:").grid(row=4, column=0, sticky=tk.W, pady=4)
        self.entry_dept = tk.Entry(form_frame, width=22)
        self.entry_dept.grid(row=4, column=1, pady=4)

        tk.Label(form_frame, text="Designation:").grid(row=5, column=0, sticky=tk.W, pady=4)
        self.entry_desig = tk.Entry(form_frame, width=22)
        self.entry_desig.grid(row=5, column=1, pady=4)

        # Form Buttons
        btn_frame = tk.Frame(form_frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=15)

        tk.Button(btn_frame, text="Add", width=8, bg="#27ae60", fg="white", command=self.on_add).grid(row=0, column=0, padx=3, pady=3)
        tk.Button(btn_frame, text="Update", width=8, bg="#2980b9", fg="white", command=self.on_update).grid(row=0, column=1, padx=3, pady=3)
        tk.Button(btn_frame, text="Delete", width=8, bg="#c0392b", fg="white", command=self.on_delete).grid(row=1, column=0, padx=3, pady=3)
        tk.Button(btn_frame, text="Clear", width=8, bg="#7f8c8d", fg="white", command=self.clear_form).grid(row=1, column=1, padx=3, pady=3)

        # Right: Table & Search Frame
        table_frame = tk.Frame(content_frame)
        table_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Search Bar
        search_frame = tk.Frame(table_frame)
        search_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.entry_search = tk.Entry(search_frame, width=25)
        self.entry_search.pack(side=tk.LEFT, padx=6)
        tk.Button(search_frame, text="Find", command=self.on_search).pack(side=tk.LEFT, padx=3)
        tk.Button(search_frame, text="Reset", command=self.refresh_table).pack(side=tk.LEFT, padx=3)

        # Treeview Table
        columns = ("ID", "Name", "Department", "Designation", "Phone", "Email")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        col_widths = {"ID": 80, "Name": 130, "Department": 110, "Designation": 130, "Phone": 100, "Email": 150}
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 100), anchor=tk.W)

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        # Initial Load
        self.refresh_table()

    def refresh_table(self, emp_list=None):
        for item in self.tree.get_children():
            self.tree.delete(item)

        records = emp_list if emp_list is not None else get_all_employees()
        for emp in records:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    emp["id"],
                    emp["name"],
                    emp["department"],
                    emp["designation"],
                    emp["phone"],
                    emp.get("email", ""),
                ),
            )

    def on_row_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        self.selected_emp_id = values[0]

        # Populate form
        emp = get_employee_by_id(self.selected_emp_id)
        if emp:
            self.clear_form()
            self.entry_id.insert(0, emp["id"])
            self.entry_name.insert(0, emp["name"])
            self.entry_email.insert(0, emp.get("email", ""))
            self.entry_phone.insert(0, emp.get("phone", ""))
            self.entry_dept.insert(0, emp["department"])
            self.entry_desig.insert(0, emp["designation"])

    def clear_form(self):
        self.selected_emp_id = None
        self.entry_id.delete(0, tk.END)
        self.entry_name.delete(0, tk.END)
        self.entry_email.delete(0, tk.END)
        self.entry_phone.delete(0, tk.END)
        self.entry_dept.delete(0, tk.END)
        self.entry_desig.delete(0, tk.END)

    def on_add(self):
        name = self.entry_name.get().strip()
        if not name:
            messagebox.showerror("Error", "Employee Name cannot be empty.")
            return

        custom_id = self.entry_id.get().strip() or None
        try:
            new_emp = add_employee(
                name=name,
                email=self.entry_email.get().strip(),
                phone=self.entry_phone.get().strip(),
                department=self.entry_dept.get().strip(),
                designation=self.entry_desig.get().strip(),
                emp_id=custom_id,
            )
            messagebox.showinfo("Success", f"Added employee with ID {new_emp['id']}")
            self.clear_form()
            self.refresh_table()
            if self.on_change_callback:
                self.on_change_callback()
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def on_update(self):
        target_id = self.selected_emp_id or self.entry_id.get().strip()
        if not target_id:
            messagebox.showwarning("Warning", "Select an employee from the table or enter ID to update.")
            return

        success = update_employee(
            emp_id=target_id,
            name=self.entry_name.get().strip(),
            email=self.entry_email.get().strip(),
            phone=self.entry_phone.get().strip(),
            department=self.entry_dept.get().strip(),
            designation=self.entry_desig.get().strip(),
        )
        if success:
            messagebox.showinfo("Success", f"Updated employee {target_id}")
            self.clear_form()
            self.refresh_table()
            if self.on_change_callback:
                self.on_change_callback()
        else:
            messagebox.showerror("Error", f"Employee '{target_id}' not found.")

    def on_delete(self):
        target_id = self.selected_emp_id or self.entry_id.get().strip()
        if not target_id:
            messagebox.showwarning("Warning", "Select an employee from the table to delete.")
            return

        if messagebox.askyesno("Confirm", f"Are you sure you want to delete employee {target_id}?"):
            if delete_employee(target_id):
                messagebox.showinfo("Success", f"Deleted employee {target_id}")
                self.clear_form()
                self.refresh_table()
                if self.on_change_callback:
                    self.on_change_callback()
            else:
                messagebox.showerror("Error", f"Could not delete employee '{target_id}'.")

    def on_search(self):
        keyword = self.entry_search.get().strip()
        results = search_employees(keyword)
        self.refresh_table(results)


def main():
    """Standalone runner for Employee Management GUI."""
    if tk is None:
        print("Error: Tkinter is required to run the graphical interface.")
        sys.exit(1)

    root = tk.Tk()
    root.title("Employee Management System")
    root.geometry("900x560")
    root.minsize(800, 480)

    title_label = tk.Label(
        root,
        text="Employee Management System",
        font=("Arial", 18, "bold"),
        bg="#2c3e50",
        fg="white",
        pady=10,
    )
    title_label.pack(fill=tk.X)

    EmployeeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
