import flet as ft
import sqlite3
import os
import json
import io
import zipfile
import hashlib
import hmac
import secrets
import shutil
import asyncio
from datetime import datetime
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from docx import Document
import httpx

# ==================================================
# SECURECASEDESK 3.0
# ==================================================

def get_base_dir():
    # على Android بعد التغليف: استخدم مجلد التطبيق القابل للكتابة
    if os.getenv("FLET_APP_STORAGE_DATA"):
        return Path(os.getenv("FLET_APP_STORAGE_DATA"))
    return Path(__file__).resolve().parent

BASE = get_base_dir()
STORAGE = BASE / "storage"
REPORTS = BASE / "reports"
BACKUPS = BASE / "backups"
DB = STORAGE / "securecase.db"
KEY_FILE = STORAGE / "secret.key"
AUDIT_KEY = STORAGE / "audit.key"

for folder in (STORAGE, REPORTS, BACKUPS):
    folder.mkdir(parents=True, exist_ok=True)

ph = PasswordHasher()

if not KEY_FILE.exists():
    KEY_FILE.write_bytes(Fernet.generate_key())

if not AUDIT_KEY.exists():
    AUDIT_KEY.write_bytes(secrets.token_bytes(32))

cipher = Fernet(KEY_FILE.read_bytes())
audit_key = AUDIT_KEY.read_bytes()

def enc(value):
    return cipher.encrypt(str(value).encode()).decode()

def dec(value):
    try:
        return cipher.decrypt(value.encode()).decode()
    except Exception:
        return ""

def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db

def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL DEFAULT '',
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            status TEXT NOT NULL,
            department TEXT NOT NULL,
            officer_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(officer_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS attachments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content BLOB NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
        """)

        user = db.execute("SELECT id FROM users LIMIT 1").fetchone()

        if not user:
            password = secrets.token_urlsafe(15)
            db.execute("""
                INSERT INTO users(username,password,role,department)
                VALUES(?,?,?,?)
            """, (
                "admin",
                ph.hash(password),
                "admin",
                "الإدارة العامة"
            ))
            (STORAGE / "first_login.txt").write_text(
                "Username: admin\nPassword: " + password,
                encoding="utf-8"
            )

def audit(username, action, details):
    with connect() as db:
        last = db.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = last["entry_hash"] if last else "GENESIS"
        message = (
            username + "|" + action + "|" + details + "|" +
            datetime.utcnow().isoformat() + "|" + previous
        )
        digest = hmac.new(audit_key, message.encode(), hashlib.sha256).hexdigest()
        db.execute("""
            INSERT INTO audit_logs
            (username,action,details,timestamp,previous_hash,entry_hash)
            VALUES(?,?,?,?,?,?)
        """, (
            username, action, enc(details),
            datetime.utcnow().isoformat(), previous, digest
        ))

def verify_audit():
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
    previous = "GENESIS"
    for row in rows:
        message = (
            row["username"] + "|" + row["action"] + "|" +
            dec(row["details"]) + "|" + row["timestamp"] + "|" + previous
        )
        expected = hmac.new(audit_key, message.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, row["entry_hash"]):
            return False
        if row["previous_hash"] != previous:
            return False
        previous = row["entry_hash"]
    return True

def can_view(user, case):
    if user["role"] in ("admin", "auditor"):
        return True
    if user["department"] != case["department"]:
        return False
    if user["role"] == "manager":
        return True
    return case["officer_id"] == user["id"]

def get_cases(user):
    with connect() as db:
        rows = db.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return [r for r in rows if can_view(user, r)]

def get_case(case_id, user):
    with connect() as db:
        row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row or not can_view(user, row):
        return None
    return row

def create_case(user, title, details, department):
    now = datetime.utcnow().isoformat()
    with connect() as db:
        cur = db.execute("""
            INSERT INTO cases(title,details,status,department,officer_id,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?)
        """, (enc(title), enc(details), "مفتوحة", department, user["id"], now, now))
        case_id = cur.lastrowid
    audit(user["username"], "CREATE_CASE", str(case_id))
    return case_id

def update_case(user, case_id, title, details, status):
    case = get_case(case_id, user)
    if not case:
        return False
    if user["role"] == "auditor":
        return False
    if user["role"] == "officer" and case["officer_id"] != user["id"]:
        return False
    with connect() as db:
        db.execute("""
            UPDATE cases SET title=?, details=?, status=?, updated_at=? WHERE id=?
        """, (enc(title), enc(details), status, datetime.utcnow().isoformat(), case_id))
    audit(user["username"], "UPDATE_CASE", str(case_id))
    return True

def delete_case(user, case_id):
    case = get_case(case_id, user)
    if not case or user["role"] not in ("admin", "manager"):
        return False
    with connect() as db:
        db.execute("DELETE FROM cases WHERE id=?", (case_id,))
    audit(user["username"], "DELETE_CASE", str(case_id))
    return True

def add_attachment(user, case_id, file_path):
    case = get_case(case_id, user)
    if not case or user["role"] == "auditor":
        return False
    if user["role"] == "officer" and case["officer_id"] != user["id"]:
        return False
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        return False
    if path.suffix.lower() not in (".pdf", ".png", ".jpg", ".jpeg"):
        return False
    if path.stat().st_size > 10 * 1024 * 1024:
        return False
    content = cipher.encrypt(path.read_bytes())
    with connect() as db:
        db.execute("""
            INSERT INTO attachments(case_id,filename,content,created_at)
            VALUES(?,?,?,?)
        """, (case_id, path.name, content, datetime.utcnow().isoformat()))
    audit(user["username"], "ADD_ATTACHMENT", str(case_id))
    return True

def export_report(user, case_id, extra_details=""):
    case = get_case(case_id, user)
    if not case:
        return None
    doc = Document()
    doc.add_heading("SECURECASEDESK", 0)
    doc.add_heading("تقرير قضية", level=1)
    fields = [
        ("رقم القضية", case["id"]),
        ("عنوان القضية", dec(case["title"])),
        ("الإدارة", case["department"]),
        ("الحالة", case["status"]),
        ("تاريخ الإنشاء", case["created_at"]),
        ("آخر تحديث", case["updated_at"]),
        ("تفاصيل القضية", dec(case["details"])),
        ("الشرح الإضافي", extra_details or "لا يوجد")
    ]
    for label, value in fields:
        doc.add_heading(label, level=2)
        doc.add_paragraph(str(value))
    doc.add_paragraph("تم إنشاء هذا التقرير بواسطة SecureCaseDesk 3.0")
    filename = REPORTS / f"case_{case_id}_{datetime.now():%Y%m%d_%H%M%S}.docx"
    doc.save(filename)
    audit(user["username"], "EXPORT_REPORT", str(case_id))
    return filename

def create_backup(user):
    if user["role"] != "admin" or not verify_audit():
        return None
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(DB, "securecase.db")
    encrypted = cipher.encrypt(data.getvalue())
    filename = BACKUPS / f"backup_{datetime.now():%Y%m%d_%H%M%S}.scdb"
    filename.write_bytes(encrypted)
    audit(user["username"], "CREATE_BACKUP", filename.name)
    return filename

def restore_backup(user, file_path):
    if user["role"] != "admin":
        return False
    path = Path(file_path).expanduser()
    if not path.is_file() or path.stat().st_size > 200 * 1024 * 1024:
        return False
    try:
        raw = cipher.decrypt(path.read_bytes())
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            if z.namelist() != ["securecase.db"]:
                return False
            candidate = io.BytesIO(z.read("securecase.db"))
        test = sqlite3.connect(":memory:")
        test.deserialize(candidate.getvalue())
        check = test.execute("PRAGMA integrity_check").fetchone()
        test.close()
        if not check or check[0] != "ok":
            return False
        temp = STORAGE / "restore_temp.db"
        temp.write_bytes(candidate.getvalue())
        shutil.copy2(DB, BACKUPS / "before_restore.db")
        os.replace(temp, DB)
        audit(user["username"], "RESTORE_BACKUP", path.name)
        return True
    except Exception:
        return False

# ==================================================
# AI ENGINE
# ==================================================

async def ask_ai(prompt, case_text, mode="local"):
    system_prompt = (
        "أنت مساعد إداري لتحرير التقارير. لا تخترع وقائع أو أدلة. "
        "ميز بين المعلومات المسجلة والاستنتاجات. لا تصدر أحكاما قانونية. "
        "أنتج مسودة قابلة للمراجعة."
    )
    if mode == "local":
        url = os.getenv("LOCAL_AI_URL", "http://127.0.0.1:11434/api/chat")
        payload = {
            "model": os.getenv("LOCAL_AI_MODEL", "llama3.2"),
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt + "\n\n" + case_text}
            ]
        }
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()["message"]["content"]

    api_key = os.getenv("AI_API_KEY")
    api_url = os.getenv("AI_API_URL")
    model = os.getenv("AI_MODEL")
    if not api_key or not api_url or not model:
        raise ValueError("لم يتم إعداد مزود AI السحابي")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt + "\n\n" + case_text}
        ]
    }
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(
            api_url, json=payload,
            headers={"Authorization": "Bearer " + api_key}
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

# ==================================================
# APPLICATION
# ==================================================

def main(page: ft.Page):
    initialize()
    page.title = "SecureCaseDesk 3.0"
    page.rtl = True
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 15
    page.scroll = ft.ScrollMode.AUTO
    current_user = None

    def notify(message):
        page.snack_bar = ft.SnackBar(content=ft.Text(message))
        page.snack_bar.open = True
        page.update()

    def header():
        return ft.Row([
            ft.Text("SECURECASE DESK", size=21, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            ft.Icon(ft.Icons.SHIELD, color=ft.Colors.BLUE)
        ])

    def login_screen():
        page.controls.clear()
        username = ft.TextField(label="اسم المستخدم", autofocus=True)
        password = ft.TextField(label="كلمة المرور", password=True, can_reveal_password=True)

        def login(e):
            nonlocal current_user
            with connect() as db:
                user = db.execute(
                    "SELECT * FROM users WHERE username=? AND active=1",
                    (username.value.strip(),)
                ).fetchone()
            if not user:
                notify("بيانات الدخول غير صحيحة")
                return
            try:
                ph.verify(user["password"], password.value)
            except Exception:
                notify("بيانات الدخول غير صحيحة")
                return
            current_user = user
            audit(user["username"], "LOGIN", "User login")
            dashboard()

        page.add(ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.SHIELD, size=65, color=ft.Colors.BLUE),
                ft.Text("SecureCaseDesk 3.0", size=25, weight=ft.FontWeight.BOLD),
                ft.Text("نظام إدارة القضايا الأمنية"),
                username, password,
                ft.Button("تسجيل الدخول", icon=ft.Icons.LOGIN, on_click=login)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=18),
            padding=25, width=430, alignment=ft.Alignment.CENTER
        ))
        page.update()

    def dashboard():
        page.controls.clear()
        role_names = {
            "admin": "مدير النظام", "manager": "مدير البحث",
            "officer": "ضابط", "auditor": "مدقق"
        }
        cases = get_cases(current_user)
        open_count = sum(1 for c in cases if c["status"] == "مفتوحة")
        pending_count = sum(1 for c in cases if c["status"] == "قيد التحقيق")
        closed_count = sum(1 for c in cases if c["status"] == "مغلقة")

        def card(label, value, icon):
            return ft.Container(
                content=ft.Column([
                    ft.Icon(icon, size=28, color=ft.Colors.BLUE),
                    ft.Text(str(value), size=26, weight=ft.FontWeight.BOLD),
                    ft.Text(label)
                ]),
                padding=15,
                border=ft.Border.all(1, ft.Colors.OUTLINE),
                border_radius=12, expand=True
            )

        def logout(e):
            nonlocal current_user
            current_user = None
            login_screen()

        def backup_action(e=None):
            result = create_backup(current_user)
            notify("تم إنشاء النسخة: " + str(result) if result else "فشل إنشاء النسخة")

        controls = [
            header(),
            ft.Text("مرحباً، " + current_user["username"], size=18),
            ft.Text("الصلاحية: " + role_names.get(current_user["role"], "مستخدم")),
            ft.Row([
                card("إجمالي القضايا", len(cases), ft.Icons.FOLDER),
                card("مفتوحة", open_count, ft.Icons.FOLDER_OPEN),
            ]),
            ft.Row([
                card("قيد التحقيق", pending_count, ft.Icons.SEARCH),
                card("مغلقة", closed_count, ft.Icons.CHECK_CIRCLE),
            ]),
            ft.Divider(),
            ft.Button("عرض القضايا", icon=ft.Icons.FOLDER, on_click=lambda e: case_screen()),
        ]
        if current_user["role"] != "auditor":
            controls.append(ft.Button("إنشاء قضية", icon=ft.Icons.ADD, on_click=lambda e: create_screen()))
        controls.append(ft.Button("مساعد الذكاء الاصطناعي", icon=ft.Icons.AUTO_AWESOME, on_click=lambda e: ai_page()))
        if current_user["role"] in ("admin", "manager"):
            controls.append(ft.Button("سجل التدقيق", icon=ft.Icons.HISTORY, on_click=lambda e: logs_page()))
        if current_user["role"] == "admin":
            controls.extend([
                ft.Button("إدارة المستخدمين", icon=ft.Icons.PEOPLE, on_click=lambda e: users_page()),
                ft.Button("إنشاء نسخة احتياطية", icon=ft.Icons.BACKUP, on_click=backup_action)
            ])
        controls.append(ft.OutlinedButton("تسجيل الخروج", icon=ft.Icons.LOGOUT, on_click=logout))
        page.add(ft.Column(controls, spacing=12))
        page.update()

    def create_screen():
        page.controls.clear()
        title = ft.TextField(label="عنوان القضية")
        details = ft.TextField(label="تفاصيل القضية", multiline=True, min_lines=5, max_lines=10)
        department = ft.TextField(label="الإدارة", value=current_user["department"])

        def save(e):
            if not title.value or not details.value:
                notify("أدخل عنوان القضية وتفاصيلها")
                return
            if current_user["role"] == "officer" and department.value != current_user["department"]:
                notify("لا يمكنك إنشاء قضية لإدارة أخرى")
                return
            cid = create_case(current_user, title.value, details.value, department.value)
            notify("تم إنشاء القضية رقم " + str(cid))
            case_screen()

        page.add(
            header(),
            ft.Text("إنشاء قضية جديدة", size=23),
            title, details, department,
            ft.Button("حفظ القضية", on_click=save),
            ft.TextButton("رجوع", on_click=lambda e: dashboard())
        )
        page.update()

    def case_screen():
        page.controls.clear()
        controls = [header(), ft.Text("سجل القضايا", size=24)]
        for case in get_cases(current_user):
            cid = case["id"]
            controls.append(ft.Container(
                content=ft.Column([
                    ft.Text("قضية #" + str(cid), weight=ft.FontWeight.BOLD),
                    ft.Text(dec(case["title"])),
                    ft.Text("الإدارة: " + case["department"]),
                    ft.Text("الحالة: " + case["status"]),
                    ft.Button("فتح القضية", on_click=lambda e, x=cid: detail_screen(x))
                ]),
                padding=12,
                border=ft.Border.all(1, ft.Colors.OUTLINE),
                border_radius=10
            ))
        controls.append(ft.TextButton("الرئيسية", on_click=lambda e: dashboard()))
        page.add(ft.Column(controls, spacing=12))
        page.update()

    def detail_screen(cid):
        case = get_case(cid, current_user)
        if not case:
            notify("لا توجد صلاحية للوصول")
            return
        page.controls.clear()
        title = ft.TextField(label="عنوان القضية", value=dec(case["title"]))
        details = ft.TextField(label="التفاصيل", value=dec(case["details"]), multiline=True, min_lines=5, max_lines=12)
        status = ft.Dropdown(label="حالة القضية", value=case["status"], options=[
            ft.dropdown.Option("مفتوحة"),
            ft.dropdown.Option("قيد التحقيق"),
            ft.dropdown.Option("مغلقة")
        ])
        file_path = ft.TextField(label="مسار ملف PDF أو الصورة داخل الهاتف")
        extra = ft.TextField(label="شرح إضافي للتقرير (اختياري)", multiline=True)

        def save(e):
            if update_case(current_user, cid, title.value, details.value, status.value):
                notify("تم تحديث القضية")
                detail_screen(cid)
            else:
                notify("ليس لديك صلاحية التعديل")

        def attach(e):
            if add_attachment(current_user, cid, file_path.value):
                notify("تم تشفير المرفق وحفظه")
            else:
                notify("تعذر إضافة المرفق")

        def report(e):
            result = export_report(current_user, cid, extra.value)
            notify("تم إنشاء التقرير: " + str(result) if result else "تعذر إنشاء التقرير")

        def delete(e):
            if delete_case(current_user, cid):
                notify("تم حذف القضية")
                case_screen()
            else:
                notify("لا تملك صلاحية الحذف")

        with connect() as db:
            attachments = db.execute("SELECT * FROM attachments WHERE case_id=?", (cid,)).fetchall()

        controls = [header(), ft.Text("القضية رقم " + str(cid), size=24), title, details,
                    ft.Text("الإدارة: " + case["department"]), status]
        if current_user["role"] != "auditor":
            controls.extend([ft.Button("حفظ التعديلات", on_click=save), ft.Divider(),
                             file_path, ft.Button("إرفاق ملف مشفر", on_click=attach)])
        controls.append(ft.Text("المرفقات:", weight=ft.FontWeight.BOLD))
        controls.extend([ft.Text(a["filename"]) for a in attachments])
        controls.extend([ft.Divider(), extra,
                         ft.Button("إنشاء تقرير Word", icon=ft.Icons.DESCRIPTION, on_click=report)])
        if current_user["role"] in ("admin", "manager"):
            controls.append(ft.Button("حذف القضية", icon=ft.Icons.DELETE, on_click=delete))
        controls.append(ft.TextButton("رجوع", on_click=lambda e: case_screen()))
        page.add(ft.Column(controls, spacing=12))
        page.update()

    def users_page():
        page.controls.clear()
        username = ft.TextField(label="اسم المستخدم")
        password = ft.TextField(label="كلمة المرور", password=True)
        department = ft.TextField(label="الإدارة")
        role = ft.Dropdown(label="الدور", value="officer", options=[
            ft.dropdown.Option("officer"),
            ft.dropdown.Option("manager"),
            ft.dropdown.Option("auditor"),
            ft.dropdown.Option("admin")
        ])

        def add_user(e):
            if not username.value or not password.value:
                notify("أكمل البيانات")
                return
            if len(password.value) < 12:
                notify("كلمة المرور يجب أن تكون 12 حرفاً على الأقل")
                return
            try:
                with connect() as db:
                    db.execute("""
                        INSERT INTO users(username,password,role,department)
                        VALUES(?,?,?,?)
                    """, (username.value.strip(), ph.hash(password.value), role.value, department.value))
                audit(current_user["username"], "CREATE_USER", username.value)
                notify("تم إنشاء المستخدم")
                users_page()
            except sqlite3.IntegrityError:
                notify("اسم المستخدم موجود مسبقاً")

        with connect() as db:
            users = db.execute("SELECT id,username,role,department,active FROM users").fetchall()

        controls = [header(), ft.Text("إدارة المستخدمين", size=24),
                    username, password, department, role,
                    ft.Button("إنشاء حساب", on_click=add_user), ft.Divider(),
                    ft.Text("الحسابات الحالية", weight=ft.FontWeight.BOLD)]
        for u in users:
            controls.append(ft.Text(f'{u["username"]} | {u["role"]} | {u["department"]}'))
        controls.append(ft.TextButton("رجوع", on_click=lambda e: dashboard()))
        page.add(ft.Column(controls, spacing=10))
        page.update()

    def logs_page():
        page.controls.clear()
        with connect() as db:
            logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
        controls = [header(), ft.Text("سجل التدقيق", size=24),
                    ft.Text("سلامة السجل: " + ("سليم" if verify_audit() else "تحذير: فشل التحقق"))]
        for log in logs:
            controls.append(ft.Container(
                content=ft.Column([
                    ft.Text(log["action"], weight=ft.FontWeight.BOLD),
                    ft.Text("المستخدم: " + log["username"]),
                    ft.Text("التاريخ: " + log["timestamp"]),
                    ft.Text("التفاصيل: " + dec(log["details"]))
                ]),
                padding=10,
                border=ft.Border.all(1, ft.Colors.OUTLINE),
                border_radius=8
            ))
        controls.append(ft.TextButton("رجوع", on_click=lambda e: dashboard()))
        page.add(ft.Column(controls, spacing=10))
        page.update()

    def ai_page():
        page.controls.clear()
        case_id = ft.TextField(label="رقم القضية", keyboard_type=ft.KeyboardType.NUMBER)
        prompt = ft.TextField(label="اكتب طلبك للمساعد الذكي", multiline=True, min_lines=3)
        mode = ft.Dropdown(label="محرك الذكاء الاصطناعي", value="local", options=[
            ft.dropdown.Option("local", "محلي"),
            ft.dropdown.Option("cloud", "سحابي")
        ])
        output = ft.TextField(label="نتيجة المساعد", multiline=True, min_lines=10, max_lines=20, read_only=True)

        async def generate(e):
            try:
                cid = int(case_id.value)
            except Exception:
                notify("أدخل رقم قضية صحيح")
                return
            case = get_case(cid, current_user)
            if not case:
                notify("لا توجد صلاحية للوصول إلى القضية")
                return
            if not prompt.value:
                notify("اكتب طلباً للمساعد")
                return
            output.value = "جارٍ إعداد المسودة..."
            page.update()
            case_text = (
                "عنوان القضية: " + dec(case["title"]) +
                "\nالتفاصيل: " + dec(case["details"]) +
                "\nالحالة: " + case["status"] +
                "\nالإدارة: " + case["department"]
            )
            try:
                result = await ask_ai(prompt.value, case_text, mode.value)
                output.value = result
                audit(current_user["username"], "AI_REQUEST", "Case " + str(cid))
            except Exception as ex:
                output.value = "تعذر الاتصال بمحرك AI: " + str(ex)
            page.update()

        page.add(header(), ft.Text("AI Assistant", size=24),
                 case_id, mode, prompt,
                 ft.Button("إنشاء مسودة", icon=ft.Icons.AUTO_AWESOME, on_click=generate),
                 output, ft.TextButton("رجوع", on_click=lambda e: dashboard()))
        page.update()

    login_screen()

ft.run(main)
