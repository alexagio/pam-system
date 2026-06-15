from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import bcrypt
import pyotp
import uuid
import os
import subprocess

import aiosmtplib
from email.message import EmailMessage

from app.database import engine, SessionLocal, Base
from app.models import User, PrivilegeRequest, ActivePrivilege, Policy, AuditLog

Base.metadata.create_all(bind=engine)

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Временное хранилище сессий
sessions = {}

scheduler = BackgroundScheduler()
scheduler.start()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

FORBIDDEN_PATTERNS = [
    "rm -rf /",
    "shutdown",
    "format",
    "del /f",
    "drop table",
    "truncate table",
]


@app.post("/api/execute_command")
async def execute_command(token: str, command: str, db: Session = Depends(get_db)):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    session_data = sessions[token]
    user_id = session_data["user_id"]

    # Проверка активных привилегий
    active = db.query(ActivePrivilege).filter(
        ActivePrivilege.user_id == user_id,
        ActivePrivilege.is_active == True
    ).first()

    if not active:
        raise HTTPException(status_code=403, detail="Недостаточно прав. Запросите повышение привилегий.")

    # Сигнатурный анализ
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.lower() in command.lower():
            log = AuditLog(
                user_id=user_id,
                event_type="command_blocked",
                description=f"Заблокирована опасная команда: {command}",
                ip_address="127.0.0.1",
                timestamp=datetime.now().isoformat()
            )
            db.add(log)
            db.commit()
            return {"status": "blocked", "reason": f"Обнаружен запрещённый шаблон: {pattern}"}

    # Запись в аудит
    log = AuditLog(
        user_id=user_id,
        event_type="command_executed",
        description=f"Выполнена команда: {command}",
        ip_address="127.0.0.1",
        timestamp=datetime.now().isoformat()
    )
    db.add(log)
    db.commit()

    # Реальное выполнение команды
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        error = result.stderr
        if result.returncode != 0:
            output = error if error else f"Ошибка (код {result.returncode})"
    except subprocess.TimeoutExpired:
        output = "Ошибка: превышено время выполнения"
    except Exception as e:
        output = f"Ошибка: {str(e)}"

    return {"status": "executed", "command": command, "output": output}


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.post("/api/register")
async def register(
        username: str,
        password: str,
        db: Session = Depends(get_db)
):
    # Проверка логина
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Логин должен быть не менее 3 символов")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Пользователь уже существует")

    # Проверка пароля
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Пароль должен быть не менее 8 символов")
    if not any(c.isupper() for c in password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну заглавную букву")
    if not any(c.islower() for c in password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну строчную букву")
    if not any(c.isdigit() for c in password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну цифру")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = User(username=username, password_hash=hashed.decode())
    db.add(user)
    db.commit()
    return {"message": "Пользователь создан"}


@app.post("/api/setup_totp")
async def setup_totp(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.totp_enabled = True
    db.commit()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="PAM_System")

    return {"secret": secret, "uri": uri, "message": "Отсканируйте QR-код в приложении-аутентификаторе"}


@app.post("/api/login")
async def login(
        username: str,
        password: str,
        totp_code: str = None,
        db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    # Проверка контекстных аномалий
    import socket
    client_ip = "127.0.0.1"  # в реальности — из request.client.host
    current_hour = datetime.now().hour

    if current_hour < 8 or current_hour > 20:
        log = AuditLog(
            user_id=user.id,
            event_type="context_anomaly",
            description=f"Вход в нерабочее время: {current_hour}:00, IP: {client_ip}",
            ip_address=client_ip,
            timestamp=datetime.now().isoformat()
        )
        db.add(log)
        db.commit()

    if user.totp_enabled:
        if not totp_code:
            return {"require_totp": True}
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code):
            user.failed_attempts += 1
            if user.failed_attempts >= 3:
                user.is_blocked = True
            db.commit()
            raise HTTPException(status_code=401, detail="Неверный TOTP-код")

    user.failed_attempts = 0
    db.commit()

    token = str(uuid.uuid4())
    sessions[token] = {"username": username, "user_id": user.id, "role": user.role}

    return {"token": token, "role": user.role}


def revoke_privilege_by_id(privilege_id: int, db: Session):
    """Автоматический отзыв привилегии по истечении времени."""
    priv = db.query(ActivePrivilege).filter(ActivePrivilege.id == privilege_id).first()
    if priv and priv.is_active:
        priv.is_active = False

        # Запись в журнал аудита
        log = AuditLog(
            user_id=priv.user_id,
            event_type="privilege_revoked",
            description=f"Привилегия {priv.role} автоматически отозвана по истечении времени",
            ip_address="127.0.0.1",
            timestamp=datetime.now().isoformat()
        )
        db.add(log)
        db.commit()
        print(f"[INFO] Привилегия {privilege_id} автоматически отозвана")


@app.post("/api/revoke_privilege")
async def revoke_privilege(token: str, db: Session = Depends(get_db)):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    session_data = sessions[token]
    user_id = session_data["user_id"]

    active = db.query(ActivePrivilege).filter(
        ActivePrivilege.user_id == user_id,
        ActivePrivilege.is_active == True
    ).first()

    if not active:
        raise HTTPException(status_code=404, detail="Нет активных привилегий")

    active.is_active = False

    # Обновляем статус заявки
    req = db.query(PrivilegeRequest).filter(
        PrivilegeRequest.id == active.request_id
    ).first()
    if req:
        req.status = "revoked"
        req.revoked_at = datetime.now().isoformat()

    # Запись в аудит
    log = AuditLog(
        user_id=user_id,
        event_type="privilege_revoked",
        description=f"Привилегия {active.role} отозвана пользователем досрочно",
        ip_address="127.0.0.1",
        timestamp=datetime.now().isoformat()
    )
    db.add(log)
    db.commit()

    return {"message": "Привилегии отозваны"}
@app.post("/api/request_privilege")
async def request_privilege(
        token: str,
        target_system: str,
        requested_role: str,
        justification: str,
        duration_minutes: int,
        db: Session = Depends(get_db)
):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    session_data = sessions[token]
    user = db.query(User).filter(User.id == session_data["user_id"]).first()

    # Проверка политик
    policy = db.query(Policy).filter(
        Policy.user_role == user.role,
        Policy.target_role == requested_role,
        Policy.is_active == True
    ).first()

    if policy:
        if duration_minutes > policy.max_duration:
            raise HTTPException(status_code=400, detail=f"Максимальная длительность: {policy.max_duration} мин")
        if policy.require_mfa and not user.totp_enabled:
            raise HTTPException(status_code=400, detail="Требуется настроенный второй фактор")

    now = datetime.now()
    expires = now + timedelta(minutes=duration_minutes)

    req = PrivilegeRequest(
        user_id=user.id,
        target_system=target_system,
        requested_role=requested_role,
        justification=justification,
        duration_minutes=duration_minutes,
        status="approved",
        created_at=now.isoformat(),
        expires_at=expires.isoformat()
    )
    db.add(req)
    db.flush()

    active = ActivePrivilege(
        user_id=user.id,
        request_id=req.id,
        role=requested_role,
        expires_at=expires.isoformat()
    )
    db.add(active)

    # Запись в аудит
    log = AuditLog(
        user_id=user.id,
        event_type="privilege_granted",
        description=f"Предоставлены права {requested_role} на {target_system} до {expires}",
        timestamp=now.isoformat()
    )
    db.add(log)
    db.commit()
    # Планирование автоматического отзыва
    scheduler.add_job(
        revoke_privilege_by_id,
        trigger=DateTrigger(run_date=expires),
        args=[active.id, db],
        id=f"revoke_{active.id}",
        replace_existing=True
    )
    return {"message": "Привилегии предоставлены", "expires_at": expires.isoformat()}


@app.get("/api/audit_log")
async def get_audit_log(token: str, db: Session = Depends(get_db)):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
    return [
        {
            "event_type": l.event_type,
            "description": l.description,
            "timestamp": l.timestamp
        }
        for l in logs
    ]


# ==================== УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ====================

@app.get("/api/users")
async def get_users(token: str, db: Session = Depends(get_db)):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    session_data = sessions[token]
    user = db.query(User).filter(User.id == session_data["user_id"]).first()

    if user.role != "security_admin":
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "totp_enabled": u.totp_enabled,
            "is_blocked": u.is_blocked,
            "failed_attempts": u.failed_attempts
        }
        for u in users
    ]


# ==================== ДАШБОРД ====================

@app.get("/api/dashboard")
async def get_dashboard(token: str, db: Session = Depends(get_db)):
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Не авторизован")

    today = datetime.now().isoformat()[:10]

    total_users = db.query(User).count()
    active_privileges = db.query(ActivePrivilege).filter(
        ActivePrivilege.is_active == True
    ).count()
    today_events = db.query(AuditLog).filter(
        AuditLog.timestamp.like(f"{today}%")
    ).count()
    blocked_commands = db.query(AuditLog).filter(
        AuditLog.event_type == "command_blocked"
    ).count()
    total_logins = db.query(AuditLog).filter(
        AuditLog.event_type == "auth_success"
    ).count()

    return {
        "total_users": total_users,
        "active_privileges": active_privileges,
        "today_events": today_events,
        "blocked_commands": blocked_commands,
        "total_logins": total_logins
    }