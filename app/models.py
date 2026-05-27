from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text
from app.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")  # user, admin, security_admin
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)

class PrivilegeRequest(Base):
    __tablename__ = "privilege_requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_system = Column(String)
    requested_role = Column(String)
    justification = Column(Text)
    duration_minutes = Column(Integer)
    status = Column(String, default="pending")
    created_at = Column(String)
    expires_at = Column(String, nullable=True)

class ActivePrivilege(Base):
    __tablename__ = "active_privileges"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    request_id = Column(Integer, ForeignKey("privilege_requests.id"))
    role = Column(String)
    expires_at = Column(String)
    is_active = Column(Boolean, default=True)

class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True)
    user_role = Column(String)
    target_role = Column(String)
    max_duration = Column(Integer, default=60)
    require_mfa = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    event_type = Column(String)
    description = Column(Text)
    ip_address = Column(String, nullable=True)
    timestamp = Column(String)