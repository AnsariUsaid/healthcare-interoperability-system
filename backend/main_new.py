"""
HIPAA-Compliant Healthcare Interoperability System
FastAPI Backend with Authentication, Authorization, and Audit Logging
"""
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, case
from datetime import datetime, timedelta
from typing import List, Optional
import os
import uuid
import json
from dotenv import load_dotenv

# Import our modules
import database
import security
import auth
import models
from database import (
    User, Session as DBSession, AuditLog, BreakGlassAccess, PatientConsent, SecurityEvent,
    Patient, PatientRecord, HospitalSystem, MatchingScore, CriticalAlert, DrugAllergyMatrix
)

load_dotenv()

# Initialize database
database.init_db()

# Initialize FastAPI app
app = FastAPI(
    title="Healthcare Interoperability System",
    description="HIPAA-Compliant Emergency Medical Data Exchange System",
    version="2.0.0"
)

# Rate Limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in security.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Audit Logging Middleware
@app.middleware("http")
async def audit_logging_middleware(request: Request, call_next):
    # Skip audit for non-data endpoints
    skip_paths = ["/docs", "/openapi.json", "/api/health", "/favicon.ico"]
    if any(request.url.path.startswith(path) for path in skip_paths):
        return await call_next(request)
    
    response = await call_next(request)
    
    # Log PHI access attempts
    if "/api/patients" in request.url.path or "/api/emergency-search" in request.url.path:
        try:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.replace("Bearer ", "")
                payload = security.verify_token(token)
                user_id = payload.get("sub")
                
                db = next(database.get_db())
                audit_entry = AuditLog(
                    user_id=user_id,
                    action="API_ACCESS",
                    resource_type="PHI",
                    resource_id=request.url.path,
                    ip_address=request.client.host,
                    user_agent=request.headers.get("user-agent"),
                    status="SUCCESS" if response.status_code < 400 else "FAILED",
                )
                db.add(audit_entry)
                db.commit()
                db.close()
        except:
            pass
    
    return response

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================

@app.post("/api/auth/register", response_model=models.UserResponse, tags=["Authentication"])
@limiter.limit("5/minute")
async def register_user(
    request: Request,
    user_data: models.UserRegister,
    db: Session = Depends(database.get_db)
):
    """Register a new user (Admin only in production)"""
    
    # Check if username exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    new_user = User(
        user_id=str(uuid.uuid4()),
        username=user_data.username,
        email=user_data.email,
        hashed_password=security.hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role.value,
        department=user_data.department,
        hospital_id=user_data.hospital_id,
        password_changed_date=datetime.utcnow()
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log security event
    auth.log_security_event(
        event_type="USER_REGISTERED",
        severity="LOW",
        description=f"New user registered: {user_data.username}",
        user_id=new_user.user_id,
        ip_address=request.client.host,
        db=db
    )
    
    return new_user

@app.post("/api/auth/login", response_model=models.Token, tags=["Authentication"])
@limiter.limit("10/minute")
async def login(
    request: Request,
    credentials: models.UserLogin,
    db: Session = Depends(database.get_db)
):
    """Login and receive JWT tokens"""
    
    # Find user
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user:
        # Log failed attempt
        auth.log_security_event(
            event_type="FAILED_LOGIN",
            severity="MEDIUM",
            description=f"Failed login attempt for non-existent user: {credentials.username}",
            ip_address=request.client.host,
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to failed login attempts"
        )
    
    # Verify password
    if not security.verify_password(credentials.password, user.hashed_password):
        # Increment failed attempts
        user.failed_login_attempts += 1
        
        # Lock account after max failed attempts
        if user.failed_login_attempts >= security.MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=security.ACCOUNT_LOCKOUT_MINUTES)
            auth.log_security_event(
                event_type="ACCOUNT_LOCKED",
                severity="HIGH",
                description=f"Account locked due to {security.MAX_FAILED_ATTEMPTS} failed login attempts",
                user_id=user.user_id,
                ip_address=request.client.host,
                db=db
            )
        
        db.commit()
        
        auth.log_security_event(
            event_type="FAILED_LOGIN",
            severity="MEDIUM",
            description=f"Failed login attempt for user: {credentials.username}",
            user_id=user.user_id,
            ip_address=request.client.host,
            db=db
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Reset failed login attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    
    # Create tokens
    access_token = security.create_access_token(
        data={"sub": user.user_id, "role": user.role}
    )
    refresh_token = security.create_refresh_token(
        data={"sub": user.user_id}
    )
    
    # Create session
    session_id = security.generate_session_id()
    new_session = DBSession(
        session_id=session_id,
        user_id=user.user_id,
        token=access_token,
        refresh_token=refresh_token,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        expires_at=datetime.utcnow() + timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    db.add(new_session)
    db.commit()
    
    # Log successful login
    audit_entry = AuditLog(
        user_id=user.user_id,
        action="LOGIN",
        resource_type="AUTH",
        resource_id=session_id,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        status="SUCCESS",
        session_id=session_id
    )
    db.add(audit_entry)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": security.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/api/auth/logout", tags=["Authentication"])
async def logout(
    current_user: User = Depends(auth.get_current_active_user),
    request: Request = None,
    db: Session = Depends(database.get_db)
):
    """Logout and revoke session"""
    
    # Get current session
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        
        # Revoke session
        session = db.query(DBSession).filter(
            DBSession.token == token,
            DBSession.user_id == current_user.user_id
        ).first()
        
        if session:
            session.is_active = False
            session.revoked = True
            session.revoked_at = datetime.utcnow()
            
            # Log logout
            audit_entry = AuditLog(
                user_id=current_user.user_id,
                action="LOGOUT",
                resource_type="AUTH",
                resource_id=session.session_id,
                ip_address=request.client.host,
                status="SUCCESS",
                session_id=session.session_id
            )
            db.add(audit_entry)
            db.commit()
    
    return {"message": "Successfully logged out"}

@app.post("/api/auth/refresh", response_model=models.Token, tags=["Authentication"])
async def refresh_token(
    token_request: models.RefreshTokenRequest,
    db: Session = Depends(database.get_db)
):
    """Refresh access token using refresh token"""
    
    try:
        payload = security.verify_token(token_request.refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
        
        user_id = payload.get("sub")
        user = db.query(User).filter(User.user_id == user_id).first()
        
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        # Create new tokens
        access_token = security.create_access_token(
            data={"sub": user.user_id, "role": user.role}
        )
        refresh_token = security.create_refresh_token(
            data={"sub": user.user_id}
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": security.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

@app.post("/api/auth/change-password", tags=["Authentication"])
async def change_password(
    password_data: models.PasswordChange,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Change user password"""
    
    # Verify old password
    if not security.verify_password(password_data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    
    # Update password
    current_user.hashed_password = security.hash_password(password_data.new_password)
    current_user.password_changed_date = datetime.utcnow()
    
    # Revoke all existing sessions for security
    db.query(DBSession).filter(DBSession.user_id == current_user.user_id).update({
        "is_active": False,
        "revoked": True,
        "revoked_at": datetime.utcnow()
    })
    
    db.commit()
    
    return {"message": "Password changed successfully. Please login again."}

# ==========================================
# USER MANAGEMENT ENDPOINTS
# ==========================================

@app.get("/api/users/me", response_model=models.UserResponse, tags=["Users"])
async def get_current_user_info(
    current_user: User = Depends(auth.get_current_active_user)
):
    """Get current logged-in user information"""
    return current_user

@app.get("/api/users", response_model=List[models.UserResponse], tags=["Users"])
async def list_users(
    current_user: User = Depends(auth.get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    """List all users (Admin only)"""
    users = db.query(User).all()
    return users

@app.put("/api/users/me", response_model=models.UserResponse, tags=["Users"])
async def update_current_user(
    user_update: models.UserUpdate,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Update current user information"""
    
    if user_update.email:
        current_user.email = user_update.email
    if user_update.full_name:
        current_user.full_name = user_update.full_name
    if user_update.department:
        current_user.department = user_update.department
    if user_update.hospital_id:
        current_user.hospital_id = user_update.hospital_id
    
    db.commit()
    db.refresh(current_user)
    
    return current_user

# ==========================================
# HEALTH CHECK (Public)
# ==========================================

@app.get("/api/health", tags=["System"])
def health_check():
    """Health check endpoint"""
    return {
        'status': 'Backend is running!',
        'version': '2.0.0',
        'hipaa_compliant': True,
        'features': [
            'JWT Authentication',
            'Role-Based Access Control',
            'Audit Logging',
            'Field-Level Encryption',
            'Break-Glass Emergency Access',
            'Session Management',
            'Rate Limiting'
        ]
    }

# ==========================================
# PROTECTED PATIENT DATA ENDPOINTS (Requires Auth)
# ==========================================

@app.get("/api/emergency-search", tags=["Patients"])
@limiter.limit("20/minute")
async def emergency_search(
    request: Request,
    first_name: str,
    last_name: str,
    dob: Optional[str] = None,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """
    Emergency Patient Search with HIPAA Compliance
    Requires authentication and logs all access
    """
    
    # Check if user has permission to view PHI
    if not security.check_permission(current_user.role, "can_view_phi"):
        raise HTTPException(status_code=403, detail="Access denied: Cannot view PHI")
    
    try:
        # Query patient with SQLAlchemy
        query = db.query(
            Patient,
            func.count(PatientRecord.hospital_id.distinct()).label('num_hospitals')
        ).outerjoin(
            PatientRecord, Patient.patient_id == PatientRecord.patient_id
        ).filter(
            Patient.first_name.ilike(f"{first_name}%"),
            Patient.last_name.ilike(f"{last_name}%")
        ).group_by(
            Patient.patient_id,
            Patient.first_name,
            Patient.last_name,
            Patient.date_of_birth,
            Patient.gender,
            Patient.ssn,
            Patient.phone,
            Patient.email,
            Patient.emergency_contact,
            Patient.created_date,
            Patient.last_updated
        )
        
        result = query.first()
        
        if not result:
            # Log failed search
            audit_entry = AuditLog(
                user_id=current_user.user_id,
                action="SEARCH",
                resource_type="PATIENT",
                resource_id=f"{first_name}_{last_name}",
                status="NOT_FOUND",
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent")
            )
            db.add(audit_entry)
            db.commit()
            
            raise HTTPException(status_code=404, detail="Patient not found")
        
        patient_obj, num_hospitals = result
        patient = {
            'patient_id': patient_obj.patient_id,
            'first_name': patient_obj.first_name,
            'last_name': patient_obj.last_name,
            'date_of_birth': patient_obj.date_of_birth,
            'gender': patient_obj.gender,
            'phone': patient_obj.phone,
            'emergency_contact': patient_obj.emergency_contact,
            'num_hospitals': num_hospitals
        }
        
        # Apply data masking based on role
        patient = security.apply_data_masking(patient, current_user.role)
        
        # Get hospital records
        records = db.query(PatientRecord, HospitalSystem).join(
            HospitalSystem, PatientRecord.hospital_id == HospitalSystem.hospital_id
        ).filter(
            PatientRecord.patient_id == patient_obj.patient_id
        ).order_by(HospitalSystem.hospital_name).all()
        
        hospital_records = []
        for record, hospital in records:
            hospital_records.append({
                'hospital': hospital.hospital_name,
                'mrn': record.mrn,
                'last_visit': record.last_visit_date,
                'medications': record.current_medications,
                'allergies': record.allergies,
                'chronic_conditions': record.chronic_conditions
            })
        
        # Get critical alerts
        alerts_db = db.query(CriticalAlert).filter(
            CriticalAlert.patient_id == patient_obj.patient_id
        ).order_by(
            case(
                (CriticalAlert.severity == 'CRITICAL', 1),
                (CriticalAlert.severity == 'HIGH', 2),
                (CriticalAlert.severity == 'MEDIUM', 3),
                else_=4
            )
        ).all()
        
        alerts = []
        for alert in alerts_db:
            alerts.append({
                'alert_id': alert.alert_id,
                'type': alert.alert_type,
                'description': alert.description,
                'severity': alert.severity,
                'details': alert.alert_details,
                'acknowledged': alert.acknowledged
            })
        
        # Log successful access
        audit_entry = AuditLog(
            user_id=current_user.user_id,
            patient_id=patient_obj.patient_id,
            action="VIEW",
            resource_type="PATIENT_FULL_RECORD",
            resource_id=str(patient_obj.patient_id),
            status="SUCCESS",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
            data_accessed="patient_info,hospital_records,alerts"
        )
        db.add(audit_entry)
        db.commit()
        
        return {
            'patient': patient,
            'hospital_records': hospital_records,
            'alerts': alerts,
            '_audit': {
                'accessed_by': current_user.username,
                'access_time': datetime.utcnow().isoformat(),
                'data_masked': current_user.role in ["NURSE", "PATIENT"]
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/patients", tags=["Patients"])
async def get_all_patients(
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Get all patients (with appropriate access control)"""
    
    if not security.check_permission(current_user.role, "can_view_phi"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        # Query all patients with SQLAlchemy
        patients_db = db.query(Patient).order_by(Patient.last_name, Patient.first_name).all()
        
        patients = []
        for patient_obj in patients_db:
            patient = {
                'patient_id': patient_obj.patient_id,
                'first_name': patient_obj.first_name,
                'last_name': patient_obj.last_name,
                'date_of_birth': patient_obj.date_of_birth,
                'gender': patient_obj.gender,
                'phone': patient_obj.phone
            }
            # Apply data masking
            patient = security.apply_data_masking(patient, current_user.role)
            patients.append(patient)
        
        return {'patients': patients, 'count': len(patients)}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# AUDIT LOG ENDPOINTS
# ==========================================

@app.get("/api/audit-logs", response_model=List[models.AuditLogResponse], tags=["Audit"])
async def get_audit_logs(
    patient_id: Optional[int] = None,
    user_id: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """
    Get audit logs
    Admins can see all logs, Users can see their own logs
    """
    
    query = db.query(AuditLog)
    
    # Non-admin users can only see their own logs
    if current_user.role != "ADMIN":
        query = query.filter(AuditLog.user_id == current_user.user_id)
    else:
        # Admin can filter by user_id
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
    
    # Filter by patient_id
    if patient_id:
        query = query.filter(AuditLog.patient_id == patient_id)
    
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    return logs

@app.get("/api/audit-logs/patient/{patient_id}", response_model=List[models.AuditLogResponse], tags=["Audit"])
async def get_patient_audit_logs(
    patient_id: int,
    current_user: User = Depends(auth.get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    """Get all access logs for a specific patient (Admin only)"""
    
    logs = db.query(AuditLog).filter(
        AuditLog.patient_id == patient_id
    ).order_by(AuditLog.timestamp.desc()).all()
    
    return logs

# ==========================================
# BREAK-GLASS EMERGENCY ACCESS
# ==========================================

@app.post("/api/emergency-access", response_model=models.BreakGlassResponse, tags=["Emergency"])
async def break_glass_access(
    access_request: models.BreakGlassRequest,
    request: Request,
    current_user: User = Depends(auth.verify_emergency_access),
    db: Session = Depends(database.get_db)
):
    """
    Break-glass emergency access to patient data
    Requires EMERGENCY role and detailed justification
    """
    
    # Log break-glass access
    break_glass = BreakGlassAccess(
        user_id=current_user.user_id,
        patient_id=access_request.patient_id,
        justification=access_request.justification,
        emergency_type=access_request.emergency_type,
        ip_address=request.client.host
    )
    
    db.add(break_glass)
    db.commit()
    db.refresh(break_glass)
    
    # Create audit log
    audit_entry = AuditLog(
        user_id=current_user.user_id,
        patient_id=access_request.patient_id,
        action="BREAK_GLASS_ACCESS",
        resource_type="EMERGENCY_OVERRIDE",
        resource_id=str(access_request.patient_id),
        status="SUCCESS",
        ip_address=request.client.host,
        justification=access_request.justification
    )
    db.add(audit_entry)
    db.commit()
    
    return break_glass

# ==========================================
# PATIENT CONSENT MANAGEMENT
# ==========================================

@app.post("/api/consents", response_model=models.ConsentResponse, tags=["Consent"])
async def create_consent(
    consent: models.ConsentCreate,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Create or update patient consent"""
    
    new_consent = PatientConsent(
        patient_id=consent.patient_id,
        consent_type=consent.consent_type,
        granted=consent.granted,
        granted_date=datetime.utcnow() if consent.granted else None,
        granted_to_role=consent.granted_to_role,
        expires_at=consent.expires_at,
        scope=str(consent.scope) if consent.scope else None
    )
    
    db.add(new_consent)
    db.commit()
    db.refresh(new_consent)
    
    return new_consent

@app.get("/api/consents/patient/{patient_id}", response_model=List[models.ConsentResponse], tags=["Consent"])
async def get_patient_consents(
    patient_id: int,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Get all consents for a patient"""
    
    consents = db.query(PatientConsent).filter(
        PatientConsent.patient_id == patient_id
    ).all()
    
    return consents

# ==========================================
# SESSION MANAGEMENT
# ==========================================

@app.get("/api/sessions", response_model=List[models.SessionResponse], tags=["Sessions"])
async def get_active_sessions(
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Get all active sessions for current user"""
    
    sessions = db.query(DBSession).filter(
        DBSession.user_id == current_user.user_id,
        DBSession.is_active == True,
        DBSession.revoked == False
    ).all()
    
    return sessions

@app.delete("/api/sessions/{session_id}", tags=["Sessions"])
async def revoke_session(
    session_id: str,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Revoke a specific session"""
    
    session = db.query(DBSession).filter(
        DBSession.session_id == session_id,
        DBSession.user_id == current_user.user_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session.is_active = False
    session.revoked = True
    session.revoked_at = datetime.utcnow()
    
    db.commit()
    
    return {"message": "Session revoked successfully"}

# ==========================================
# SECURITY MONITORING
# ==========================================

@app.get("/api/security-events", response_model=List[models.SecurityEventResponse], tags=["Security"])
async def get_security_events(
    limit: int = 100,
    current_user: User = Depends(auth.get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    """Get recent security events (Admin only)"""
    
    events = db.query(SecurityEvent).order_by(
        SecurityEvent.timestamp.desc()
    ).limit(limit).all()
    
    return events

@app.get("/api/stats", response_model=models.SystemStats, tags=["System"])
async def get_system_stats(
    current_user: User = Depends(auth.get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    """Get system statistics (Admin only)"""
    
    total_users = db.query(User).count()
    active_sessions = db.query(DBSession).filter(
        DBSession.is_active == True,
        DBSession.expires_at > datetime.utcnow()
    ).count()
    
    total_audit_logs = db.query(AuditLog).count()
    
    failed_logins = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "FAILED_LOGIN",
        SecurityEvent.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    security_events_24h = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    break_glass_24h = db.query(BreakGlassAccess).filter(
        BreakGlassAccess.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_audit_logs": total_audit_logs,
        "failed_login_attempts": failed_logins,
        "security_events_last_24h": security_events_24h,
        "break_glass_accesses_last_24h": break_glass_24h
    }

# ==========================================
# LEGACY ENDPOINTS (Kept for compatibility)
# ==========================================

@app.get("/api/matching-scores", tags=["Legacy"])
async def get_matching_scores(
    patient_id: int,
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Get matching scores (requires authentication now)"""
    try:
        # Query matching scores with SQLAlchemy
        matches_db = db.query(
            MatchingScore,
            Patient.first_name.label('p1_first'),
            Patient.last_name.label('p1_last'),
            HospitalSystem.hospital_name.label('h1_name')
        ).join(
            Patient, MatchingScore.patient_id_1 == Patient.patient_id
        ).join(
            HospitalSystem, MatchingScore.hospital_id_1 == HospitalSystem.hospital_id
        ).filter(
            or_(MatchingScore.patient_id_1 == patient_id, MatchingScore.patient_id_2 == patient_id)
        ).all()
        
        matches = []
        for match, p1_first, p1_last, h1_name in matches_db:
            # Get second patient info
            p2 = db.query(Patient).filter(Patient.patient_id == match.patient_id_2).first()
            h2 = db.query(HospitalSystem).filter(HospitalSystem.hospital_id == match.hospital_id_2).first()
            
            matches.append({
                'match_id': match.match_id,
                'patient_1': f"{p1_first} {p1_last}",
                'patient_2': f"{p2.first_name} {p2.last_name}" if p2 else "Unknown",
                'hospital_1': h1_name,
                'hospital_2': h2.hospital_name if h2 else "Unknown",
                'confidence_score': float(match.overall_confidence_score) if match.overall_confidence_score else 0.0,
                'first_name_score': float(match.first_name_score) if match.first_name_score else 0.0,
                'last_name_score': float(match.last_name_score) if match.last_name_score else 0.0,
                'dob_score': float(match.dob_score) if match.dob_score else 0.0,
                'ssn_score': float(match.ssn_score) if match.ssn_score else 0.0
            })
        
        return {'matches': matches}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/drug-interactions", tags=["Legacy"])
async def get_drug_interactions(
    current_user: User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Get drug interactions (requires authentication now)"""
    try:
        # Query drug interactions with SQLAlchemy
        interactions_db = db.query(DrugAllergyMatrix).filter(
            DrugAllergyMatrix.interaction_severity.in_(['CONTRAINDICATED', 'SIGNIFICANT'])
        ).order_by(DrugAllergyMatrix.interaction_severity.desc(), DrugAllergyMatrix.drug_name).all()
        
        interactions = []
        for interaction in interactions_db:
            interactions.append({
                'drug': interaction.drug_name,
                'allergen': interaction.allergen_name,
                'severity': interaction.interaction_severity,
                'description': interaction.interaction_description
            })
        
        return {'interactions': interactions}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
