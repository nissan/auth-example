from typing import Union, Optional
from fastapi import FastAPI, status, Body, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, constr, validator
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, LargeBinary, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import uuid
import logging
import os
from jose import JWTError, jwt
from pathlib import Path

# ===================== SQLAlchemy setup ===========================
DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===================== SQLAlchemy Models ===========================
class User(Base):
    """User model storing basic user information"""
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    date_of_birth = Column(DateTime, nullable=False)
    job_title = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)  # "user" or "admin"
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to WebAuthn credentials
    credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan")

    @property
    def full_name(self) -> str:
        """Return full name (first + last)"""
        return f"{self.first_name} {self.last_name}"

class WebAuthnCredential(Base):
    """WebAuthn credential model storing public keys and metadata"""
    __tablename__ = "webauthn_credentials"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    # credential_id: unique identifier from the authenticator (stored as bytes)
    credential_id = Column(LargeBinary, unique=True, nullable=False, index=True)
    # public_key: the public key for signature verification (stored as bytes)
    public_key = Column(LargeBinary, nullable=False)
    # sign_count: counter to prevent replay attacks
    sign_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to user
    user = relationship("User", back_populates="credentials")

class AuditLog(Base):
    """Audit log for tracking authentication and authorization events"""
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String, nullable=False, index=True)  # e.g., 'registration', 'login', 'access'
    user_email = Column(String, nullable=True, index=True)  # Email if known
    user_id = Column(String, ForeignKey("users.id"), nullable=True)  # User ID if authenticated
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Integer, nullable=False)  # 1 for success, 0 for failure
    details = Column(Text, nullable=True)  # Additional context (e.g., error messages)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationship to user (optional, for successful events)
    user = relationship("User", foreign_keys=[user_id])


#---------------------------------------------------------------------
# Configure logging once at startup
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),              # prints to console
        logging.FileHandler("app.log")
    ],
)
logger = logging.getLogger(__name__)

# ===================== Configuration ===========================
# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

# WebAuthn Configuration
RP_ID = os.getenv("RP_ID", "localhost")  # Relying Party ID (your domain)
RP_NAME = os.getenv("RP_NAME", "Auth Example")  # Relying Party Name
ORIGIN = os.getenv("ORIGIN", "http://localhost:8000")  # Expected origin

# In-memory storage for challenges (in production, use Redis or similar)
registration_challenges = {}  # email -> challenge
authentication_challenges = {}  # email -> challenge

# ===================== FastAPI App ===========================
app = FastAPI(title="WebAuthn Authentication Backend")

# Add CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ===================== Utility Functions ===========================
def get_client_ip(request: Request) -> str:
    """Extract client IP address from request, handling proxies."""
    # Check X-Forwarded-For header (set by proxies/load balancers)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (alternative proxy header)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client IP
    if request.client:
        return request.client.host

    return "unknown"

def get_user_agent(request: Request) -> str:
    """Extract user agent from request headers."""
    return request.headers.get("User-Agent", "unknown")

def create_audit_log(
    db: Session,
    event_type: str,
    user_email: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
    details: Optional[str] = None
):
    """Create an audit log entry."""
    audit_entry = AuditLog(
        event_type=event_type,
        user_email=user_email,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=1 if success else 0,
        details=details
    )
    db.add(audit_entry)
    db.commit()

# Create database tables on startup
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")

# Root endpoint - serve demo frontend
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the WebAuthn demo page"""
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse(
        content="<h1>WebAuthn Backend</h1><p>API is running. Demo frontend not yet installed.</p><p>Visit <a href='/docs'>/docs</a> for API documentation.</p>",
        status_code=200
    )

# ===================== JWT Utilities ===========================
def create_access_token(data: dict) -> str:
    """
    Create a JWT access token.

    Args:
        data: Dictionary containing claims to encode in the token

    Returns:
        Encoded JWT token as string
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": "auth-example-backend"
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str) -> dict:
    """
    Verify and decode a JWT access token.

    Args:
        token: The JWT token string to verify

    Returns:
        Dictionary containing the decoded token claims

    Raises:
        JWTError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"JWT verification failed: {str(e)}")
        raise


# ===================== Authentication Dependency ===========================
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency that validates JWT token and returns the current user.

    This is used to protect endpoints that require authentication.

    Args:
        credentials: The HTTP Authorization header credentials
        db: Database session

    Returns:
        User object of the authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        token = credentials.credentials
        payload = verify_access_token(token)
        user_id = payload.get("sub")

        if user_id is None:
            logger.warning("Token missing 'sub' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Fetch user from database
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            logger.warning(f"User not found for token: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ===================== Pydantic Models ===========================
class UserRegistrationRequest(BaseModel):
    """Request model for initiating user registration"""
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    date_of_birth: datetime
    job_title: str

class UserViewModel(BaseModel):
    """Response model for user data (excludes sensitive info)"""
    id: str
    first_name: str
    last_name: str
    email: EmailStr
    date_of_birth: datetime
    job_title: str
    role: str
    created_at: datetime

class RegistrationCompleteRequest(BaseModel):
    """Request model for completing WebAuthn registration"""
    email: EmailStr
    credential: dict  # The WebAuthn credential from the browser

class LoginBeginRequest(BaseModel):
    """Request model for initiating login"""
    email: EmailStr

class LoginCompleteRequest(BaseModel):
    """Request model for completing WebAuthn login"""
    email: EmailStr
    assertion: dict  # The WebAuthn assertion from the browser


# ===================== WebAuthn Registration Endpoints ===========================

@app.post("/users", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
def register_user_redirect():
    """
    Redirect POST /users to /register/begin for spec compatibility.

    The original spec requested POST /users for registration, but WebAuthn
    requires a two-step process (begin + complete). This endpoint redirects
    to /register/begin to maintain some level of spec compatibility while
    supporting the WebAuthn protocol.

    Returns a 307 Temporary Redirect, which preserves the POST method and body.
    """
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/register/begin", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.post("/register/begin")
def register_begin(
    user_data: UserRegistrationRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiate user registration with WebAuthn.

    This endpoint:
    1. Validates that the email doesn't already exist
    2. Generates WebAuthn registration options (challenge)
    3. Stores the challenge temporarily for verification
    4. Returns options for the browser to create a credential
    """
    # Extract IP and user agent for audit logging
    ip_address = get_client_ip(http_request)
    user_agent = get_user_agent(http_request)

    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        logger.warning(f"Registration attempt with existing email: {user_data.email} from IP: {ip_address}")
        # Log failed registration attempt
        create_audit_log(
            db=db,
            event_type="registration_begin",
            user_email=user_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details="Email already registered"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists"
        )

    # Import WebAuthn utilities
    from webauthn import generate_registration_options
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import (
        PublicKeyCredentialCreationOptions,
        UserVerificationRequirement,
        AuthenticatorSelectionCriteria,
        AuthenticatorAttachment
    )

    # Generate registration options
    user_id = str(uuid.uuid4())
    user_id_bytes = user_id.encode('utf-8')  # WebAuthn requires bytes
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id_bytes,
        user_name=user_data.email,
        user_display_name=f"{user_data.first_name} {user_data.last_name}",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # TouchID
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )

    # Store challenge and user info temporarily (indexed by email)
    registration_challenges[user_data.email] = {
        "challenge": options.challenge,
        "user_id": user_id,
        "first_name": user_data.first_name,
        "last_name": user_data.last_name,
        "email": user_data.email,
        "date_of_birth": user_data.date_of_birth,
        "job_title": user_data.job_title
    }

    # Log successful registration initiation
    create_audit_log(
        db=db,
        event_type="registration_begin",
        user_email=user_data.email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True,
        details=f"Registration challenge created for {user_data.first_name} {user_data.last_name}"
    )

    logger.info(f"Registration initiated for: {user_data.email} from IP: {ip_address}")

    # Return options as JSON for the browser
    return {
        "publicKey": {
            "challenge": bytes_to_base64url(options.challenge),
            "rp": {"id": options.rp.id, "name": options.rp.name},
            "user": {
                "id": bytes_to_base64url(options.user.id),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [{"type": p.type, "alg": p.alg} for p in options.pub_key_cred_params],
            "timeout": options.timeout,
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "required"
            },
            "attestation": options.attestation
        }
    }


@app.post("/register/complete", response_model=UserViewModel, status_code=status.HTTP_201_CREATED)
def register_complete(
    reg_data: RegistrationCompleteRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Complete user registration by verifying the WebAuthn credential.

    This endpoint:
    1. Retrieves the stored challenge
    2. Verifies the credential signature
    3. Creates the user in the database
    4. Stores the public key for future authentication
    """
    # Extract IP and user agent for audit logging
    ip_address = get_client_ip(http_request)
    user_agent = get_user_agent(http_request)

    # Get the stored challenge
    if reg_data.email not in registration_challenges:
        logger.error(f"No registration challenge found for: {reg_data.email}")
        create_audit_log(
            db=db,
            event_type="registration_complete",
            user_email=reg_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details="No registration challenge found"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No registration in progress for this email"
        )

    stored_data = registration_challenges[reg_data.email]

    from webauthn import verify_registration_response
    from webauthn.helpers import base64url_to_bytes

    try:
        # Verify the registration response
        verification = verify_registration_response(
            credential=reg_data.credential,
            expected_challenge=stored_data["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN
        )

        # Create user in database (default role is "user")
        user = User(
            id=stored_data["user_id"],
            first_name=stored_data["first_name"],
            last_name=stored_data["last_name"],
            email=stored_data["email"],
            date_of_birth=stored_data["date_of_birth"],
            job_title=stored_data["job_title"],
            role="user"  # Default role for self-registration
        )
        db.add(user)

        # Store the WebAuthn credential
        credential = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count
        )
        db.add(credential)

        db.commit()
        db.refresh(user)

        # Clean up the challenge
        del registration_challenges[reg_data.email]

        # Log successful registration
        create_audit_log(
            db=db,
            event_type="registration_complete",
            user_email=user.email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details=f"User {user.full_name} registered successfully"
        )

        logger.info(f"User registered successfully: {user.full_name} ({user.email}), job: {user.job_title} from IP: {ip_address}")

        return UserViewModel(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            date_of_birth=user.date_of_birth,
            job_title=user.job_title,
            role=user.role,
            created_at=user.created_at
        )

    except Exception as e:
        logger.error(f"Registration verification failed for {reg_data.email}: {str(e)}")
        # Log failed registration
        create_audit_log(
            db=db,
            event_type="registration_complete",
            user_email=reg_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details=f"Verification failed: {str(e)}"
        )
        # Clean up the challenge on failure
        if reg_data.email in registration_challenges:
            del registration_challenges[reg_data.email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {str(e)}"
        )


# ===================== WebAuthn Login Endpoints ===========================

@app.post("/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
def login_redirect():
    """
    Redirect POST /login to /login/begin for spec compatibility.

    The original spec requested POST /login, but WebAuthn requires a two-step
    process (begin + complete). This endpoint redirects to /login/begin to
    maintain some level of spec compatibility while supporting the WebAuthn protocol.

    Returns a 307 Temporary Redirect, which preserves the POST method and body.
    """
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/login/begin", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.post("/login/begin")
def login_begin(
    login_data: LoginBeginRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiate login with WebAuthn.

    This endpoint:
    1. Looks up the user by email
    2. Retrieves their registered WebAuthn credentials
    3. Generates authentication options (challenge)
    4. Returns options for the browser to sign
    """
    # Extract IP and user agent for audit logging
    ip_address = get_client_ip(http_request)
    user_agent = get_user_agent(http_request)

    # Find user by email
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user:
        logger.warning(f"Login attempt for non-existent user: {login_data.email} from IP: {ip_address}")
        # Log failed login attempt
        create_audit_log(
            db=db,
            event_type="login_begin",
            user_email=login_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details="User not found"
        )
        # Don't reveal whether user exists (return generic error)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Get user's credentials
    credentials = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == user.id
    ).all()

    if not credentials:
        logger.error(f"User {login_data.email} has no WebAuthn credentials from IP: {ip_address}")
        create_audit_log(
            db=db,
            event_type="login_begin",
            user_email=login_data.email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details="No WebAuthn credentials found"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    from webauthn import generate_authentication_options
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.structs import UserVerificationRequirement

    # Generate authentication options
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{
            "type": "public-key",
            "id": cred.credential_id,
        } for cred in credentials],
        user_verification=UserVerificationRequirement.REQUIRED
    )

    # Store challenge temporarily
    authentication_challenges[login_data.email] = {
        "challenge": options.challenge,
        "user_id": user.id
    }

    # Log successful login initiation
    create_audit_log(
        db=db,
        event_type="login_begin",
        user_email=login_data.email,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True,
        details=f"Authentication challenge created for {user.full_name}"
    )

    logger.info(f"Login initiated for: {login_data.email} from IP: {ip_address}")

    # Return options as JSON for the browser
    return {
        "publicKey": {
            "challenge": bytes_to_base64url(options.challenge),
            "timeout": options.timeout,
            "rpId": options.rp_id,
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": bytes_to_base64url(cred.credential_id)
                } for cred in credentials
            ],
            "userVerification": "required"
        }
    }


@app.post("/login/complete")
def login_complete(
    auth_data: LoginCompleteRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Complete login by verifying the WebAuthn assertion.

    This endpoint:
    1. Retrieves the stored challenge
    2. Verifies the assertion signature using the stored public key
    3. Updates the sign count to prevent replay attacks
    4. Generates and returns a JWT token
    """
    # Extract IP and user agent for audit logging
    ip_address = get_client_ip(http_request)
    user_agent = get_user_agent(http_request)

    # Get the stored challenge
    if auth_data.email not in authentication_challenges:
        logger.error(f"No authentication challenge found for: {auth_data.email}")
        create_audit_log(
            db=db,
            event_type="login_complete",
            user_email=auth_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details="No authentication challenge found"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No login in progress for this email"
        )

    stored_data = authentication_challenges[auth_data.email]

    from webauthn import verify_authentication_response
    from webauthn.helpers import base64url_to_bytes

    try:
        # Get the credential from assertion
        credential_id = base64url_to_bytes(auth_data.assertion.get("id", ""))

        # Find the credential in database
        credential = db.query(WebAuthnCredential).filter(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == stored_data["user_id"]
        ).first()

        if not credential:
            logger.error(f"Credential not found for user: {auth_data.email} from IP: {ip_address}")
            create_audit_log(
                db=db,
                event_type="login_complete",
                user_email=auth_data.email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details="Credential not found"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Verify the authentication response
        verification = verify_authentication_response(
            credential=auth_data.assertion,
            expected_challenge=stored_data["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count
        )

        # Update sign count to prevent replay attacks
        credential.sign_count = verification.new_sign_count
        db.commit()

        # Get user info
        user = db.query(User).filter(User.id == stored_data["user_id"]).first()

        # Generate JWT token with role claim
        token = create_access_token(
            data={
                "sub": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role  # Include role for authorization checks
            }
        )

        # Clean up the challenge
        del authentication_challenges[auth_data.email]

        # Log successful login
        create_audit_log(
            db=db,
            event_type="login_complete",
            user_email=user.email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details=f"User {user.full_name} logged in successfully"
        )

        logger.info(f"User logged in successfully: {user.full_name} ({user.email}) from IP: {ip_address}")

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "role": user.role
            }
        }

    except Exception as e:
        logger.error(f"Authentication verification failed for {auth_data.email}: {str(e)}")
        # Log failed login
        create_audit_log(
            db=db,
            event_type="login_complete",
            user_email=auth_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details=f"Authentication failed: {str(e)}"
        )
        # Clean up the challenge on failure
        if auth_data.email in authentication_challenges:
            del authentication_challenges[auth_data.email]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )


# ===================== Protected User Endpoint ===========================
@app.get("/users/{user_id}", response_model=UserViewModel)
def get_user(
    user_id: str,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> UserViewModel:
    """
    Get user information by ID.

    This endpoint is protected and requires JWT authentication.
    Users can only access their own information (authorization check).

    Args:
        user_id: The ID of the user to retrieve
        http_request: The HTTP request for IP logging
        current_user: The authenticated user (from JWT token)
        db: Database session

    Returns:
        User information

    Raises:
        HTTPException: If user tries to access another user's data or user not found
    """
    # Extract IP and user agent for audit logging
    ip_address = get_client_ip(http_request)
    user_agent = get_user_agent(http_request)

    # Authorization: Role-based access control
    # - Users with "user" role can only view their own profile
    # - Users with "admin" role can view any user's profile
    is_own_profile = current_user.id == user_id
    is_admin = current_user.role == "admin"

    if not is_own_profile and not is_admin:
        logger.warning(
            f"Authorization failed: User {current_user.email} (role: {current_user.role}) "
            f"attempted to access user {user_id}'s data from IP: {ip_address}"
        )
        # Log authorization failure
        create_audit_log(
            db=db,
            event_type="user_access",
            user_email=current_user.email,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details=f"Insufficient permissions (role: {current_user.role}). Attempted to access user {user_id}'s data"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this resource"
        )

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.error(f"User not found: {user_id}")
        create_audit_log(
            db=db,
            event_type="user_access",
            user_email=current_user.email,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details=f"User {user_id} not found"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Log successful access
    create_audit_log(
        db=db,
        event_type="user_access",
        user_email=user.email,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True,
        details=f"User {user.full_name} accessed by {current_user.full_name} (role: {current_user.role})"
    )

    logger.info(f"User data accessed: {user.email} by {current_user.email} (role: {current_user.role}) from IP: {ip_address}")

    return UserViewModel(
        id=user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        date_of_birth=user.date_of_birth,
        job_title=user.job_title,
        role=user.role,
        created_at=user.created_at
    )