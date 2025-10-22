"""
WebAuthn Authentication Microservice
=====================================

A production-ready passwordless authentication service using WebAuthn with JWT authorization
and role-based access control (RBAC).

Architecture Overview
--------------------
This microservice implements a complete authentication and authorization system:

1. **Authentication**: WebAuthn (FIDO2) passwordless biometric authentication
   - Uses platform authenticators (TouchID, FaceID, Windows Hello)
   - Public key cryptography (private keys never leave device)
   - Phishing-resistant by design (origin binding)
   - Replay attack prevention (sign count validation)

2. **Authorization**: JWT tokens with role-based access control
   - HS256 signed tokens with 60-minute expiration
   - Claims: sub, email, first_name, last_name, role, exp, iat
   - Two roles: 'user' (self-access only) and 'admin' (cross-user access)

3. **Audit Logging**: Dual logging for security monitoring
   - File-based logging (app.log) for development/debugging
   - Database logging (audit_logs table) for long-term audit trail
   - All events include IP address and user agent tracking

Database Schema
--------------
- users: User profiles with first_name, last_name, email, role
- webauthn_credentials: Public keys and credential metadata
- audit_logs: Security event tracking with IP/user agent

API Endpoints
------------
Registration Flow (2-step WebAuthn protocol):
  POST /users → 307 redirect → POST /register/begin → POST /register/complete

Login Flow (2-step WebAuthn protocol):
  POST /login → 307 redirect → POST /login/begin → POST /login/complete

Protected Resources:
  GET /users/{id} - Requires JWT, enforces RBAC

Security Considerations
----------------------
- WebAuthn challenge storage is in-memory (use Redis in production)
- JWT_SECRET must be changed in production (use secrets manager)
- CORS is permissive for development (restrict in production)
- Rate limiting not implemented (use WAF/reverse proxy in production)
- HTTPS required in production for WebAuthn
- Sign count validation prevents credential cloning

For comprehensive documentation, see:
- README.md: Complete user guide, security controls, testing
- IMPLEMENTATION_SUMMARY.md: Implementation details and architecture
- MULTI_AUTH_ARCHITECTURE.md: Future multi-provider roadmap

Author: Generated with Claude Code
Version: 1.0
"""

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
"""
Database Configuration
---------------------
Using SQLite for development/demo purposes. For production:
- Use PostgreSQL, MySQL, or similar production-grade database
- Configure connection pooling
- Enable SSL/TLS for database connections
- Set up automated backups
"""
DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite-specific: allow multi-threading
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db() -> Session:
    """
    Database session dependency for FastAPI endpoints.

    Yields a database session that is automatically closed after the request.
    This is the recommended pattern for FastAPI dependency injection.

    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===================== SQLAlchemy Models ===========================
class User(Base):
    """
    User model storing core user profile information.

    This model represents a registered user in the system. Users authenticate
    using WebAuthn credentials (stored separately in WebAuthnCredential table).

    Attributes:
        id (str): UUID primary key
        first_name (str): User's first name
        last_name (str): User's last name
        email (str): Unique email address (indexed for fast lookup)
        date_of_birth (datetime): User's date of birth
        job_title (str): User's job title
        role (str): User role for RBAC - "user" (default) or "admin"
        created_at (datetime): Account creation timestamp

    Relationships:
        credentials: One-to-many relationship with WebAuthnCredential
                    (cascade delete: removing user deletes all their credentials)

    Security Notes:
        - Email is unique and indexed for fast authentication lookups
        - No password field - authentication is entirely WebAuthn-based
        - Role field enables role-based access control (RBAC)
        - Default role is "user" (limited to self-access)
        - Admin role grants cross-user data access
    """
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
        """
        Return user's full name (first + last).

        Returns:
            str: Full name in "FirstName LastName" format
        """
        return f"{self.first_name} {self.last_name}"

class WebAuthnCredential(Base):
    """
    WebAuthn credential model storing public keys and security metadata.

    Each credential represents a registered authenticator (e.g., TouchID, YubiKey)
    for a user. Users can have multiple credentials (e.g., laptop + phone).

    Attributes:
        id (str): UUID primary key
        user_id (str): Foreign key to users table
        credential_id (bytes): Unique identifier from the authenticator device
                              (indexed for fast authentication lookups)
        public_key (bytes): Public key for cryptographic signature verification
        sign_count (int): Monotonic counter for credential cloning detection
                         (increments with each authentication)
        created_at (datetime): Credential registration timestamp

    Relationships:
        user: Many-to-one relationship with User

    Security Notes:
        - credential_id is unique and indexed for fast WebAuthn authentication
        - public_key is used to verify authentication assertions
        - sign_count prevents replay attacks and detects cloned credentials:
          * Should always increase with each use
          * If it decreases or doesn't change, credential may be cloned
        - Private keys never leave the user's device (WebAuthn security model)
        - Credentials are bound to the origin (prevents phishing)
    """
    __tablename__ = "webauthn_credentials"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    credential_id = Column(LargeBinary, unique=True, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to user
    user = relationship("User", back_populates="credentials")

class AuditLog(Base):
    """
    Audit log model for tracking authentication and authorization events.

    This table provides a comprehensive audit trail for security monitoring,
    incident response, and compliance. All security-relevant events are logged
    with IP address and user agent for forensic analysis.

    Attributes:
        id (str): UUID primary key
        event_type (str): Event category (indexed for fast queries)
                         Values: 'registration_begin', 'registration_complete',
                                'login_begin', 'login_complete', 'user_access'
        user_email (str): User's email address if known (indexed)
        user_id (str): Foreign key to users table (null for failed auth)
        ip_address (str): Client IP address (handles X-Forwarded-For proxies)
        user_agent (str): Browser/client user agent string
        success (int): 1 for successful events, 0 for failures
        details (str): Additional context (error messages, authorization details)
        created_at (datetime): Event timestamp (indexed for time-range queries)

    Relationships:
        user: Many-to-one relationship with User (nullable for failed events)

    Security Notes:
        - Indexes on event_type, user_email, and created_at for fast querying
        - IP addresses enable detection of suspicious patterns (brute force, etc.)
        - User agent helps identify automated attacks or unusual clients
        - Dual logging: Also logs to app.log file for real-time monitoring
        - Used for incident response, security monitoring, and compliance
        - Query examples in README.md (failed logins, unauthorized access, etc.)

    Example Queries:
        - Failed login attempts: WHERE event_type='login_complete' AND success=0
        - Unauthorized access: WHERE event_type='user_access' AND success=0
        - Admin actions: WHERE details LIKE '%role: admin%'
    """
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String, nullable=False, index=True)
    user_email = Column(String, nullable=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    success = Column(Integer, nullable=False)  # 1 for success, 0 for failure
    details = Column(Text, nullable=True)
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
"""
JWT Configuration
----------------
JSON Web Token settings for authorization. Tokens are signed with HS256
and include user claims (sub, email, first_name, last_name, role).

SECURITY WARNING: JWT_SECRET must be changed in production!
- Use a cryptographically random value (32+ bytes)
- Store in environment variable or secrets manager (Vault, AWS Secrets Manager)
- Never commit secrets to version control
"""
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

"""
WebAuthn Configuration
---------------------
WebAuthn/FIDO2 settings for passwordless authentication.

RP_ID: Relying Party ID - must match the domain (e.g., "example.com")
       For localhost development, use "localhost"
       MUST NOT include port number or protocol

RP_NAME: Human-readable name shown to users during authentication

ORIGIN: Full URL with protocol and port (e.g., "https://auth.example.com")
        MUST be HTTPS in production (WebAuthn requirement)
        Credentials are bound to this origin (prevents phishing)
"""
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Auth Example")
ORIGIN = os.getenv("ORIGIN", "http://localhost:8000")

"""
Challenge Storage
----------------
WebAuthn challenges must be stored temporarily during the two-step
registration/authentication flow.

DEVELOPMENT: In-memory dictionaries (current implementation)
- Simple, no dependencies
- Lost on server restart
- Not shared across multiple server instances

PRODUCTION: Use Redis or similar distributed cache
- Persistent across server restarts
- Shared across load-balanced instances
- Set TTL (time-to-live) for automatic cleanup
- Example: redis.setex(f"challenge:{email}", 300, challenge)

Security Notes:
- Challenges should expire after 5 minutes
- Each challenge can only be used once
- Clean up challenges after successful/failed attempts
"""
registration_challenges = {}  # email -> {challenge, user_data}
authentication_challenges = {}  # email -> {challenge, allowed_credentials}

# ===================== FastAPI App ===========================
app = FastAPI(title="WebAuthn Authentication Backend")

# Add CORS middleware for local development
"""
CORS Configuration
-----------------
SECURITY WARNING: Current configuration is permissive for development.

In production, configure CORS strictly:
- allow_origins: List specific origins, e.g., ["https://app.example.com"]
- allow_methods: Limit to ["GET", "POST"] (remove DELETE, etc.)
- allow_headers: List specific headers instead of ["*"]

Example production config:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
"""
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DEVELOPMENT ONLY - specify exact origins in production
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
    """
    Extract client IP address from request, handling reverse proxies and load balancers.

    This function checks headers in order of preference:
    1. X-Forwarded-For (set by most proxies/load balancers)
    2. X-Real-IP (alternative proxy header)
    3. Direct client IP from socket connection

    Args:
        request: FastAPI Request object

    Returns:
        str: Client IP address or "unknown" if unable to determine

    Security Notes:
        - X-Forwarded-For can be spoofed if not behind a trusted proxy
        - In production, configure your reverse proxy to set these headers correctly
        - Consider using request.client.host only if behind a trusted proxy
        - For rate limiting, use this IP (but be aware of shared IPs behind NAT)

    Example:
        X-Forwarded-For: "203.0.113.1, 198.51.100.1, 192.0.2.1"
        Returns: "203.0.113.1" (first/original client IP)
    """
    # Check X-Forwarded-For header (set by proxies/load balancers)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
        # Take the first one (original client)
        return forwarded_for.split(",")[0].strip()

    # Check X-Real-IP header (alternative proxy header)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fall back to direct client IP from socket connection
    if request.client:
        return request.client.host

    return "unknown"

def get_user_agent(request: Request) -> str:
    """
    Extract user agent string from request headers.

    User agent helps identify the client browser/application for:
    - Security monitoring (detecting automated attacks)
    - Audit trail (understanding access patterns)
    - Compatibility issues (browser-specific problems)

    Args:
        request: FastAPI Request object

    Returns:
        str: User agent string or "unknown" if not present

    Example:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    """
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
    """
    Create an audit log entry in the database.

    This function implements dual logging:
    - Database (audit_logs table): Long-term audit trail for compliance
    - File logging (app.log): Already handled by logger.info/warning calls

    Args:
        db: SQLAlchemy database session
        event_type: Event category ('registration_begin', 'login_complete', etc.)
        user_email: User's email address (if known)
        user_id: User's UUID (if authenticated)
        ip_address: Client IP address
        user_agent: Client user agent string
        success: True for successful events, False for failures
        details: Additional context (error messages, authorization details)

    Security Notes:
        - All authentication/authorization events should be logged
        - Include both successes and failures for incident response
        - IP and user agent enable detection of attack patterns
        - Logs are queryable for security monitoring (see README.md)

    Example Usage:
        create_audit_log(
            db=db,
            event_type="login_complete",
            user_email="user@example.com",
            user_id="user-uuid",
            ip_address="203.0.113.1",
            user_agent="Mozilla/5.0...",
            success=True,
            details="User logged in successfully"
        )
    """
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
    Create a JWT access token for authorization.

    This function generates a signed JWT token with standard claims plus
    custom user claims (sub, email, first_name, last_name, role).

    Args:
        data: Dictionary containing user claims to encode
              Expected keys: sub (user ID), email, first_name, last_name, role

    Returns:
        str: Encoded JWT token (HS256 signed)

    Token Structure:
        {
          "sub": "user-uuid",           # Subject (user ID)
          "email": "user@example.com",
          "first_name": "Jane",
          "last_name": "Doe",
          "role": "user",               # For RBAC ("user" or "admin")
          "exp": 1234567890,            # Expiration (60 minutes from now)
          "iat": 1234567890,            # Issued at (current time)
          "iss": "auth-example-backend" # Issuer
        }

    Security Notes:
        - Token expires after JWT_EXPIRATION_MINUTES (60 minutes)
        - Signed with HS256 using JWT_SECRET
        - Role claim enables role-based access control
        - No refresh token mechanism (user must re-authenticate after expiry)
        - For production, store JWT_SECRET in secrets manager
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode.update({
        "exp": expire,  # Expiration time
        "iat": datetime.utcnow(),  # Issued at
        "iss": "auth-example-backend"  # Issuer
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str) -> dict:
    """
    Verify and decode a JWT access token.

    This function validates the token signature, expiration, and algorithm.
    If valid, returns the decoded claims for use in authorization logic.

    Args:
        token: The JWT token string to verify

    Returns:
        dict: Decoded token payload containing claims
              (sub, email, first_name, last_name, role, exp, iat, iss)

    Raises:
        JWTError: If token is invalid, expired, or has wrong signature

    Security Notes:
        - Validates signature using JWT_SECRET
        - Checks expiration automatically (exp claim)
        - Verifies algorithm matches JWT_ALGORITHM (HS256)
        - Logs verification failures for security monitoring
        - Returns None for "sub" claim if token is malformed
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
    FastAPI dependency for JWT authentication.

    This function is used as a dependency injection for protected endpoints.
    It validates the JWT token from the Authorization header and returns
    the authenticated user object.

    Usage in endpoints:
        @app.get("/protected")
        def protected_endpoint(current_user: User = Depends(get_current_user)):
            # current_user is automatically populated with authenticated user
            return {"message": f"Hello, {current_user.email}"}

    Args:
        credentials: HTTPBearer credentials from Authorization header
                    Expected format: "Bearer <jwt-token>"
        db: SQLAlchemy database session (auto-injected)

    Returns:
        User: SQLAlchemy User object with full profile (including role)

    Raises:
        HTTPException 401: If token is invalid, expired, or user not found

    Authentication Flow:
        1. Extract JWT token from Authorization header
        2. Verify token signature and expiration
        3. Extract user_id from "sub" claim
        4. Query database for user by ID
        5. Return User object (with role for RBAC)

    Security Notes:
        - Token validation includes signature check and expiration
        - If user is deleted but token is valid, raises 401 (user not found)
        - Role claim in JWT enables role-based access control
        - Uses HTTPBearer scheme (standard OAuth2/JWT pattern)
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