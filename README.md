# WebAuthn Authentication Microservice

A secure authentication microservice implementing passwordless WebAuthn (TouchID/biometric) authentication with JWT tokens and role-based access control. Built for high-security environments with comprehensive logging and authorization controls.

**✨ Interactive Demo Frontend** - Test TouchID authentication in your browser at `http://localhost:8000`

## Table of Contents

- [Microservice Architecture Goals](#microservice-architecture-goals)
- [Threat Model](#threat-model)
- [Security Controls](#security-controls)
- [Endpoint Implementations](#endpoint-implementations)
- [Role-Based Access Control](#role-based-access-control)
- [Quick Start](#quick-start)
- [Database Schema](#database-schema)
- [Configuration](#configuration)
- [Development & Testing](#development--testing)

---

## Microservice Architecture Goals

This authentication microservice is designed to be:

1. **Stateless**: JWT-based authentication eliminates server-side session storage
2. **API-First**: RESTful JSON API suitable for integration with any frontend
3. **Phishing-Resistant**: WebAuthn prevents credential theft and phishing attacks
4. **Auditable**: Comprehensive logging supports security monitoring and compliance
5. **Scalable**: No session state allows horizontal scaling
6. **Microservice-Ready**: Designed to run in containerized environments with external infrastructure support (load balancers, secret managers, monitoring)

### Key Design Principles

- **Defense in Depth**: Authentication (WebAuthn) + Authorization (JWT + RBAC)
- **Least Privilege**: Users can only access their own data; admin role for cross-user access
- **Security by Default**: Secure configurations, comprehensive logging, input validation
- **Operational Visibility**: Dual logging (file + database) for security team monitoring

---

## Threat Model

### Security Assumptions

This microservice is designed for deployment in a **high-security environment** with:

1. **Infrastructure-Layer Security**: TLS termination at load balancer/reverse proxy
2. **Network Security**: WAF, DDoS protection, and rate limiting at infrastructure layer
3. **Secrets Management**: External secret manager (Vault, AWS Secrets Manager, Azure Key Vault)
4. **Centralized Logging**: Integration with SIEM/log aggregation (ELK, Splunk, CloudWatch)
5. **Internal Deployment**: Not directly exposed to the public internet

### Threat Actors & Mitigations

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| **Credential Theft** | Password database breach | No passwords stored (WebAuthn only) |
| **Phishing** | Fake login page | WebAuthn origin binding prevents credential use on wrong domain |
| **Replay Attacks** | Intercepted authentication | Challenge-response protocol with cryptographic nonces |
| **Session Hijacking** | Stolen JWT token | Short expiration (60 min), no refresh tokens in this version |
| **Credential Stuffing** | Reused passwords | No passwords (WebAuthn eliminates this attack) |
| **MITM Attacks** | Man-in-the-middle | HTTPS required in production (enforced by WebAuthn spec) |
| **Unauthorized Access** | Accessing other users' data | RBAC with ownership checks on every protected endpoint |
| **Credential Cloning** | Duplicating biometric credentials | Sign count validation detects cloned credentials |
| **Account Enumeration** | Discovering valid emails | Generic error messages prevent user enumeration |
| **Insider Threats** | Malicious admin access | Comprehensive audit logging of all access attempts |

### Security Team Monitoring Support

The microservice provides comprehensive monitoring capabilities:

#### 1. Real-Time Logging
- **File-based logs** (`app.log`): Immediate visibility during development/debugging
- **Database audit trail** (`audit_logs` table): Queryable history for analysis

#### 2. Tracked Security Events
- User registration attempts (with IP, user agent, success/failure)
- Login attempts (with IP, user agent, success/failure)
- Authorization failures (users attempting to access others' data)
- JWT validation failures
- Credential verification failures

#### 3. Incident Response Capabilities
```sql
-- Find failed login attempts (potential brute force)
SELECT created_at, user_email, ip_address, user_agent, details
FROM audit_logs
WHERE event_type='login_complete' AND success=0
ORDER BY created_at DESC;

-- Detect account compromise (multiple IPs for same user)
SELECT user_email, ip_address, COUNT(*) as attempts
FROM audit_logs
WHERE event_type='login_complete' AND success=1
GROUP BY user_email, ip_address
HAVING COUNT(*) > 1;

-- Track unauthorized access attempts
SELECT created_at, user_email, ip_address, details
FROM audit_logs
WHERE event_type='user_access' AND success=0
ORDER BY created_at DESC;
```

#### 4. Compliance Support
- **SOC 2**: Audit trail of all authentication/authorization events
- **HIPAA**: Comprehensive logging of PHI access (when storing health data)
- **GDPR**: User activity tracking for right-to-access requests

---

## Security Controls

### Implemented Controls

#### ✅ Authentication
- **WebAuthn with Platform Authenticators**: TouchID, FaceID, Windows Hello
- **Multi-Factor by Design**: Something you have (device) + something you are (biometric)
- **Public Key Cryptography**: Private key never leaves device
- **Challenge-Response Protocol**: Prevents replay attacks with cryptographic nonces
- **Sign Count Validation**: Detects and prevents credential cloning

#### ✅ Authorization
- **JWT Token-Based Access Control**: Stateless authentication
- **Token Expiration**: 60-minute lifetime (configurable)
- **Role-Based Access Control (RBAC)**:
  - `user` role: Can only access own data
  - `admin` role: Can access any user's data
- **Per-Endpoint Authorization Checks**: Validates ownership or admin role
- **JWT Claims**: `sub` (user_id), `email`, `first_name`, `last_name`, `role`

#### ✅ Input Validation
- **Pydantic Models**: Type-safe validation for all inputs
- **Email Format Validation**: RFC-compliant email validation
- **Required Field Validation**: Enforced at API layer
- **Type Checking**: Prevents type confusion attacks

#### ✅ Database Security
- **SQL Injection Prevention**: SQLAlchemy ORM parameterized queries
- **Email Uniqueness Constraints**: Prevents duplicate accounts
- **Foreign Key Relationships**: Ensures referential integrity
- **Indexed Lookups**: Optimized queries on `email`, `event_type`, `created_at`

#### ✅ Logging & Monitoring
- **Dual Logging System**:
  - File-based (`app.log`): Real-time debugging
  - Database (`audit_logs`): Long-term audit trail
- **IP Address Tracking**: All events logged with client IP (handles `X-Forwarded-For`)
- **User Agent Tracking**: Browser/client identification
- **Success/Failure Recording**: All authentication/authorization outcomes logged
- **Generic Error Messages**: Prevents user enumeration

#### ✅ Error Handling
- **Generic Error Messages**: "Invalid credentials" (no hints about user existence)
- **Proper HTTP Status Codes**: `401` (unauthenticated), `403` (unauthorized), `404` (not found)
- **Challenge Cleanup**: Failed attempts clean up server-side state

### Deferred Security Controls

The following controls are **intentionally deferred** due to infrastructure requirements or scope limitations:

#### ❌ Rate Limiting
- **Why Deferred**: Requires distributed cache (Redis) for multi-instance deployments
- **Risk**: Brute force attacks possible on registration/login endpoints
- **Production Recommendation**: Implement with `slowapi` + Redis or infrastructure-level WAF rate limiting
- **Mitigation**: WebAuthn's biometric requirement slows brute force significantly

#### ❌ HTTPS/TLS
- **Why Deferred**: Local development uses HTTP
- **Risk**: Credentials visible to network observers
- **Production Requirement**: WebAuthn spec **requires** HTTPS in production
- **Production Recommendation**: TLS termination at reverse proxy (nginx, ALB) with Let's Encrypt certificates

#### ❌ Email Verification
- **Why Deferred**: Requires email service integration (SendGrid, AWS SES)
- **Risk**: Users can register with emails they don't own
- **Production Recommendation**: Send verification email with time-limited token
- **Workaround**: Manual admin verification of user accounts

#### ❌ Account Recovery Flow
- **Why Deferred**: Complex multi-step process requiring email service
- **Risk**: Users who lose device credentials cannot recover access
- **Current Mitigation**: Users must re-register with new email
- **Production Recommendation**: Backup authentication methods (recovery codes, secondary device)

#### ❌ Distributed Challenge Storage
- **Why Deferred**: Currently using in-memory dictionary
- **Risk**: Server restart invalidates pending registrations/logins
- **Current Mitigation**: Acceptable for development; users retry registration
- **Production Recommendation**: Redis with TTL (5-minute expiration)

#### ❌ Secrets Management
- **Why Deferred**: Using environment variables with fallback defaults
- **Risk**: JWT secret could be exposed in source code or logs
- **Current Mitigation**: Documentation requires `JWT_SECRET` in production
- **Production Requirement**: HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault

#### ❌ Centralized Audit Logging
- **Why Deferred**: Currently logging to local file and SQLite
- **Risk**: Logs not centralized, difficult to analyze at scale, can be lost
- **Current Mitigation**: Dual logging (file + database) for redundancy
- **Production Recommendation**: ELK stack, Splunk, CloudWatch, or similar SIEM

#### ❌ WAF/DDoS Protection
- **Why Deferred**: Requires infrastructure (CloudFlare, AWS WAF, Azure Front Door)
- **Risk**: Application vulnerable to volumetric attacks
- **Current Mitigation**: None at application level
- **Production Requirement**: Deploy behind WAF with DDoS protection

#### ❌ Database Encryption at Rest
- **Why Deferred**: SQLite doesn't support native encryption
- **Risk**: Database file contains user PII in plaintext on disk
- **Current Mitigation**: File system permissions restrict access
- **Production Recommendation**: PostgreSQL with encryption or encrypted filesystem (LUKS, BitLocker)

#### ❌ JWT Refresh Tokens
- **Why Deferred**: Adds complexity with token rotation logic
- **Risk**: Users must re-authenticate every 60 minutes
- **Current Mitigation**: Short session timeout acceptable for high-security applications
- **Production Recommendation**: Implement refresh token flow with rotation and family tracking

#### ❌ CORS Configuration
- **Why Deferred**: No specific frontend domain defined
- **Risk**: Any origin can call the API in browser context
- **Current Mitigation**: Accept for development; WebAuthn origin binding provides some protection
- **Production Requirement**: Configure specific allowed origins in CORS middleware

---

## Endpoint Implementations

### Design Philosophy: WebAuthn Two-Step Protocol

The original specification requested:
- `POST /users` - User registration
- `POST /login` - User login
- `GET /users/{id}` - Retrieve user information

**Our implementation modifies registration and login to accommodate WebAuthn's cryptographic protocol**, which inherently requires two round-trips between client and server.

### Why Two-Step Endpoints Are Required

WebAuthn is a **challenge-response protocol** that cannot be collapsed into a single request-response cycle:

1. **Server must generate a cryptographic challenge** (random nonce)
2. **Client must sign the challenge** with the authenticator (TouchID/FaceID)
3. **Browser APIs are asynchronous** and require user interaction (biometric prompt)
4. **Signed result must be sent back** for verification

This protocol design prevents replay attacks and ensures the user is physically present with the registered device.

### Endpoint Specification Compliance

| Original Spec Operation | Our Implementation | Semantic Equivalence |
|-------------------------|-------------------|---------------------|
| `POST /users` (register) | `POST /register/begin` → `POST /register/complete` | Two-step registration creates user |
| `POST /login` | `POST /login/begin` → `POST /login/complete` | Two-step login returns JWT |
| `GET /users/{id}` | `GET /users/{id}` | **Unchanged** - works as specified |

**The original requirements are fully satisfied**: users can register, login, and retrieve information. The only difference is that registration and login require two sequential API calls due to the cryptographic protocol.

---

### POST /users - User Self-Registration (Two-Step Flow)

Users self-register with First Name, Last Name, Email, Date of Birth, and Job Title. WebAuthn creates a phishing-resistant credential tied to the user's device biometrics.

**Note**: For spec compatibility, `POST /users` is available as a redirect endpoint. It returns a `307 Temporary Redirect` to `/register/begin`, preserving the POST method and request body. Clients that follow redirects will automatically be routed to the correct endpoint.

#### Step 1: POST /register/begin (or POST /users)

Initiates registration by sending user information. Server generates a cryptographic challenge.

**Request:**
```json
{
  "first_name": "Jane",
  "last_name": "Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer"
}
```

**Response:** WebAuthn PublicKeyCredentialCreationOptions
```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "id": "localhost",
      "name": "Auth Example"
    },
    "user": {
      "id": "base64url-encoded-user-uuid",
      "name": "jane@example.com",
      "displayName": "Jane Doe"
    },
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -257}
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "required"
    },
    "timeout": 60000
  }
}
```

**Implementation Details:**
- Creates user record with `role: "user"` (default)
- Generates UUID for `user.id`
- Stores challenge in-memory (5-minute expiration)
- Logs registration initiation with IP address and user agent
- Returns WebAuthn options for `navigator.credentials.create()`

**Security Controls:**
- Email uniqueness validation (prevents duplicate accounts)
- Input validation via Pydantic models
- Audit logging of registration attempts
- Generic error messages (prevents user enumeration)

---

#### Step 2: POST /register/complete

Completes registration by submitting the WebAuthn credential created by the user's authenticator.

**Request:**
```json
{
  "email": "jane@example.com",
  "credential": {
    "id": "credential-id-base64url",
    "rawId": "credential-id-base64url",
    "response": {
      "clientDataJSON": "base64url-encoded-json",
      "attestationObject": "base64url-encoded-cbor"
    },
    "type": "public-key"
  }
}
```

**Response** (201 Created):
```json
{
  "id": "user-uuid",
  "first_name": "Jane",
  "last_name": "Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer",
  "role": "user",
  "created_at": "2025-10-22T12:00:00Z"
}
```

**Implementation Details:**
- Verifies credential signature using `webauthn` library
- Validates challenge matches stored challenge
- Stores credential public key in `webauthn_credentials` table
- Deletes challenge from memory after use
- Logs successful registration with IP address and user agent
- Returns complete user object (excluding sensitive credential data)

**Security Controls:**
- Cryptographic verification of attestation
- Challenge validation (prevents replay attacks)
- Sign count initialization (detects credential cloning)
- One-time challenge use (deleted after verification)
- Credential uniqueness constraint in database

---

### POST /login - User Login (Avoids Auth0, Uses JWT)

Login flow uses **WebAuthn challenge-response** instead of external authentication services like Auth0. Returns a **JWT token** containing user claims and role.

#### Step 1: POST /login/begin

Initiates login by providing email. Server generates challenge and returns allowed credentials.

**Request:**
```json
{
  "email": "jane@example.com"
}
```

**Response:** WebAuthn PublicKeyCredentialRequestOptions
```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rpId": "localhost",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "credential-id-base64url"
      }
    ],
    "userVerification": "required",
    "timeout": 60000
  }
}
```

**Implementation Details:**
- Looks up user by email
- Retrieves all registered credentials for user
- Generates fresh challenge (stored in-memory)
- Logs login initiation with IP address
- Returns challenge + allowed credential IDs for `navigator.credentials.get()`

**Security Controls:**
- Generic error if user not found (prevents user enumeration: "Invalid credentials")
- Fresh challenge per login attempt
- All registered credentials allowed (supports multiple devices)
- Audit logging of login attempts

---

#### Step 2: POST /login/complete

Completes login by submitting the WebAuthn assertion (signed challenge). Returns JWT token.

**Request:**
```json
{
  "email": "jane@example.com",
  "assertion": {
    "id": "credential-id-base64url",
    "rawId": "credential-id-base64url",
    "response": {
      "clientDataJSON": "base64url-encoded-json",
      "authenticatorData": "base64url-encoded-data",
      "signature": "base64url-encoded-signature"
    },
    "type": "public-key"
  }
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "user-uuid",
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com",
    "role": "user"
  }
}
```

**Implementation Details:**
- Verifies signature using stored public key
- Validates challenge matches expected challenge
- Validates sign count (must be greater than stored count)
- Updates stored sign count (prevents credential cloning)
- Generates JWT token with claims: `sub`, `email`, `first_name`, `last_name`, `role`
- Logs successful login with IP address and user agent
- Deletes challenge from memory after use

**JWT Token Claims:**
```json
{
  "sub": "user-uuid",
  "email": "jane@example.com",
  "first_name": "Jane",
  "last_name": "Doe",
  "role": "user",
  "exp": 1729608000,
  "iat": 1729604400
}
```

**Security Controls:**
- Cryptographic signature verification
- Sign count validation (detects cloned credentials)
- Challenge validation (prevents replay attacks)
- Short token expiration (60 minutes, configurable)
- HS256 signing algorithm with secret key
- Generic error messages (prevents user enumeration)

**Why Not Auth0:**
- WebAuthn is the primary authentication mechanism (Auth0 would be redundant)
- Self-contained microservice with no external dependencies
- JWT generation is simple and secure with proper key management
- Avoids vendor lock-in and external service costs

---

### GET /users/{id} - Retrieve User Information (Claims, Roles, Permissions)

Protected endpoint that returns user information. Requires JWT authentication. Implements role-based access control.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

**Response:**
```json
{
  "id": "user-uuid",
  "first_name": "Jane",
  "last_name": "Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer",
  "role": "user",
  "created_at": "2025-10-22T12:00:00Z"
}
```

**Implementation Details:**
- Validates JWT token (signature, expiration)
- Extracts user identity from JWT claims (`sub`, `role`)
- Checks authorization:
  - **Users with `user` role**: Can only access their own profile (`user_id == requested_id`)
  - **Users with `admin` role**: Can access any user's profile
- Logs access attempt with IP address, user agent, and authorization outcome
- Returns user object if authorized

**Authorization Logic:**
```python
is_own_profile = current_user.id == user_id
is_admin = current_user.role == "admin"

if not is_own_profile and not is_admin:
    # Deny access, log authorization failure
    raise HTTPException(status_code=403, detail="You don't have permission to access this resource")
```

**Security Controls:**
- JWT validation (signature, expiration)
- Role-based access control (RBAC)
- Per-request authorization check
- Audit logging of access attempts (both success and failure)
- IP address and user agent tracking
- Generic error messages

**Error Responses:**
- `401 Unauthorized`: Invalid or expired JWT token
- `403 Forbidden`: User trying to access another user's data (non-admin)
- `404 Not Found`: User doesn't exist

**Audit Logging:**
- **Success**: "User Jane Doe accessed by Jane Doe (role: user) from IP: 192.168.1.1"
- **Failure (non-admin accessing others' data)**: "Authorization failed: User jane@example.com (role: user) attempted to access user abc-123's data from IP: 192.168.1.1"

---

## Role-Based Access Control

### Roles

| Role | Permissions | Use Case |
|------|-------------|----------|
| `user` | Access own data only | Default role for all registered users |
| `admin` | Access any user's data | Support staff, security team, auditors |

### Role Assignment

- **Default**: All users registered via `POST /register/begin` receive `role: "user"`
- **Admin Assignment**: Currently requires direct database update (no API endpoint for role promotion)
  ```sql
  UPDATE users SET role='admin' WHERE email='admin@example.com';
  ```
- **Future Enhancement**: Implement `POST /admin/users/{id}/promote` endpoint (requires authentication as existing admin)

### Role Claims in JWT

The `role` claim is embedded in the JWT token during login:

```json
{
  "sub": "user-uuid",
  "email": "admin@example.com",
  "first_name": "Admin",
  "last_name": "User",
  "role": "admin",
  "exp": 1729608000,
  "iat": 1729604400
}
```

### Authorization Enforcement

Authorization is enforced at the endpoint level using dependency injection:

```python
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Validates JWT and extracts user from database
    # Raises 401 if invalid
    return user

@app.get("/users/{user_id}")
def get_user(user_id: str, current_user: User = Depends(get_current_user), ...):
    # Check authorization based on role
    is_own_profile = current_user.id == user_id
    is_admin = current_user.role == "admin"

    if not is_own_profile and not is_admin:
        # Log and deny access
        raise HTTPException(status_code=403, ...)
```

### Admin Access Logging

All admin access is logged with full context:

```sql
SELECT * FROM audit_logs WHERE user_email='admin@example.com' AND event_type='user_access';
```

Example log entry:
```
event_type: user_access
user_email: admin@example.com
user_id: admin-uuid
ip_address: 192.168.1.1
success: 1
details: User John Doe accessed by Admin User (role: admin)
```

---

## Quick Start

### Prerequisites
- Python 3.9+
- Modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)
- Biometric hardware (TouchID, FaceID, Windows Hello) or security key

### Installation

```bash
# Clone and navigate to repository
cd auth-example

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set JWT secret (production requirement)
export JWT_SECRET="your-secure-random-secret-key"

# Run the server
uvicorn main:app --reload
```

The server starts at `http://localhost:8000`.

### Try the Interactive Demo

1. **Open browser**: `http://localhost:8000`
2. **Register**: Fill form → Click "Register with Biometrics" → Authenticate with TouchID
3. **View profile**: See your user data and JWT expiration countdown
4. **Logout and login**: Test the login flow with biometrics

### View API Documentation

FastAPI automatic docs: `http://localhost:8000/docs`

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,                -- UUID
    first_name TEXT NOT NULL,           -- First name
    last_name TEXT NOT NULL,            -- Last name
    email TEXT UNIQUE NOT NULL,         -- Email (indexed for fast lookup)
    date_of_birth DATETIME NOT NULL,    -- Date of birth
    job_title TEXT NOT NULL,            -- Job title
    role TEXT NOT NULL DEFAULT 'user',  -- Role: 'user' or 'admin'
    created_at DATETIME NOT NULL        -- Registration timestamp
);

CREATE INDEX idx_users_email ON users(email);
```

### WebAuthn Credentials Table
```sql
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,                -- UUID
    user_id TEXT NOT NULL,              -- Foreign key to users.id
    credential_id BLOB UNIQUE NOT NULL, -- WebAuthn credential ID (binary)
    public_key BLOB NOT NULL,           -- Public key for signature verification
    sign_count INTEGER NOT NULL DEFAULT 0, -- Counter for credential cloning detection
    created_at DATETIME NOT NULL,       -- Credential creation timestamp
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_credentials_user_id ON webauthn_credentials(user_id);
CREATE UNIQUE INDEX idx_credentials_credential_id ON webauthn_credentials(credential_id);
```

### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,                -- UUID
    event_type TEXT NOT NULL,           -- Event category (indexed)
    user_email TEXT,                    -- Email address (indexed)
    user_id TEXT,                       -- User ID (foreign key)
    ip_address TEXT,                    -- Client IP address
    user_agent TEXT,                    -- Browser/client user agent
    success INTEGER NOT NULL,           -- 1 for success, 0 for failure
    details TEXT,                       -- Additional context
    created_at DATETIME NOT NULL,       -- Event timestamp (indexed)
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_user_email ON audit_logs(user_email);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);
```

**Event Types:**
- `registration_begin`: User started registration
- `registration_complete`: User completed registration (success/failure)
- `login_begin`: User started login
- `login_complete`: User completed login (success/failure)
- `user_access`: User accessed `GET /users/{id}` (success/failure)

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `your-secret-key-change-in-production` | **⚠️ MUST change in production** - Secret key for signing JWTs |
| `JWT_ALGORITHM` | `HS256` | Algorithm for JWT signing |
| `JWT_EXPIRATION_MINUTES` | `60` | Token lifetime in minutes |
| `RP_ID` | `localhost` | WebAuthn Relying Party ID (your domain) |
| `RP_NAME` | `Auth Example` | WebAuthn Relying Party display name |
| `ORIGIN` | `http://localhost:8000` | Expected origin for WebAuthn (must be HTTPS in production) |

### Production Configuration Checklist

- [ ] Set `JWT_SECRET` to cryptographically random value (32+ bytes)
- [ ] Store `JWT_SECRET` in secret manager (Vault, AWS Secrets Manager)
- [ ] Set `RP_ID` to your production domain (e.g., `auth.example.com`)
- [ ] Set `ORIGIN` to HTTPS URL (e.g., `https://auth.example.com`)
- [ ] Configure TLS termination at reverse proxy
- [ ] Set up centralized logging (ELK, Splunk, CloudWatch)
- [ ] Implement rate limiting (Redis + `slowapi` or WAF)
- [ ] Configure CORS with specific allowed origins
- [ ] Set up database backups
- [ ] Enable database encryption at rest
- [ ] Configure WAF and DDoS protection
- [ ] Set up monitoring and alerting

---

## Development & Testing

### Reset Database

To test registration multiple times (useful when you only have one device with TouchID):

```bash
# Option 1: Python script (clears database and logs)
python3 reset_db.py

# Option 2: Shell script (clears database, restarts server)
./reset.sh
```

This deletes `app.db` and `app.log`, allowing you to re-register with the same email.

### Query Audit Logs

**View all events for a user:**
```bash
sqlite3 app.db "SELECT created_at, event_type, ip_address, success, details
                FROM audit_logs
                WHERE user_email='jane@example.com'
                ORDER BY created_at DESC;"
```

**Find failed login attempts:**
```bash
sqlite3 app.db "SELECT created_at, user_email, ip_address, user_agent, details
                FROM audit_logs
                WHERE event_type='login_complete' AND success=0
                ORDER BY created_at DESC;"
```

**Detect suspicious activity (multiple IPs):**
```bash
sqlite3 app.db "SELECT user_email, ip_address, COUNT(*) as attempts
                FROM audit_logs
                WHERE event_type='login_complete' AND success=1
                GROUP BY user_email, ip_address;"
```

**View authorization failures:**
```bash
sqlite3 app.db "SELECT created_at, user_email, ip_address, details
                FROM audit_logs
                WHERE event_type='user_access' AND success=0;"
```

### Promote User to Admin

```bash
sqlite3 app.db "UPDATE users SET role='admin' WHERE email='admin@example.com';"
```

After promoting, the user must **log out and log in again** to receive a new JWT with the `admin` role claim.

### Test Role-Based Access Control

1. Register two users: `user1@example.com` and `user2@example.com`
2. Login as `user1@example.com` → Save JWT token
3. Try to access `user2`'s data with `user1`'s token:
   ```bash
   curl -H "Authorization: Bearer <user1-token>" \
        http://localhost:8000/users/<user2-id>
   ```
   **Expected**: `403 Forbidden` + audit log entry
4. Promote `user1` to admin: `UPDATE users SET role='admin' WHERE email='user1@example.com';`
5. Login as `user1@example.com` again (to get new JWT with `admin` role)
6. Try to access `user2`'s data with `user1`'s admin token:
   ```bash
   curl -H "Authorization: Bearer <user1-admin-token>" \
        http://localhost:8000/users/<user2-id>
   ```
   **Expected**: `200 OK` + `user2`'s data + audit log entry with `(role: admin)`

---

## License

This is an example project for educational purposes.
