# WebAuthn Authentication Backend

A secure authentication microservice implementing passwordless WebAuthn (TouchID/biometric) authentication with JWT tokens. Built for high-security environments with comprehensive logging and authorization controls.

**✨ NEW: Interactive Demo Frontend** - Test TouchID authentication in your browser at `http://localhost:8000`

## Features

- **Passwordless Authentication**: Uses WebAuthn (TouchID, FaceID, Windows Hello) instead of passwords
- **Interactive Demo**: Browser-based frontend to test WebAuthn flows
- **JWT Token-Based Authorization**: Secure, stateless session management
- **Strong Access Control**: Users can only access their own data
- **Security Logging**: Comprehensive audit trail for security monitoring
- **SQLite Database**: Persistent user and credential storage
- **Replay Attack Prevention**: Sign count validation for WebAuthn credentials

## Quick Start

Want to try it right now? Just run:

```bash
# Install dependencies (first time only)
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload

# Open in your browser
open http://localhost:8000
```

Then click "Register" and follow the TouchID prompts to create your first account!

## Architecture

### Authentication Flow

**Registration (Two-Step)**:
1. `POST /register/begin` - Client sends user info → Server returns WebAuthn challenge
2. Client creates credential with TouchID → Client sends credential to server
3. `POST /register/complete` - Server verifies credential → Creates user account

**Login (Two-Step)**:
1. `POST /login/begin` - Client sends email → Server returns WebAuthn challenge
2. Client signs challenge with TouchID → Client sends assertion to server
3. `POST /login/complete` - Server verifies signature → Returns JWT token

**Accessing Protected Resources**:
1. Client includes JWT in `Authorization: Bearer <token>` header
2. Server validates JWT and checks authorization rules
3. `GET /users/{id}` - Returns user data only if user owns the resource

### Security Model

**Authentication**: Multi-factor by design
- Something you have: The device with the registered credential
- Something you are: Biometric verification (TouchID/FaceID)

**Authorization**: Principle of least privilege
- Users can only access their own user data
- JWT tokens contain minimal claims (user_id, email, name)
- Authorization checks happen at endpoint level

## Endpoint Design Decisions

### Differences from Original Specification

The original requirements specified:
- `POST /users` - User self-registration
- `POST /login` - User login
- `GET /users/{id}` - Retrieve user information

Our implementation modifies these endpoints to accommodate WebAuthn's two-step authentication protocol:

#### Modified Endpoints

**Original**: `POST /users`
**Implemented**: `POST /register/begin` + `POST /register/complete`

**Justification**: WebAuthn is inherently a two-step protocol:
1. Server generates a challenge and registration options
2. Client creates credential with authenticator (TouchID)
3. Client sends credential back to server for verification
4. Server validates and stores the credential

A single `/users` endpoint cannot handle this flow because step 2 happens client-side with browser APIs. The registration must be split into two round-trips.

**Original**: `POST /login`
**Implemented**: `POST /login/begin` + `POST /login/complete`

**Justification**: Similar to registration, WebAuthn authentication requires:
1. Server sends challenge and allowed credential IDs
2. Client prompts user for biometric (TouchID)
3. Client signs challenge with private key
4. Server verifies signature and issues JWT

The challenge-response nature of WebAuthn mandates two separate endpoints.

**Kept**: `GET /users/{id}` - No changes, works as specified with JWT authentication

### Why This Architecture is Necessary

WebAuthn is a **challenge-response protocol** that prevents replay attacks. The server must:
1. Generate a cryptographically random challenge
2. Send it to the client
3. Wait for the client to sign it
4. Verify the signature matches the stored public key

This cannot be collapsed into a single request-response cycle because:
- The client needs the challenge before calling `navigator.credentials.create()` or `navigator.credentials.get()`
- These browser APIs are asynchronous and require user interaction (TouchID prompt)
- The signed result must be sent back for verification

### Maintaining API Compatibility

While the endpoint structure differs, the semantic operations match the specification:

| Spec Operation | Implementation | HTTP Method | Returns |
|----------------|----------------|-------------|---------|
| User Registration | `/register/begin` → `/register/complete` | POST + POST | User object (201) |
| User Login | `/login/begin` → `/login/complete` | POST + POST | JWT token |
| Get User Info | `/users/{id}` | GET | User object |

The original requirements are fully satisfied - users can register, login, and retrieve information. The only difference is that registration and login require two API calls instead of one due to the cryptographic protocol.

## API Endpoints

### Public Endpoints

#### `POST /register/begin`
Initiate user registration.

**Request**:
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer"
}
```

**Response**: WebAuthn PublicKeyCredentialCreationOptions
```json
{
  "publicKey": {
    "challenge": "base64-encoded-challenge",
    "rp": {"id": "localhost", "name": "Auth Example"},
    "user": {
      "id": "user-uuid",
      "name": "jane@example.com",
      "displayName": "Jane Doe"
    },
    "pubKeyCredParams": [...],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "required"
    }
  }
}
```

#### `POST /register/complete`
Complete registration by submitting the WebAuthn credential.

**Request**:
```json
{
  "email": "jane@example.com",
  "credential": { /* WebAuthn credential from navigator.credentials.create() */ }
}
```

**Response** (201 Created):
```json
{
  "id": "user-uuid",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer",
  "created_at": "2025-10-22T12:00:00Z"
}
```

#### `POST /login/begin`
Initiate login.

**Request**:
```json
{
  "email": "jane@example.com"
}
```

**Response**: WebAuthn PublicKeyCredentialRequestOptions
```json
{
  "publicKey": {
    "challenge": "base64-encoded-challenge",
    "rpId": "localhost",
    "allowCredentials": [
      {"type": "public-key", "id": "credential-id-hex"}
    ],
    "userVerification": "required"
  }
}
```

#### `POST /login/complete`
Complete login by submitting the WebAuthn assertion.

**Request**:
```json
{
  "email": "jane@example.com",
  "assertion": { /* WebAuthn assertion from navigator.credentials.get() */ }
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "user-uuid",
    "name": "Jane Doe",
    "email": "jane@example.com"
  }
}
```

### Protected Endpoints

#### `GET /users/{id}`
Get user information by ID. Requires JWT authentication.

**Headers**:
```
Authorization: Bearer <jwt-token>
```

**Response**:
```json
{
  "id": "user-uuid",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "date_of_birth": "1990-01-15T00:00:00Z",
  "job_title": "Software Engineer",
  "created_at": "2025-10-22T12:00:00Z"
}
```

**Errors**:
- `401 Unauthorized` - Invalid or expired JWT token
- `403 Forbidden` - User trying to access another user's data
- `404 Not Found` - User doesn't exist

## Running Locally

### Prerequisites
- Python 3.9+
- Modern browser with WebAuthn support (Chrome, Safari, Firefox, Edge)

### Setup

1. **Clone and navigate to the repository**:
```bash
cd auth-example
```

2. **Create and activate virtual environment**:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Set environment variables** (optional):
```bash
export JWT_SECRET="your-secure-secret-key"
export RP_ID="localhost"
export RP_NAME="Auth Example"
export ORIGIN="http://localhost:8000"
```

5. **Run the server**:
```bash
uvicorn main:app --reload
```

The server will start at `http://localhost:8000`.

6. **View API documentation**:
Open `http://localhost:8000/docs` in your browser for interactive API docs.

### Testing & Development

**Reset Database** (to test registration multiple times):

If you need to clear all users and credentials to test registration again:

```bash
# Option 1: Python script only (just clears DB)
python3 reset_db.py

# Option 2: Shell script (clears DB and restarts server)
./reset.sh
```

This is useful when:
- Testing registration flow multiple times with the same email
- Clearing test data between development sessions
- You only have one device with TouchID and want to re-register

Note: The database and logs will be automatically recreated on the next server request.

### Frontend Demo

**NEW!** We now include a fully functional browser-based demo:

1. **Start the server**: `uvicorn main:app --reload`
2. **Open your browser**: Navigate to `http://localhost:8000`
3. **Register a new account**:
   - Fill in the registration form (name, email, date of birth, job title)
   - Click "Register with Biometrics"
   - Your browser will prompt for TouchID/FaceID/Windows Hello
   - Authenticate with your biometric
   - You'll automatically be logged in and see your profile
4. **Test login**:
   - Click "Logout"
   - Switch to the "Login" tab
   - Enter your email
   - Click "Login with Biometrics"
   - Authenticate again to access your profile

**Features**:
- ✅ Live JWT expiration countdown
- ✅ Session management (cleared on tab close)
- ✅ Real-time status messages
- ✅ Loading indicators during biometric prompts
- ✅ Responsive design (mobile & desktop)
- ✅ Error handling for all scenarios

**Browser Requirements**:
- Chrome/Edge (recommended)
- Safari (macOS Big Sur+, iOS 14+)
- Firefox
- Requires biometric hardware (TouchID, FaceID, Windows Hello, or security key)

### API Testing

For API-only testing without the frontend:
- See the `api.http` file for endpoint structure
- Note: `/register/complete` and `/login/complete` require WebAuthn credentials from browser APIs
- Use the interactive frontend for actual TouchID testing

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    date_of_birth DATETIME NOT NULL,
    job_title TEXT NOT NULL,
    created_at DATETIME NOT NULL
);
```

### WebAuthn Credentials Table
```sql
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id BLOB UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Security Controls

### Implemented Controls

✅ **Authentication**
- WebAuthn with platform authenticators (TouchID/FaceID)
- Multi-factor by design (device + biometric)
- Credential public key cryptography
- Challenge-response prevents replay attacks
- Sign count validation prevents credential cloning

✅ **Authorization**
- JWT token-based access control
- Token expiration (60 minutes)
- Authorization checks per endpoint
- Users can only access own resources

✅ **Input Validation**
- Pydantic models for all inputs
- Email format validation
- Required field validation
- Type checking

✅ **Database Security**
- SQL injection prevention (SQLAlchemy ORM)
- Email uniqueness constraints
- Foreign key relationships
- Indexed lookups for performance

✅ **Logging & Monitoring**
- All authentication attempts logged
- Authorization failures logged
- User enumeration protection (generic error messages)
- Audit trail in `app.log`

✅ **Error Handling**
- Generic error messages to prevent information leakage
- Proper HTTP status codes
- Challenge cleanup on failures

### Security Controls NOT Implemented

The following controls are deferred due to infrastructure requirements or complexity beyond this exercise scope:

❌ **Rate Limiting**
- **Why**: Requires Redis or similar distributed cache
- **Risk**: Brute force attacks possible
- **Mitigation**: Should implement per-IP and per-email rate limits in production
- **Recommendation**: Use middleware like `slowapi` with Redis backend

❌ **HTTPS/TLS**
- **Why**: Local testing uses HTTP
- **Risk**: Credentials transmitted in clear text
- **Mitigation**: WebAuthn requires secure context (HTTPS) in production
- **Recommendation**: Deploy behind reverse proxy (nginx) with Let's Encrypt certificates

❌ **Email Verification**
- **Why**: Requires email service integration (SendGrid, AWS SES)
- **Risk**: Users can register with emails they don't own
- **Mitigation**: None currently
- **Recommendation**: Send verification email with time-limited token

❌ **Account Recovery Flow**
- **Why**: Complex multi-step process requiring email service
- **Risk**: Users who lose device credentials cannot recover access
- **Mitigation**: None - users must re-register with new email
- **Recommendation**: Implement recovery codes or backup authentication method

❌ **Distributed Challenge Storage**
- **Why**: Currently using in-memory dictionary (lost on restart)
- **Risk**: Server restart invalidates pending registrations/logins
- **Mitigation**: Acceptable for development
- **Recommendation**: Use Redis with TTL for production

❌ **Secrets Management**
- **Why**: Using environment variables with fallback defaults
- **Risk**: JWT secret could be exposed in source code or logs
- **Mitigation**: Document that `JWT_SECRET` MUST be set in production
- **Recommendation**: Use HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault

❌ **Audit Logging Infrastructure**
- **Why**: Currently logging to local file
- **Risk**: Logs not centralized, difficult to analyze, can be lost
- **Mitigation**: File-based logging adequate for development
- **Recommendation**: Integrate with ELK stack, Splunk, or CloudWatch

❌ **WAF/DDoS Protection**
- **Why**: Requires infrastructure (CloudFlare, AWS WAF)
- **Risk**: Application vulnerable to volumetric attacks
- **Mitigation**: None at application level
- **Recommendation**: Deploy behind WAF with DDoS protection

❌ **Database Encryption at Rest**
- **Why**: SQLite doesn't support native encryption
- **Risk**: Database file contains user PII in plaintext
- **Mitigation**: File system permissions restrict access
- **Recommendation**: Use encrypted database (PostgreSQL with encryption) or encrypt filesystem

❌ **JWT Refresh Tokens**
- **Why**: Adds complexity with token rotation logic
- **Risk**: Users must re-authenticate every 60 minutes
- **Mitigation**: Short session timeout is acceptable for high-security apps
- **Recommendation**: Implement refresh token flow with rotation

❌ **CORS Configuration**
- **Why**: No specific frontend domain defined
- **Risk**: Any origin can call the API in browser context
- **Mitigation**: Accept for development
- **Recommendation**: Configure specific allowed origins for production

❌ **Input Sanitization for XSS**
- **Why**: No HTML rendering in this API (JSON only)
- **Risk**: If used with web frontend, XSS possible
- **Mitigation**: API returns JSON only
- **Recommendation**: Frontend should sanitize before rendering

## Logging

All security-relevant events are logged to both console and `app.log`:

- User registration attempts (success/failure)
- Login attempts (success/failure)
- JWT validation failures
- Authorization failures (users accessing others' data)
- Credential verification failures
- Database operations

**Log Format**: `YYYY-MM-DD HH:MM:SS [LEVEL] message`

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | `your-secret-key-change-in-production` | Secret key for signing JWTs ⚠️ MUST change in production |
| `JWT_ALGORITHM` | `HS256` | Algorithm for JWT signing |
| `JWT_EXPIRATION_MINUTES` | `60` | Token lifetime in minutes |
| `RP_ID` | `localhost` | WebAuthn Relying Party ID (your domain) |
| `RP_NAME` | `Auth Example` | WebAuthn Relying Party display name |
| `ORIGIN` | `http://localhost:8000` | Expected origin for WebAuthn |

## Threat Model Considerations

This application is designed for a **high-security microservice architecture** with the following assumptions:

1. **Strong Authentication Required**: WebAuthn provides phishing-resistant MFA
2. **Security Team Monitoring**: Comprehensive logging enables detection of anomalies
3. **Microservice Architecture**: API-only design (no session cookies)
4. **Internal Network Deployment**: Some controls (WAF, TLS termination) expected at infrastructure layer

**Key Security Properties**:
- Resistant to credential stuffing (no passwords)
- Resistant to phishing (WebAuthn origin binding)
- Resistant to MITM in credential exchange (challenge-response)
- Resistant to replay attacks (sign count validation)
- Defense in depth (authentication + authorization)

## License

This is an example project for educational purposes.