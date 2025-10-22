# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a FastAPI-based passwordless authentication microservice implementing WebAuthn (TouchID/biometric) with JWT authorization. Designed for high-security environments with comprehensive logging and access controls.

## Development Commands

### Running the Server
```bash
# Activate virtual environment first
source .venv/bin/activate

# Run development server with auto-reload
uvicorn main:app --reload

# Server runs on http://localhost:8000
# API docs available at http://localhost:8000/docs
```

### Testing API Endpoints
The project includes an `api.http` file with pre-configured HTTP requests for testing endpoints. Variables are defined at the top of the file:
- User registration: `POST /users`
- User login: `POST /login`
- Get user: `GET /users/{user_id}`

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt
```

## Architecture

### Implementation Status: ✅ Complete

- **Single-file application**: All code in `main.py` (613 lines)
- **Database**: SQLite with two tables (users, webauthn_credentials)
- **Authentication**: WebAuthn passwordless authentication with TouchID/FaceID
- **Authorization**: JWT tokens with 60-minute expiration
- **Logging**: All security events logged to console and `app.log`

### Key Components

**Database Models** (SQLAlchemy):
- `User`: Stores user profile (name, email, DOB, job_title)
- `WebAuthnCredential`: Stores public keys and credential metadata

**Pydantic Models**:
- `UserRegistrationRequest`: Registration input
- `UserViewModel`: User data response
- `RegistrationCompleteRequest`: WebAuthn credential submission
- `LoginBeginRequest`: Login initiation
- `LoginCompleteRequest`: WebAuthn assertion submission

**Authentication Flow**:
- `POST /register/begin` → Generate WebAuthn challenge
- `POST /register/complete` → Verify credential, create user
- `POST /login/begin` → Generate auth challenge
- `POST /login/complete` → Verify assertion, return JWT
- `GET /users/{id}` → Protected endpoint with JWT auth

**JWT Utilities**:
- `create_access_token()`: Generate signed tokens
- `verify_access_token()`: Validate and decode tokens
- `get_current_user()`: FastAPI dependency for auth

**Security Features**:
- Challenge-response prevents replay attacks
- Sign count validation prevents credential cloning
- Authorization checks (users access only own data)
- Generic error messages prevent user enumeration
- Comprehensive logging for security monitoring

### Important: WebAuthn Testing

WebAuthn requires browser APIs and **cannot be tested with curl/Postman**. To test:
1. Create HTML frontend with JavaScript
2. Use `navigator.credentials.create()` for registration
3. Use `navigator.credentials.get()` for authentication

See `README.md` section "Testing" for details.
