# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a FastAPI-based authentication example application. Currently implements basic user registration and login endpoints with placeholder/dummy implementations. SQLAlchemy is configured but not yet integrated into the endpoints.

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

### Current State
- **Single-file application**: All code is in `main.py`
- **Database**: SQLAlchemy configured for SQLite (`app.db`) but not yet connected to endpoints
- **Endpoints return dummy data**: Both `/users/{user_id}` (GET) and `/login` (POST) return hardcoded responses
- **No actual authentication**: Login endpoint returns a static JWT token
- **Logging**: Configured to write to both console and `app.log`

### Data Models
Two Pydantic models exist:
- `UserCreateModel`: For registration (includes password)
- `UserViewModel`: For responses (excludes password)

### Database Configuration
- SQLAlchemy Base, engine, and session factory configured at top of `main.py`
- `get_db()` dependency function exists but is not yet used in endpoints
- No SQLAlchemy models defined yet (Base is unused)

### Key Implementation Gaps
The codebase is in an early stage. To make this production-ready:
1. Define SQLAlchemy User model and create tables
2. Implement actual user creation in the database (POST /users)
3. Implement password hashing (bcrypt/passlib)
4. Implement actual authentication logic in /login endpoint
5. Add JWT token generation and validation
6. Use the `get_db()` dependency in endpoints
7. Implement actual user lookup in GET /users/{user_id}
