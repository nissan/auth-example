from typing import Union, Optional
from fastapi import FastAPI, status, Body, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field, constr, validator
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer, LargeBinary, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import uuid
import logging
import os
from jose import JWTError, jwt

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
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    date_of_birth = Column(DateTime, nullable=False)
    job_title = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to WebAuthn credentials
    credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan")

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

# Create database tables on startup
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")

class UserCreateModel(BaseModel):
    name: str
    email: EmailStr
    date_of_birth: datetime
    job_title: str
    password: str          

class UserViewModel(BaseModel):
    id: str
    name: str
    email: EmailStr
    date_of_birth: datetime
    job_title: str


@app.get("/users/{user_id}", response_model=UserViewModel)
def get_user(user_id: str) -> UserViewModel:  
    dummy_user = UserViewModel(
        id="1",
        name="John Smith",
        email="john@acme.com",
        date_of_birth=datetime.fromisoformat("1980-04-14T10:00:00+00:00"), 
        job_title="Janitor",
    )
    return dummy_user

@app.post("/users",response_model=UserViewModel,status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreateModel) -> UserViewModel:
    user = UserViewModel(
        id="1",
        name=payload.name,
        email=payload.email,
        date_of_birth=payload.date_of_birth, 
        job_title=payload.job_title,
    )

    # Log the signup event
    logger.info(f"New user signed up: {user.name} ({user.email}), job title: {user.job_title}")

    return user

@app.post("/login")
def login_user(
    email: str = Body(..., embed=True),
    password: str = Body(..., embed=True),
):
    dummy_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxYzRmODc4YS0yZTUzLTQ3MjctOTMyMy1kN2JjNzQ4M2I5N2UiLCJuYW1lIjoiSmFuZSBEb2UiLCJlbWFpbCI6ImphbmVAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlzcyI6InNlY3VyZS1iYWNrZW5kIiwiYXVkIjoic2VjdXJlLWJhY2tlbmQtdXNlcnMiLCJpYXQiOjE3MzAzMjg3MDAsImV4cCI6MTczMDMyOTYwMCwianRpIjoiYTJmNzc4NjEtZDc3Zi00ZTlkLWI1NDctZTQ4ZGVhODdhZDRkIiwidHYiOjF9.SpI3M8GlPGe_LqQttwC0HVWSpCBZIrqIYhL9qG9jX2E"
    return {"access_token": dummy_jwt, "token_type": "bearer"}