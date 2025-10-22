from typing import Union
from fastapi import FastAPI, status, Body
from pydantic import BaseModel, EmailStr, Field, constr, validator
from datetime import datetime

app = FastAPI(title="Simple Backend ")

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
    return user

@app.post("/login")
def login_user(
    email: str = Body(..., embed=True),
    password: str = Body(..., embed=True),
):
    dummy_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxYzRmODc4YS0yZTUzLTQ3MjctOTMyMy1kN2JjNzQ4M2I5N2UiLCJuYW1lIjoiSmFuZSBEb2UiLCJlbWFpbCI6ImphbmVAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlzcyI6InNlY3VyZS1iYWNrZW5kIiwiYXVkIjoic2VjdXJlLWJhY2tlbmQtdXNlcnMiLCJpYXQiOjE3MzAzMjg3MDAsImV4cCI6MTczMDMyOTYwMCwianRpIjoiYTJmNzc4NjEtZDc3Zi00ZTlkLWI1NDctZTQ4ZGVhODdhZDRkIiwidHYiOjF9.SpI3M8GlPGe_LqQttwC0HVWSpCBZIrqIYhL9qG9jX2E"
    return {"access_token": dummy_jwt, "token_type": "bearer"}