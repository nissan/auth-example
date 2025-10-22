from typing import Union
from fastapi import FastAPI, status
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
    dummy_user = UserViewModel(
        id="1",
        name="John Smith",
        email="john@acme.com",
        date_of_birth=datetime.fromisoformat("1980-04-14T10:00:00+00:00"), 
        job_title="Janitor",
    )
    return dummy_user

