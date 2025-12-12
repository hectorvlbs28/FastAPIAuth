from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

app = FastAPI()

auth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

fake_users_db = {
    "root": {
        "username": "root",
        "full_name": "Root User",
        "email": "root@gmail.com",
        "hashed_password": pwd_context.hash("toor"),
        "disabled": False,
    }
}

SECRET_KEY = "436e95feae3340fa9d077087e4366651f91c3032ee25cc974469e8a583c984fc"
ALGORITHM = "HS256"


class User(BaseModel):
    username: Union[str, None] = None
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str, db):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    return []


def authenticate_user(username: str, password: str, db):
    user = get_user(username, db)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    return user


def access_token(data: dict, time_expire: Union[datetime, None] = None):
    data_copy = data.copy()
    now = datetime.now(timezone.utc)
    if time_expire is None:
        expires = now + timedelta(minutes=15)
    else:
        expires = now + time_expire
    data_copy.update({"exp": expires})
    token_jwt = jwt.encode(data_copy, key=SECRET_KEY, algorithm=ALGORITHM)
    return token_jwt


@app.get("/")
async def root():
    return "Hello, World!"


@app.get("/users/me")
async def user(token: str = Depends(auth2_scheme)):
    return token


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password, fake_users_db)
    access_token_expires = timedelta(minutes=30)
    acces_token_jwt = access_token({"sub": user.username}, access_token_expires)
    return {
        "access_token": acces_token_jwt,
        "token_type": "bearer"
    }
