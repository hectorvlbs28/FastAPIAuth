from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

auth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/")
async def root():
    return "Hello, World!"

@app.get("/users/me")
async def user(token: str = Depends(auth2_scheme)):
    print(token)
    return "I am the current user."

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    return {
        "access_token": form_data.username,
        "token_type": "bearer"
    }