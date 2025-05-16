from fastapi import FastAPI, HTTPException, Depends, Request
from pymongo import MongoClient
from auth import create_access_token, create_refresh_token, verify_token
from passlib.hash import bcrypt
from pydantic import BaseModel

app = FastAPI()

# Connect to MongoDB Atlas
client = MongoClient("mongodb+srv://Ashwin:296UDiJSili9Lpnz@ashcluster.7p7zc61.mongodb.net/")
db = client["forPratham"]
users = db["users"]

# ----------- Models -----------
class User(BaseModel):
    username: str
    password: str

class TokenRequest(BaseModel):
    refresh_token: str

# ----------- Routes -----------
@app.post("/register")
def register(user: User):
    if users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = bcrypt.hash(user.password)
    users.insert_one({"username": user.username, "password": hashed_password})
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: User):
    db_user = users.find_one({"username": user.username})
    if not db_user or not bcrypt.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user.username})
    refresh_token = create_refresh_token({"sub": user.username})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@app.post("/refresh")
def refresh_tokens(body: TokenRequest):
    payload = verify_token(body.refresh_token)
    if not payload:
        raise HTTPException(status_code=403, detail="Invalid refresh token")
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=403, detail="Invalid token payload")

    new_access_token = create_access_token({"sub": username})
    return {"access_token": new_access_token}

@app.get("/protected")
def protected_route(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {"message": f"Hello, {payload['sub']}!"}
