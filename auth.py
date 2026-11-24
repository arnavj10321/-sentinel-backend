from datetime import datetime,timedelta,timezone

import bcrypt
import jwt
from fastapi import Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer

from config import Settings
from database import get_db
from models import User
from sqlalchemy.orm import Session

oauth2_scheme=OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"),bcrypt.gensalt()).decode("utf-8")

def verfy_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"),hashed.encode("utf-8"))

def create_access_token(emial: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=Settings.access_token_expire_minutes
    )
    return jwt.encode(
        {"Sub":email,"exp":expire},Settings.secret_key,algorithm="HS256"
    )

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token,Settings)