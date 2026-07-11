import os
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session
from .database import get_db, set_tenant_context
from .models import User, APIKey
import secrets

SECRET_KEY = os.environ.get(
    "KAAVAL_SECRET_KEY",
    "kaaval_super_secret_key_change_me_in_prod",
)
REFRESH_SECRET_KEY = os.environ.get(
    "KAAVAL_REFRESH_SECRET_KEY",
    "kaaval_refresh_secret_key_change_me_in_prod",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# bcrypt ignores everything past 72 bytes; truncate explicitly so hashes
# minted by the previous passlib setup (which truncated silently) keep
# verifying, and bcrypt>=4 doesn't raise on long inputs.
_BCRYPT_MAX = 72


def verify_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(
            plain_password.encode()[:_BCRYPT_MAX], hashed_password.encode()
        )
    except ValueError:
        return False


def get_password_hash(password):
    return bcrypt.hashpw(password.encode()[:_BCRYPT_MAX], bcrypt.gensalt()).decode()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def decode_refresh_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def generate_api_key():
    prefix = secrets.token_urlsafe(8)[:7]
    raw_key = secrets.token_urlsafe(32)
    return raw_key, prefix


async def get_user_from_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except jwt.PyJWTError:
        return None
    user = db.query(User).filter(User.username == username).first()
    if user:
        set_tenant_context(str(user.tenant_id))
    return user


async def get_user_by_api_key(
    x_api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db),
):
    if not x_api_key or len(x_api_key) < 8:
        return None
    prefix = x_api_key[:7]
    api_key_record = db.query(APIKey).filter(APIKey.prefix == prefix).first()
    if api_key_record and verify_password(x_api_key, api_key_record.key_hash):
        api_key_record.last_used_at = datetime.utcnow()
        db.commit()
        user = db.query(User).filter(User.id == api_key_record.user_id).first()
        if user:
            set_tenant_context(str(user.tenant_id))
        return user
    return None


async def get_current_user(token_user: Optional[User] = Depends(get_user_from_token)):
    if not token_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_user


async def get_current_active_user(
    token_user: Optional[User] = Depends(get_user_from_token),
    api_key_user: Optional[User] = Depends(get_user_by_api_key),
):
    user = token_user or api_key_user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
