from datetime import datetime, timedelta, timezone
import bcrypt
import jwt

# SECRET_KEY should be loaded from environment variables in a real application
SECRET_KEY = "SUPER_SECRET_KEY_PLEASE_CHANGE_IN_PRODUCTION"
ALGORITHM = "HS256"
# Short expiration time for access tokens minimizes the window of opportunity if a token is compromised
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a hashed one."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Hashes a password using bcrypt. Salt is automatically appended."""
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pwd.decode('utf-8')

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Creates a signed JSON Web Token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        
    # 'exp' (expiration time) is a standard JWT claim. It ensures the token becomes invalid after a certain time.
    to_encode.update({"exp": expire})
    
    # We sign the token using HMAC-SHA256 (HS256) and our secret key.
    # This ensures that if the token payload is tampered with by the client, 
    # the signature verification will fail on the server.
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
