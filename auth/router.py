from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import Dict
import uuid
from datetime import timedelta

from .models import UserCreate, UserInDB, Token, UserResponse
from .security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()
security = HTTPBearer()

# In-memory database for demonstration purposes
# NEVER use in-memory dicts for storage in production. Use a database (PostgreSQL, MongoDB, etc.)
users_db: Dict[str, UserInDB] = {}

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserResponse:
    """
    Dependency to intercept the Authorization header and validate the JWT.
    """
    token = credentials.credentials
    try:
        # jwt.decode verifies both the signature and the 'exp' claim automatically.
        # If the token is expired or tampered with, it raises an exception.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # 'sub' (subject) is a standard claim representing the user ID.
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
            
    except jwt.ExpiredSignatureError:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError: # Catch all other JWT errors (invalid signature, etc.)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    user = users_db.get(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
    return UserResponse(id=user.id, email=user.email)


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def register(user_in: UserCreate):
    """
    Registers a new user. Expects a JSON payload with 'email' and 'password'.
    """
    # Check if user already exists
    for user in users_db.values():
        if user.email == user_in.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
            
    # Hash the password. NEVER store plaintext passwords.
    hashed_pwd = get_password_hash(user_in.password)
    
    user_id = str(uuid.uuid4())
    new_user = UserInDB(id=user_id, email=user_in.email, hashed_password=hashed_pwd)
    
    # Store in database
    users_db[user_id] = new_user
    
    return UserResponse(id=new_user.id, email=new_user.email)

@router.post("/login", response_model=Token)
async def login(user_in: UserCreate):
    """
    Authenticates a user and returns a JWT access token.
    """
    # Find user by email
    db_user = None
    for user in users_db.values():
        if user.email == user_in.email:
            db_user = user
            break
            
    if not db_user:
        # Return generic error to prevent email/username enumeration attacks
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        
    # Verify the password against the stored hash
    if not verify_password(user_in.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        
    # Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # The 'sub' claim should be the unique identifier for the user
    access_token = create_access_token(
        data={"sub": db_user.id}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    """
    Protected route. Returns the current user's information if the token is valid.
    """
    return current_user
