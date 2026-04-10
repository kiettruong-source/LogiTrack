from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    # Email validation provided out of the box by Pydantic's EmailStr
    email: EmailStr
    # Password must be reasonably strong: At least 8 characters
    password: str = Field(min_length=8, max_length=72, description="Password must be at least 8 characters long")

class UserInDB(BaseModel):
    """Internal model for database representation, do not leak hashed_password to external users"""
    id: str
    email: EmailStr
    hashed_password: str

class Token(BaseModel):
    """Response model for login containing JWT access token"""
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    """Response model for public user metadata, hides sensitive fields"""
    id: str
    email: EmailStr
