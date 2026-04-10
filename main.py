from fastapi import FastAPI
from auth.router import router as auth_router

app = FastAPI(title="Identity Service API", description="Core Identity Service for Authentication")

# Include the authentication router
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Identity Service API"}
