import pytest
from auth.router import users_db

def test_register_successful(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "securepassword123"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
    assert "password" not in data
    assert "hashed_password" not in data

def test_register_duplicate_email(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "securepassword123"}
    )
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "differentpassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"

def test_login_successful(client):
    # Setup test user
    client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "my_strong_password"}
    )
    
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "my_strong_password"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_failed_wrong_password(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "real_password"}
    )
    
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"

def test_login_failed_non_existent_user(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"

def test_protected_route_valid_token(client):
    # Register and Login
    client.post(
        "/api/v1/auth/register",
        json={"email": "auth@example.com", "password": "mypassword!"}
    )
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "auth@example.com", "password": "mypassword!"}
    )
    token = login_response.json()["access_token"]
    
    # Access protected route
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == "auth@example.com"

def test_protected_route_invalid_token(client):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not_a_real_token..."}
    )
    assert response.status_code == 401

def test_protected_route_no_token(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401 # HTTPBearer returns 401 when no credentials are provided

def test_security_passwords_are_hashed(client):
    """
    Directly inspects the mock database to verify that passwords
    are fundamentally never stored in plaintext.
    """
    plain_password = "very_secret_plaintext_password_123"
    client.post(
        "/api/v1/auth/register",
        json={"email": "secure@example.com", "password": plain_password}
    )
    
    # Introspect our global mocked db
    assert len(users_db) == 1
    stored_user = list(users_db.values())[0]
    
    # Assert that the password exists but is NOT plaintext
    assert stored_user.hashed_password != plain_password
    # Because bcrypt hashes typically start with $2..., we can check that format
    assert stored_user.hashed_password.startswith("$2")
