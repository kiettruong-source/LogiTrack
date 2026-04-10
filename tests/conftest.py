import pytest
from fastapi.testclient import TestClient
from main import app
from auth.router import users_db

@pytest.fixture
def client():
    """
    Test client for FastAPI app. Uses HTTPX under the hood.
    """
    return TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    """
    Auto-used fixture that clears out the mocked in-memory database
    before every single test. This ensures all tests are isolated 
    from side-effects of other test runs.
    """
    users_db.clear()
    yield
