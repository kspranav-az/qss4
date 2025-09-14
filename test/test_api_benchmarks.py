import pytest
import requests
import json
import os

BASE_URL = "http://localhost:5001"
TEST_USER = "benchmark_user@example.com"
TEST_PASSWORD = "BenchmarkPassword123"
TOKEN_FILE = "test/stress_token.json"

@pytest.fixture(scope="session")
def jwt_token():
    """Fixture to get or generate a JWT token for testing."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            # Ensure user_id is also loaded if present
            return token_data.get("access_token"), token_data.get("refresh_token"), token_data.get("user_id")

    # If token file doesn't exist, register and login
    register_url = f"{BASE_URL}/api/v1/auth/register"
    register_payload = {"email": TEST_USER, "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD}
    requests.post(register_url, json=register_payload)

    login_url = f"{BASE_URL}/api/v1/auth/login"
    login_payload = {"email": TEST_USER, "password": TEST_PASSWORD}
    response = requests.post(login_url, json=login_payload)
    response.raise_for_status()
    tokens = response.json().get("tokens")
    user_id = response.json().get("user").get("id")

    # Ensure the directory for TOKEN_FILE exists
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        json.dump({"access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"], "user_id": user_id}, f)
    return tokens["access_token"], tokens["refresh_token"], user_id

def test_login_benchmark(benchmark, jwt_token):
    """Benchmark the login endpoint."""
    access_token, _, _ = jwt_token
    login_url = f"{BASE_URL}/api/v1/auth/login"
    login_payload = {"email": TEST_USER, "password": TEST_PASSWORD}
    benchmark(requests.post, login_url, json=login_payload)

def test_health_check(jwt_token):
    """Test the health check endpoint with authentication."""
    access_token, _, _ = jwt_token
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/api/v1/health/live", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.fixture(scope="module")
def dummy_file(tmp_path_factory):
    """Fixture to create a dummy file for upload."""
    file_content = b"This is a dummy file for testing file uploads."
    file_path = tmp_path_factory.mktemp("data") / "dummy.txt"
    with open(file_path, "wb") as f:
        f.write(file_content)
    return file_path

def test_file_upload_benchmark(benchmark, jwt_token, dummy_file):
    """Benchmark the file upload endpoint."""
    access_token, _, _ = jwt_token
    headers = {"Authorization": f"Bearer {access_token}"}
    upload_url = f"{BASE_URL}/api/v1/files/upload"

    def upload_file_wrapper():
        return upload_file(access_token, dummy_file)

    file_id = benchmark(upload_file_wrapper)
    
    # Clean up the uploaded file
    delete_url = f"{BASE_URL}/api/v1/files/{file_id}"
    requests.delete(delete_url, headers=headers)

def upload_file(jwt_token, dummy_file):
    files = {'file': (os.path.basename(dummy_file), open(dummy_file, 'rb'), 'application/octet-stream')}
    response = requests.post(f"{BASE_URL}/api/v1/files/upload",
                             headers={"Authorization": f"Bearer {jwt_token}"},
                             files=files)
    response.raise_for_status()
    return response.json()["file"]["file_id"]


def test_file_download_benchmark(benchmark, jwt_token, dummy_file):
    """Benchmark the file download endpoint."""
    access_token, refresh_token, user_id = jwt_token
    headers = {"Authorization": f"Bearer {access_token}"}

    # Upload a file first to have something to download
    file_id = upload_file(access_token, dummy_file)
    assert file_id is not None

    download_url_template = f"{BASE_URL}/api/v1/files/{file_id}/download?token="

    def download_file_wrapper():
        # Create a download token for each download attempt
        token_response = requests.post(f"{BASE_URL}/api/v1/files/{file_id}/token",
                                       headers=headers,
                                       json={"ttl_seconds": 60})
        token_response.raise_for_status()
        download_token = token_response.json()["token"]
        assert download_token is not None

        download_url = f"{download_url_template}{download_token}"

        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        # Consume the content to simulate a full download
        for chunk in response.iter_content(chunk_size=8192):
            pass

    benchmark(download_file_wrapper)

    # Clean up the uploaded file
    delete_url = f"{BASE_URL}/api/v1/files/{file_id}"
    requests.delete(delete_url, headers=headers)
