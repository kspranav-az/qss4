import requests
import json

BASE_URL = "http://localhost:5001"

def register_and_login(email, password):
    # Register user
    register_url = f"{BASE_URL}/api/v1/auth/register"
    register_payload = {"email": email, "password": password, "confirm_password": password}
    response = requests.post(register_url, json=register_payload)
    print(f"Register response status: {response.status_code}")
    print(f"Register response: {response.json()}")

    # Login user
    login_url = f"{BASE_URL}/api/v1/auth/login"
    login_payload = {"email": email, "password": password}
    response = requests.post(login_url, json=login_payload)
    print(f"Login response status: {response.status_code}")
    login_data = response.json()
    print(f"Login response: {login_data}")

    if response.status_code == 200 and "tokens" in login_data:
        return login_data["tokens"]["access_token"], login_data["tokens"]["refresh_token"]
    return None, None

if __name__ == "__main__":
    test_email = "benchmark_user@example.com"
    test_password = "BenchmarkPassword123"
    access_token, refresh_token = register_and_login(test_email, test_password)

    if access_token and refresh_token:
        print(f"Successfully obtained JWT access token: {access_token}")
        print(f"Successfully obtained JWT refresh token: {refresh_token}")
        with open("stress_token.json", "w") as f:
            json.dump({"access_token": access_token, "refresh_token": refresh_token}, f)
        print("Tokens saved to test_token.json")
    else:
        print("Failed to obtain JWT tokens.")