import requests
import os
import time
import subprocess

# Start the Flask API in the background
print("Starting API in background...")
env = os.environ.copy()
env["SUPERVISOR_TOKEN"] = "mock_token_123"
env["PYTHONPATH"] = os.path.abspath("project_sentinel")
api_process = subprocess.Popen(["python", "project_sentinel/sentinel/api.py"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2) # wait for startup

try:
    # 1. Test without token (Should fail with 401)
    print("Test 1: Unauthenticated Request")
    res1 = requests.post("http://127.0.0.1:8099/api/assets/approve", json={"mac": "00:11:22:33:44:55"})
    print(f"Status: {res1.status_code}, Response: {res1.text}")
    assert res1.status_code == 401, "Expected 401 Unauthorized"

    # 2. Test with invalid token (Should fail with 403)
    print("\nTest 2: Invalid Token Request")
    res2 = requests.post("http://127.0.0.1:8099/api/assets/approve", json={"mac": "00:11:22:33:44:55"}, headers={"Authorization": "Bearer bad_token"})
    print(f"Status: {res2.status_code}, Response: {res2.text}")
    assert res2.status_code == 403, "Expected 403 Forbidden"

    # 3. Test with valid token (Should succeed with 200 or 500 depending on DB state, but not Auth error)
    print("\nTest 3: Valid Token Request")
    res3 = requests.post("http://127.0.0.1:8099/api/assets/approve", json={"mac": "00:11:22:33:44:55"}, headers={"Authorization": "Bearer mock_token_123"})
    print(f"Status: {res3.status_code}, Response: {res3.text}")
    assert res3.status_code in [200, 500], "Expected 200 or 500 (DB logic), not auth error"

    print("\nAll auth tests passed successfully!")

finally:
    api_process.terminate()
    api_process.wait()
