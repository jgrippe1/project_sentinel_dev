
import requests
import json
import sys

def test_google_llm():
    # Configuration provided by user
    api_key = "YOUR_API_KEY"
    model = "gemini-2.5-flash"
    base_url = "https://generativelanguage.googleapis.com"

    # Auto-correction logic matching cve_analyzer.py
    if 'v1beta/openai' not in base_url:
        if base_url == 'https://generativelanguage.googleapis.com':
            base_url += '/v1beta/openai'

    full_url = f"{base_url}/chat/completions"
    
    print(f"Testing connectivity to: {full_url}")
    print(f"Model: {model}")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": model,
        "messages": [
            {"role": "user", "content": "Hello, are you working?"}
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(full_url, headers=headers, json=data, timeout=15)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("SUCCESS! API Response:")
            print(json.dumps(response.json(), indent=2))
        else:
            print("FAILURE. API Response:")
            print(response.text)
            
    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    test_google_llm()
