import httpx
import os

key = os.getenv("GROQ_API_KEY")
if not key:
    raise SystemExit("Set GROQ_API_KEY before running this probe.")

url = "https://api.groq.com/openai/v1/chat/completions"
headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
data = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": "Hello"}]}

try:
    response = httpx.post(url, headers=headers, json=data)
    print("Status:", response.status_code)
    print("Body preview:", response.text[:500])
except Exception as e:
    print("Error:", e)
