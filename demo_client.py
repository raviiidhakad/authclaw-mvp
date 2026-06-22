import os
from openai import OpenAI

# ==========================================
# AUTHCLAW LIVE DEMO SCRIPT
# ==========================================
# Instructions for Demo:
# 1. Put your AuthClaw API Key here (starts with 'ac_')
AUTHCLAW_API_KEY = "ac_d539c9a160134696c20673ad3ec0b53e395bbdc8a68f1f83"

# 2. Point to the AuthClaw Gateway instead of OpenAI
AUTHCLAW_BASE_URL = "http://localhost:8000/api/v1/gateway"

print("🚀 Connecting to AuthClaw AI Gateway...")

# Initialize the official OpenAI client, but route it through AuthClaw!
client = OpenAI(
    api_key=AUTHCLAW_API_KEY,
    base_url=AUTHCLAW_BASE_URL,
)

def run_demo():
    print("\n" + "="*50)
    print("Welcome to AuthClaw Live Demo!")
    print("Type 'exit' to quit.")
    print("="*50)
    
    while True:
        user_prompt = input("\n👤 Enter Prompt for AI: ")
        if user_prompt.lower() == 'exit':
            break
            
        print("⏳ Processing through AuthClaw Policy Engine...")
        
        try:
            # This looks like a standard OpenAI call, but it's protected by AuthClaw!
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            print("\n🤖 AI Response:")
            print(response.choices[0].message.content)
            
        except Exception as e:
            print("\n❌ AUTHCLAW INTERCEPTED THE REQUEST!")
            print(f"Error Message: {e}")

if __name__ == "__main__":
    run_demo()
