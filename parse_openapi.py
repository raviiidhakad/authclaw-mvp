import json

with open('openapi.json', 'r') as f:
    data = json.load(f)

for path, methods in data.get('paths', {}).items():
    for method, details in methods.items():
        print(f"{method.upper()} {path} - {details.get('summary', '')}")
