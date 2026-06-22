import os
import re

def process_dir(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r') as f:
                    content = f.read()
                
                # Match await db.commit() followed by await db.refresh(var)
                # We want to replace it with await db.flush() ... refresh ... commit
                # Let's use regex
                new_content = re.sub(
                    r'(await\s+db\.commit\(\)\s*\n\s*await\s+db\.refresh\(\s*([a-zA-Z0-9_]+)\s*\))',
                    r'await db.flush()\n        await db.refresh(\2)\n        await db.commit()',
                    content
                )
                if new_content != content:
                    print(f'Fixed {path}')
                    with open(path, 'w') as f:
                        f.write(new_content)

process_dir('apps/api/app/api/v1/endpoints')

