import os
import re

def process_dir(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r') as f:
                    content = f.read()
                
                # Match await db.flush() followed by hardcoded 8 spaces refresh
                new_content = re.sub(
                    r'([ \t]*)await db\.flush\(\)\n        await db\.refresh\(([a-zA-Z0-9_]+)\)\n        await db\.commit\(\)',
                    r'\1await db.flush()\n\1await db.refresh(\2)\n\1await db.commit()',
                    content
                )
                if new_content != content:
                    print(f'Fixed {path}')
                    with open(path, 'w') as f:
                        f.write(new_content)

process_dir('apps/api/app/api/v1/endpoints')

