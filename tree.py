import os

def print_tree(startpath, max_level):
    for root, dirs, files in os.walk(startpath):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.next', '__pycache__', '.venv', '.git')]
        
        level = root.replace(startpath, '').count(os.sep)
        if level > max_level:
            continue
        indent = ' ' * 4 * (level)
        print('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))

print("=== API ===")
print_tree('apps/api', 3)
print("\n=== WEB ===")
print_tree('apps/web', 3)
