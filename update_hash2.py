import subprocess

sql = "UPDATE users SET password_hash='$2b$12$oabfGlN7WAvIBHbdmifQPO/uA4J.1dFSQxnVlz/cXT4/C2KGihCRe' WHERE email='root.test1@gmail.com';"

subprocess.run([
    'docker', 'exec', '-i', 'authclawproject-db-1', 
    'psql', '-U', 'postgres', '-d', 'authclaw', '-c', sql
])
