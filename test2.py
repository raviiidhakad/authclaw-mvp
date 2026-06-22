from passlib.context import CryptContext
print(CryptContext(schemes=['bcrypt']).verify('root@123', '$2b$12$Wu.L.0XNlvHfcuDIouluneWhxYSh5Z2zHe4oAJ.v8xJ5Q1jaR8ETC'))
