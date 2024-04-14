import bcrypt

def check_validate_input(string: str):
    blocked_pattern: str = "<>='`"
    for pattern in blocked_pattern.split():
        if pattern in string:
            return False
    return True

def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password.encode(), bcrypt.gensalt())

def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password.encode(), hashed_password.encode())