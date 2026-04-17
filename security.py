import os
from pathlib import Path
from passlib.hash import bcrypt
from cryptography.fernet import Fernet
from config import INSTANCE_DIR, FERNET_KEY_PATH, SESSION_SECRET_PATH


def ensure_instance_dir():
    Path(INSTANCE_DIR).mkdir(parents=True, exist_ok=True)


def load_fernet():
    ensure_instance_dir()
    if not Path(FERNET_KEY_PATH).exists():
        key = Fernet.generate_key()
        Path(FERNET_KEY_PATH).write_bytes(key)
        os.chmod(FERNET_KEY_PATH, 0o600)
    key = Path(FERNET_KEY_PATH).read_bytes()
    return Fernet(key)


def load_session_secret():
    ensure_instance_dir()
    if not Path(SESSION_SECRET_PATH).exists():
        secret = os.urandom(32)
        Path(SESSION_SECRET_PATH).write_bytes(secret)
        os.chmod(SESSION_SECRET_PATH, 0o600)
    return Path(SESSION_SECRET_PATH).read_bytes()


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.verify(password, password_hash)
    except Exception:
        return False


def encrypt_secret(value: str) -> str:
    f = load_fernet()
    return f.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    f = load_fernet()
    return f.decrypt(value.encode("utf-8")).decode("utf-8")
