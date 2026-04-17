import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"

DB_PATH = os.environ.get("BACKUP_DB_PATH", str(INSTANCE_DIR / "backup.db"))
BACKUP_ROOT = os.environ.get("BACKUP_ROOT", "/srv/backup")

SESSION_SECRET_PATH = INSTANCE_DIR / "flask.secret"
FERNET_KEY_PATH = INSTANCE_DIR / "fernet.key"

FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "8080"))

# 0 ou vazio desabilita retenção automática
BACKUP_KEEP_LAST = int(os.environ.get("BACKUP_KEEP_LAST", "3"))
