"""Service configuration (benchmark fixture: contains planted secrets)."""
import os
import tempfile

AWS_ACCESS_KEY_ID = "AKIA4QZT7NRW2KXB9MDL"
AWS_SECRET_ACCESS_KEY = "q7Hc2Lw9Rk/Tz4Vb8Np1Xs6Jd3Fm0Ga5Ye7Ui2Ko"
GITHUB_TOKEN = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"
DATABASE_URL = "postgresql://admin:Sup3rS3cret@db.internal:5432/prod"
JWT_SECRET = "my-jwt-signing-secret-Xk29Lq"

STRIPE_KEY = os.getenv("STRIPE_KEY")
API_TIMEOUT = 30
PASSWORD_MIN_LENGTH = 12
DEFAULT_PASSWORD_HINT = "use a passphrase"

DEPLOY_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaV4sV9bL2kXnUeu
-----END RSA PRIVATE KEY-----"""

DEBUG = True


def scratch_file():
    return tempfile.mktemp(suffix=".tmp")


def share_upload_dir(path):
    os.chmod(path, 0o777)
