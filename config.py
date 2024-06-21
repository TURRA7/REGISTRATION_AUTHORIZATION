"""Application Configuration Module."""

import os
from dotenv import load_dotenv


load_dotenv()


PG_USER = os.environ.get("PG_USER")
PG_PASS = os.environ.get("PG_PASS")
PG_HOST = os.environ.get("PG_HOST")
PG_PORT = os.environ.get("PG_PORT")
PG_DB = os.environ.get("PG_DB")
WOKR_EMAIL = os.environ.get("WOKR_EMAIL")
WOKR_EMAIL_PASS = os.environ.get("WOKR_EMAIL_PASS")
WORK_HOSTNAME = os.environ.get("WORK_HOSTNAME")
WOKR_PORT = os.environ.get("WOKR_PORT")
SECRET_KEY = os.environ.get("SECRET_KEY")
SESSION_STATE_CODE = os.environ.get("SESSION_STATE_CODE")
SESSION_STATE_MAIL = os.environ.get("SESSION_STATE_MAIL")
REDIS_URL = os.environ.get("REDIS_URL")
SENTRY_DNS = os.environ.get("SENTRY_DNS")
