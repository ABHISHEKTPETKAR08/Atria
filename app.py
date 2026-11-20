"""Entry-point alias. Azure App Service (Oryx) auto-detects app.py when no startup command is set,
so the site still boots with `gunicorn app:app`. The real application lives in host.py."""
from host import app  # noqa: F401
