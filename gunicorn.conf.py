# Auto-loaded by gunicorn from the working directory (so `gunicorn host:app` picks it up).
# Binds to the platform-provided $PORT (Azure App Service / Heroku-style), defaulting to 8000,
# which is the port Azure's built-in Python image expects when PORT is not injected.
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
worker_class = "gthread"
timeout = 60
graceful_timeout = 20
accesslog = "-"
errorlog = "-"
