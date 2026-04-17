FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /srv/backup /app/instance

EXPOSE 8080

CMD ["sh", "-c", "exec gunicorn -w ${GUNICORN_WORKERS:-2} -b ${FLASK_HOST:-0.0.0.0}:${FLASK_PORT:-8080} --timeout ${GUNICORN_TIMEOUT:-120} app:app"]
