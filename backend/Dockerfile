FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --shell /bin/bash appuser

COPY --chown=appuser:appuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

USER appuser

ENV PORT=5001

EXPOSE 5001

CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
