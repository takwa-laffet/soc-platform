FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 5001

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--timeout", "120", "app:app"]
