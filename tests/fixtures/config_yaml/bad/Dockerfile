# FAKE fixture: deliberately insecure Dockerfile for tests (runs as root, no healthcheck).
FROM python:latest
RUN pip install flask
CMD ["python", "-m", "flask", "run"]
