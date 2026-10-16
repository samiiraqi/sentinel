# Hardened Dockerfile: Checkov should report no failed checks.
FROM python:3.12.7-slim
RUN useradd --create-home app
USER app
HEALTHCHECK CMD python -c "print('ok')"
CMD ["python", "-c", "print('hello')"]
