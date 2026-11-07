FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY waf.py ./
COPY config/ ./config/

# Run as an unprivileged user
RUN useradd --system --no-create-home waf
USER waf

EXPOSE 8080
ENTRYPOINT ["python3", "waf.py"]
CMD ["--config", "/app/config/waf.json"]
