FROM python:3.13-slim
WORKDIR /app
COPY index.html ./
# Render provides $PORT at runtime
CMD ["sh", "-c", "python3 -m http.server ${PORT:-10000} --bind 0.0.0.0"]
