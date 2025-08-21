FROM python:3.11-slim

# install git and curl (for healthcheck)
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/agents/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/agents/app /app/app

EXPOSE 8080
CMD ["uvicorn","app.server:app","--host","0.0.0.0","--port","8080"]

