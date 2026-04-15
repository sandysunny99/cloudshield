# ── CloudShield Backend Dockerfile ──────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="CloudShield"
LABEL description="CloudShield AI-Augmented Cloud Security Platform Backend"

# Install Trivy
RUN apt-get update && apt-get install -y wget apt-transport-https gnupg curl \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
       gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ .

# Copy policies
COPY policies/ /app/policies/

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "wsgi:app"]
