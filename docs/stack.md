# CloudShield Technology Stack

CloudShield is built using a modern, scalable, and secure technology stack designed for rapid telemetry ingestion and global scale.

## Frontend
- **Vite**: Ultra-fast build tool for local development and bundle optimization.
- **JavaScript (ES6+)**: Core Vanilla JS orchestration for polling and UI updates.
- **Vanilla CSS**: Custom styling with CSS vars matching the deep cyber-aesthetic requirements.
- **Vercel**: Edge-deployed global CDN delivering the dashboard interface seamlessly.

## Backend
- **Flask**: Python microframework allowing ultra-lightweight REST endpoints.
- **Flask-SQLAlchemy**: ORM for managing relational records with extreme portability.
- **Flask-Limiter**: Application-level connection rate limitation.
- **Gunicorn**: Production WSGI server (used securely in Render backend).

## Database
- **SQLite (Development)**: Generates locally automatically (`cloudshield.db`). Used for frictionless contributor testing without Docker.
- **PostgreSQL (Production)**: The enterprise unstructured storage backing Render for robust transaction history handling. Instantly switches when `DATABASE_URL` is detected.

## Security & Edges
- **HMAC + SHA256 Verification**: Edges cryptographically sign telemetry. Backend intercepts and cryptographically rejects malformed packets instantly.
- **Cloudflare WAF (SaaS Mode)**: The system hooks into Cloudflare's Edge API via Python backend to block offending attackers globally in <1 second upon 5 failed auth attempts.
