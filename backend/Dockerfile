FROM python:3.11-slim-bookworm

# Install required system dependencies (git is needed for github clone, curl for uv)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies (but not the project itself)
RUN uv sync --frozen --no-install-project --no-dev

# Copy the rest of the application
COPY . .

# Install the project
RUN uv sync --frozen --no-dev

# Set production environment variables
ENV CODERISK_ENVIRONMENT=production
ENV CODERISK_DATABASE_AUTO_CREATE=false
ENV CODERISK_DATABASE_ECHO=false

EXPOSE 8000

CMD uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
