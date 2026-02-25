# ---------------------------------------------------------------------------
# Stage 1: dependency builder
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder

WORKDIR /app

# Install dependencies into a local prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Stage 2: runtime image
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS runtime

# Non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY org/       ./org/
COPY data/      ./data/

# Switch to non-root
USER appuser

EXPOSE 8080

# Tini-less, single-process entrypoint.
# --no-access-log keeps stdout clean; structured access logs can be added via middleware.
CMD ["uvicorn", "org.xyz.backslash.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]