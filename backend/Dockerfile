# syntax=docker/dockerfile:1
FROM python:3.12-slim

# nmap ships the vulners.nse script; libcap2-bin provides setcap.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# The vulners.nse bundled with Debian's nmap is 1.x, which ignores API keys.
# Install the 2.x script from a pinned commit; the checksum guards against tampering.
ARG VULNERS_NSE_COMMIT=47c73ec5addcaad04904f233c6f85dfe76c58ed5
ADD --chmod=644 \
    --checksum=sha256:96ab184c1c2da56a184f2a6e156614c9daf9e7d35142ee6c210bd54a1b312cd4 \
    https://raw.githubusercontent.com/vulnersCom/nmap-vulners/${VULNERS_NSE_COMMIT}/vulners.nse \
    /usr/share/nmap/scripts/vulners.nse
RUN nmap --script-updatedb

# Least privilege: run as an unprivileged user, and give ONLY the nmap binary the
# raw-socket capability it needs for SYN/UDP/OS scans (instead of running as root).
RUN setcap cap_net_raw+eip "$(readlink -f /usr/bin/nmap)" \
    && useradd --create-home --uid 10001 najdrecon

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Make the code readable by the non-root user whatever the host's file permissions are
# (e.g. a umask of 077, or files created by tools that default to owner-only).
RUN chmod -R a+rX /app/app
RUN mkdir -p /app/data && chown najdrecon:najdrecon /app/data

USER najdrecon
ENV NMAP_PRIVILEGED=true \
    DATABASE_PATH=/app/data/scansight.db \
    PYTHONUNBUFFERED=1

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
