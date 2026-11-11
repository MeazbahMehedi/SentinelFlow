# Container image for PCAP replay and analysis. Live capture inside a container
# additionally needs host networking and the NET_RAW / NET_ADMIN capabilities.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    SENTINELFLOW_DATA=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinelflow ./sentinelflow
COPY samples ./samples
COPY run.py .

RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown sentinel /data
USER sentinel
VOLUME ["/data"]
EXPOSE 5000

CMD ["python", "run.py"]
