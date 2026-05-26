FROM python:3.12-slim

RUN python -m pip install --no-cache-dir aioquic
WORKDIR /work
COPY scripts/interop/http3-external/docker/aioquic_http3_client.py /usr/local/bin/aioquic-http3-client
RUN chmod +x /usr/local/bin/aioquic-http3-client
ENTRYPOINT ["python"]
