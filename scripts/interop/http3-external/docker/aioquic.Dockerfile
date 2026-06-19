FROM python:3.12-slim

ARG AIOQUIC_VERSION=1.3.0
RUN python -m pip install --no-cache-dir "aioquic==${AIOQUIC_VERSION}"
WORKDIR /work
COPY scripts/interop/http3-external/docker/aioquic_http3_client.py /usr/local/bin/aioquic-http3-client
COPY scripts/interop/http3-external/docker/aioquic_http3_server.py /usr/local/bin/aioquic-http3-server
RUN chmod +x /usr/local/bin/aioquic-http3-client /usr/local/bin/aioquic-http3-server
ENTRYPOINT ["python"]
