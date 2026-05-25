FROM python:3.12-slim

RUN python -m pip install --no-cache-dir aioquic
WORKDIR /work
ENTRYPOINT ["python"]
