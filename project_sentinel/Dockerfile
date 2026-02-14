ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM $BUILD_FROM

# Set shell
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install requirements for add-on
RUN apk add --no-cache \
    python3 \
    py3-pip

WORKDIR /app
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy data for add-on
COPY run.sh ./
COPY sentinel ./sentinel

RUN chmod a+x run.sh

# Entrypoint
CMD [ "./run.sh" ]
