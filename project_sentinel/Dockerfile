ARG BUILD_FROM
FROM $BUILD_FROM

# Set shell
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install requirements for add-on
WORKDIR /app
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy data for add-on
COPY run.sh ./
COPY sentinel ./sentinel

RUN chmod a+x run.sh

# Entrypoint
CMD [ "./run.sh" ]
