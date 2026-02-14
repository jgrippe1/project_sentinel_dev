ARG BUILD_FROM
FROM $BUILD_FROM

# Install requirements for add-on
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy data for add-on
COPY run.sh /
COPY sentinel /opt/sentinel/

WORKDIR /opt

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
