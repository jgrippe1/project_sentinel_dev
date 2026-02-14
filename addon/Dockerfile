ARG BUILD_FROM
FROM $BUILD_FROM

# Install requirements for add-on
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy data for add-on
COPY run.sh ./
COPY sentinel ./sentinel

RUN chmod a+x run.sh

CMD [ "./run.sh" ]
