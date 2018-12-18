FROM microsoft/azure-functions-python3.6:v2.0.11961-alpha

COPY . /home/site/wwwroot

RUN cd /home/site/wwwroot && \
    pip install -r requirements.txt