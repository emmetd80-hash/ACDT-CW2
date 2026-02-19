FROM python:3.12-slim

WORKDIR /app

COPY main.py /app/main.py
COPY config.yml /app/config.yml
COPY requirements-dev.txt /app/requirements-dev.txt

RUN pip install --no-cache-dir -r /app/requirements-dev.txt

ENV INPUT_EMAIL_CSV=/data/email_list.csv

CMD ["python", "main.py"]
