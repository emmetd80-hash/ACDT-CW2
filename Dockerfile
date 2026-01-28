FROM python:3.12-slim

WORKDIR /app

COPY main.py /app/main.py
COPY config.yml /app/config.yml

RUN pip install --no-cache-dir requests pyyaml matplotlib

# default input path inside the container
ENV INPUT_EMAIL_CSV=/data/email_list.csv

CMD ["python", "main.py"]