FROM python:3.12-slim

WORKDIR /app

# Copy application files
COPY main.py /app/main.py
COPY config.yml /app/config.yml

# Install required Python packages
RUN pip install --no-cache-dir requests pyyaml
RUN pip install --no-cache-dir requests pyyaml matplotlib

# Environment variable defaults (can be overridden at runtime)
ENV INPUT_EMAIL_CSV=/data/email_list.csv
ENV OUTPUT_CSV=/data/output_result1.csv

CMD ["python", "main.py"]
