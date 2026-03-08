FROM python:3.12-slim

WORKDIR /app

# Copy project files
COPY src /app/src
COPY requirements-dev.txt /app/requirements-dev.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements-dev.txt

# Default CSV location inside container
ENV INPUT_EMAIL_CSV=/data/email_list.csv

# Ensure output folder exists
RUN mkdir -p /app/output

# Run package entrypoint
CMD ["python", "-m", "src"]