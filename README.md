# **ALC Breach Screener**
## **Problem / Purpose**

The ALC Breach Screener is a Python application that checks a list of email addresses against the IntelX (Intelligence X) API to determine if those emails appear in known breach or leaked files.
The tool is designed Antrim Logistics Company (ALC), that screens new and existing clients for potential exposure in known data breaches and to help inform mitigation actions.

## **What the Application Does**

Once provided a CSV file of email addresses, the application:

1. Screens each email against the IntelX API

2. Checks whether the email appears in breach records

3. Extracts breach source domains and the files in which client credentials were found

4. Produces:

    - A detailed results CSV
    - A concise analyst summary CSV
    - A bar chart (PNG) of top breach sources

## **Outputs**

When the program runs successfully, it generates the following files

1. Results CSV
File: "output_result1.csv"
Contains one row per email: "email_address", "breached" (True/False), "site_where_breached" (semicolon-separated)

2. Analyst Summary CSV
File: "breach_summary.csv"
Contains: Total emails processed, Number of breach sources, Number of unique breach sources and Top breach sources with counts

3. Chart Output
File: "breach_summary_png"
Contains A bar chart showing the most common breach sources.

## **Project Structure** 

Layout:
    
    - main.py (main application logic)
    - config.yml (Application configuration)
    - email_list.csv (Input file)
    - tests/ - (Unit tests "test_main.py")
    - Dockerfile - (Docker definition)
    - README.md (Documentation)

## **Requirements**

Python 3.12+
requests
pyyaml
matplotlib

**Development / Testing Requirements**

pytest
ruff
black

All dependencies are listed in `requirements-dev.txt`.

### **Install dependencies using pip**

pip install -r requirements-dev.txt

# **Configuration**
## **IntelX API Key and Environment variables**

An IntelX API is required and must be provided via an environment variable:

    - $env:INTELX_API_KEY="API_KEY"

The application also uses environment variables for file paths:

    - $env:INPUT_EMAIL_CSV="PATH TO email_list.csv"
    - $env:OUTPUT_CSV="PATH TO output_result1.csv"

## **Example input CSV format**

    - Header: email_address
    - row1: user1@example.com
    - row2: user2@example.com

## **Running the application locally**

After entering the required environment variables and changing to the projects directory:

    - python main.py
