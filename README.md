# **ALC Breach Screener**
## **Problem / Purpose**

The ALC Breach Screener is a Python application that checks a list of email addresses against the IntelX (Intelligence X) API to determine if those emails appear in known breach or leaked files.
The tool is designed Antrim Logistics Company (ALC), that screens new and existing clients for potential exposure in known data breaches and to help inform mitigation actions.

## **What the Application Does**

Once provided a CSV file of email addresses, the application will:

1. Screen each email against the IntelX API

2. Check whether the email appears in breach records

3. Extract breach source domains and the files in which client credentials were found

4. Produce:

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

## **Example Results**

1. Results CSV
Example rows from output_result1.csv:

    | email_address     | breached | breached_sources    |
    | ----------------- | -------- | ------------------- |
    | user_001@redacted | True     | example.com;foo.com |
    | user_002@redacted | False    |                     |
    | user_003@redacted | True     | example.com         |

2. Analyst Summary CSV
Example contents of breach_summary.csv: 

    | metric          | value |
    | --------------- | ----- |
    | total_emails    | 3     |
    | breached_emails | 2     |
    | unique_sources  | 2     |

Top breached sources:
    | domain      | count |
    | ----------- | ----- |
    | example.com | 2     |
    | foo.com     | 1     |


3. Breach Source Chart
The application generates a bar chart (breach_summary.png) showing the most common breaches across the screened email CSV.

* The x-axis represents breach source files or domains

* The y-axis shows the number of affected email addresses

* The chart enables rapid identification of high-risk breach sources

## **Data Protection Notice**

All example outputs shown above use synthetic or redacted data.
No real client email addresses or personal identifiers are included in this documentation.

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

The application interacts with the IntelX API endpoint: 

    -https://free.intelx.io

IntelX registration is required for API key and can be found here after registration: https://intelx.io/account?tab=developer
Only users in possession of a valid IntelX API key can successfully run the application.

An IntelX API is required and must be provided via an environment variable:

    - $env:INTELX_API_KEY="API_KEY"

The application also uses environment variables for file path:

    - $env:INPUT_EMAIL_CSV="PATH TO email_list.csv"

## **Example input CSV format**

    - Header: email_address
    - row1: user1@example.com
    - row2: user2@example.com

## **Running the application locally**

After entering the required environment variables and changing to the projects directory:

    - python main.py

On completion, if successful the output CSV files and chart will be written to the projects location.

# **Docker Usage**

## **Building the Docker Image**

    - docker build -t breach-screener .

## **Run the Container**

    - docker run --rm `
    -e INTELX_API_KEY="18211fcd-cb24-4343-b2b0-a2d81868adfe" `
    -e INPUT_EMAIL_CSV="/data/email_list.csv" `
    -v "C:\Users\Emmet\OneDrive\Level 6\Cloud\ACDT CW2:/data" `
    breach-screener

This ensures all input files and generated outputs are accessible on the Host system

# **Testing**

Unit tests are written using Pytest and cover the following:

1. CSV input handling
2. Email validation
3. Correlation ID generation
4. Breach source extraction
5. IntelX polling behaviour
6. Retry and backoff logic
7. Error handling

Run tests locally with: 
    
    - python -m pytest -v .\tests\test_main.py

# **Continuous Integration (CI)**

The project includes a GitHub Actions CI pipeline (ci.yml) which runs on every push and pull requests
The Pipeline performs the following:

1. Dependency installation
2. Linting with Ruff
3. Formatting checks with Black
4. Execution of all unit tests using Pytest

A build will fails if any of the above steps fail.

# **Limitations**

1. Results depend on IntelX API availability and data quality
2. Free IntelX endpoints may return partial or delayed results
3. The tool does not verify password exposure

# **Ethics & GDPR Considerations**

Ethical and legal considerations to consider:

1. Screening only email addresses owned or authorised by ALC
2. Minimal personal data processing
3. No storage of unnecessary personal information
4. Compliance with GDPR principles of data minimisation and purpose limitation

This application is intended for educational and prototype purposes only.

# **Author**

Emmet Devine
Advanced Cloud Development Technologies
ACDT_CW_II_25-26