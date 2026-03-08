# **ALC Breach Screener**
## **Problem / Purpose**

The ALC Breach Screener is a Python application that checks a list of email addresses against the IntelX (Intelligence X) API to determine if those emails appear in known breach or leaked files.
The tool is designed for Antrim Logistics Company (ALC), that screens new and existing clients for potential exposure in known data breaches and to help inform mitigation actions.

## **What the Application Does**

Once provided a CSV file of email addresses, the application will:

1. Screen each email against the IntelX API concurrently using asynchronous requests

2. Check whether the email appears in breach records

3. Extract breach source domains and the files in which client credentials were found

4. Produce:

    - A detailed results CSV
    - A concise analyst summary CSV
    - A breach source chart (PNG) visualising the most common domains

## **Asynchronous Architecture**

The application uses Python’s asyncio framework and the httpx.AsyncClient library to perform non-blocking HTTP requests to the IntelX API.
This enables:

* Concurrent screening of multiple email addresses
* Improved runtime performance for large input datasets
* Controlled concurrency using rate limiting and retry/backoff logic

## **Outputs**

When the program runs successfully, it generates the following files

## 1. Results CSV File: "output/output_result1.csv"

Contains one row per email with the following columns:

- email_address  
- breached (True/False)  
- breach_media_summary (human-readable summary of file/media types returned by IntelX)  
- breached_sources (semicolon-separated list of extracted source domains)

## 2. Analyst Summary CSV File: "output/breach_summary.csv"

Contains screening metrics followed by a ranked table of breach sources.

- total_emails  
- breached_emails 
- unique_sources 
- breached_sources (semicolon-separated list of extracted source domains)
- top_breached_sources with count

## 3. Chart Output File: "output/breach_summary.png"

Visual representation of the most common breach sources identified during screening.

All generated files are written into an "output/" directory.
If the directory does not exist, the application will create it automatically.

## **Example Results**

1. Results CSV
Example rows from `output/output_result1.csv`:

    | email_address        | breached | breach_media_summary                              | breached_sources |
    |----------------------|----------|---------------------------------------------------|------------------|
    | user_001@redacted    | TRUE     | 32 Text Files, 5 CSV Files, 3 Database Files      | redacted-source1.txt;redacted-source2.txt;redacted-db.sql;redacted-leak.tar;example.com;foo.com;archive1.rar;dump1.tar |
    | user_002@redacted    | TRUE     | 8 Text Files, 6 CSV Files, 1 Database File        | fitness-app.com;verification-data.txt;redacted.tsv;cloud-storage.rar;example.net |
    | user_003@redacted    | TRUE     | 8 Text Files, 2 Database Files                    | dataset1.txt;archive-old.zip;leakfile.tar;example.org |
    | user_004@redacted    | TRUE     | 2 CSV Files                                       | music-platform.com |
    | user_005@redacted    | TRUE     | 38 Text Files, 2 CSV Files                        | dump1.rar;collection.tar;logs.txt;archive.zip;redacted-data.txt;example.com |

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

The application generates a donut-style chart (breach_summary.png) showing the distribution of the most common breach sources.

* Each segment represents a breach source file or domain  
* Segment size and percentage indicate its share of total breaches  
* The legend lists the top sources  
* The centre displays total emails processed, breached emails, and exposure rate  

This visual provides a quick summary of breach exposure and highlights dominant sources.

Example:

![alt text](breach_summary.png)

## **Data Protection Notice**

All example outputs shown above use synthetic or redacted data.
No real client email addresses or personal identifiers are included in this documentation.

## **Project Structure** 

- src/
    - __main__.py (entry point for module execution)
    - screener.py (core async screening workflow)
    - intelx_client.py (IntelX API communication client)
    - config.py (configuration models + loader)
    - utils.py (shared helpers, logging, CSV + chart output)
    - config.yml (Application configuration)
- email_list.csv (Input file)
- output/ (generated results folder – created automatically)
- tests/ (unit tests including async tests)
- Dockerfile (Docker definition)
- README.md (Documentation)

## **Requirements**

Python 3.12+
httpx
pyyaml
matplotlib

**Development / Testing Requirements**

pytest
pytest-asyncio
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

    - python -m src

The application internally runs an asynchronous event loop to process multiple email checks efficiently.
On completion, if successful all output CSV files and charts will be written to the automatically created "output/" folder inside the project directory.

# **Docker Usage**

## **Building the Docker Image**

    - docker build -t breach-screener .

## **Run the Container**

    - docker run --rm `
    -e INTELX_API_KEY="API_KEY" `
    -e INPUT_EMAIL_CSV="/data/email_list.csv" `
    -v "C:\Users\Emmet\OneDrive\Level 6\Cloud\ACDT CW2 Project:/data" `
    breach-screener

Generated files will appear in the mounted host folder under the "output/" directory.

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

Some tests use asynchronous execution and require pytest-asyncio (included in requirements-dev.txt).

# **Continuous Integration (CI)**

The project includes a GitHub Actions CI pipeline (ci.yml) which runs on every push and pull requests
The Pipeline performs the following:

1. Dependency installation
2. Linting with Ruff
3. Formatting checks with Black
4. Execution of all unit tests (including async tests) using Pytest

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