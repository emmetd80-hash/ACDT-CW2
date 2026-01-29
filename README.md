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

