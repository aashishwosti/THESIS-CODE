from flask import Flask, render_template, request
from sqli_scan import test_sqli
from detectxss import detect_xss_in_form
from dtscan import detect_directory_traversal
app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    scan_type = request.form['scan_type']
    # print(scan_type)
    if scan_type == 'FullScan':
        results = perform_full_scan(url)
        return render_template('xssresult.html', url=url, scan_type=scan_type, results=results)
    else:
        results = perform_individual_scan(url, scan_type)
        # print(results)
        return render_template('result.html', url=url, scan_type=scan_type, results=results)


def perform_individual_scan(url, scan_type):
    # Implement logic to perform individual scans and return results
    # Use your XSS, SQLi, Directory Traversal models for scanning

    # results = f"Results for {scan_type} scan on {url}"

    # Example:
    if scan_type == 'SQLi':
        result_message = test_sqli(url)
        return result_message
        # print(result_message)
        # return render_template('xssresult.html', result_message=result_message)
    elif scan_type == 'XSS':
        result_message = detect_xss_in_form(url)
        return result_message
        # return render_template('xssresult.html', result_message=results)

    


def perform_full_scan(url):
    # Call individual scan functions and aggregate results for Full Scan
    xss_results = perform_individual_scan(url, 'XSS')
    sqli_results = perform_individual_scan(url, 'SQLi')

    full_scan_results = f"Results for Full Scan on {url}\n\n" \
                        f"XSS Scan Results:\n{xss_results}\n\n" \
                        f"SQLi Scan Results:\n{sqli_results}\n\n" \


    return full_scan_results

if __name__ == '__main__':
    app.run(debug=True)
