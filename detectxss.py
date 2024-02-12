import requests

from bs4 import BeautifulSoup

import pickle

from html import unescape

from modeldesign import getVec

from htmlelements import extract_elements_from_response

trained_model = pickle.load(open('MLPClassifier.sav', 'rb'))

payload_file_path = 'short-list.txt'
# Assuming you have a trained XSS detection model

def detect_xss(input_string):

    result = trained_model.predict(input_string)

    return result


def read_payloads_from_file(file_path):

    with open(file_path, 'r', encoding='utf-8') as file:

        payloads = [line.strip() for line in file]

    return payloads


def find_forms(url):

    try:

        # Send a GET request to the specified URL

        response = requests.get(url)

        # Parse HTML content using BeautifulSoup

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the webpage

        forms = soup.find_all('form')

        # print(forms)

        return forms

    except requests.RequestException as e:

        print(f"Error: {e}")

        return []


def submit_form(url, form, method, payload):

    try:

        # Extract form details

        form_data = {}

        for input_tag in form.find_all('input'):

            input_name = input_tag.get('name')

            if input_name:

                form_data[input_name] = payload

        # Submit the form with the XSS payload

        if method == 'get':

            response = requests.get(url, params=form_data)

        elif method == 'post':

            response = requests.post(url, data=form_data)

        else:

            print("Unsupported form submission method")

            return None

        return response.text

    except requests.RequestException as e:

        print(f"Error: {e}")

        return None


def exploit_xss(url, form, payload):

    try:

        # Extract form details

        form_method = form.get('method', 'get').lower()

        # Try submitting the form using GET

        response = submit_form(url, form, form_method, payload)

        response_elements = extract_elements_from_response(unescape(response))

        vec = getVec(response_elements)

        result = detect_xss(vec) if vec else None

        # response_post = submit_form(url, form, 'post', payload)

        # vec_post = getVec(unescape(response_post)) if response_post else None

        # result_post = detect_xss(vec_post) if vec_post else None

        return result

    except requests.RequestException as e:

        print(f"Error: {e}")

        return None, None


def detect_xss_in_form(url):

    
    payloads = read_payloads_from_file(payload_file_path)

    forms = find_forms(url)

    if not forms:

        print("No forms found on the website.")

    else:

        print(f"Found {len(forms)} form(s) on the website.")

        for i, form in enumerate(forms, start=1):
            results =[]

            print(f"\nForm {i}:")

            for payload in payloads:

                # print(f"Trying payload: {payload}")

                result_get = exploit_xss(url, form, payload)

                if result_get.any():
                    
                    results.append(payload)
                    # print(results)

                # elif result_post.any():

                #     print(f"XSS vulnerability detected with payload: {payload} (Method: POST)")"

    return results

    
