import requests
from urllib.parse import urlparse, parse_qs
import pandas as pd
import tensorflow as tf
import numpy as np


model_path = 'sqlimodel.h5'

# Load the saved model
model = tf.keras.models.load_model(model_path)

sql_injection_keywords = [
    'select',
    'update',
    'insert',
    'create',
    'drop',
    'alter',
    'rename',
    'exec',
    'order',
    'group',
    'sleep',
    'count',
    'where'
]

punc_list = ['!', ",", "\'", ";", "\"", ".", "-", "?", "[", "]", ")", "("]

# SQL injection payloads for testing
sqli_payloads = [
    "' OR '1'='1",
    "1; DROP TABLE users;",
    "SELECT * FROM users WHERE username = 'admin' AND password = 'password';",
    # Add more payloads as needed
]

def remove_and_count_specific_punctuation(input_string, punctuations_to_remove):
    # Create a translation table to map each specified punctuation character to None
    translator = str.maketrans('', '', ''.join(punctuations_to_remove))

    # Use translate method to remove specified punctuations from the input string
    no_specified_punctuations = input_string.translate(translator)

    # Count the occurrences of each specified punctuation character
    specified_punctuation_counts = len(
        input_string)-len(no_specified_punctuations)

    return specified_punctuation_counts


def preprocess_input(user_input, keywords):
    # print(user_input)
    length = len(str(user_input))
    keyword_count = sum(user_input.lower().count(keyword.lower())
                        for keyword in keywords)
    punc_count = remove_and_count_specific_punctuation(user_input, punc_list)
    df = pd.DataFrame({'Length': [length], 'punctuation': [
                      punc_count], 'keyword': [keyword_count]}, index=None)
    return df


def detect_sql_injection_with_model(form_input):
    df = preprocess_input(form_input, sql_injection_keywords)

    df = np.array(df).reshape(len(df), 1, 3)
    tensor_df = tf.data.Dataset.from_tensor_slices(df).batch(64)

    output = model.predict(tensor_df)
    value = output[0, 0]
    if value > 0.5:
        return True
    else:
        return False


def extract_search_query(url):
    # Parse the URL
    parsed_url = urlparse(url)
    # print(parsed_url)
    # Extract query parameters
    query_params = parse_qs(parsed_url.query)
    # print(query_params)
    # Get the value of the 'q' parameter
    search_query = query_params.get('search', [None])[0]

    # print(search_query)
    return search_query

def test_sqli_payload(url, payload):

    # Test each SQL injection payload
    
    # Specify the target URL
    base_url = url.split('?')[0]  

    injected_url = f"{base_url}?search={payload}"
 
    search_query = extract_search_query(injected_url)
    # print(search_query)
        # print(search_query)
        # Check if the search query indicates SQL injection
    if detect_sql_injection_with_model(search_query):
        return search_query
    # else:
    #         print(f"No SQL Injection detected with payload: {payload}")
    # else:
    #     print(f"Request failed with status code: {response.status_code}")


def test_sqli(target_url):
    results = []
    for payload in sqli_payloads:
        result =test_sqli_payload(target_url, payload)
        results.append(result)
    return results










