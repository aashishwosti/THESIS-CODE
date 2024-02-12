import requests
from bs4 import BeautifulSoup

def extract_elements_from_response(response):
    try:
        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(response, 'html.parser')

        # Find all HTML elements on the webpage
        elements = soup.find_all()

        # Convert HTML elements to a list of strings
        string_list = [str(element) for element in elements]

        return string_list

    except requests.RequestException as e:
        print(f"Error: {e}")
        return []