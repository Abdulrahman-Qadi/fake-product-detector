import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from whois import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
from requests.exceptions import SSLError
from urllib.parse import urlparse, urlunparse
from spellchecker import SpellChecker
import datetime
import re


def check_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Check for non-standard top-level domains
    standard_tlds = ['.com', '.net', '.org', '.gov', '.edu', '.co.uk']
    if not any(domain.endswith(tld) for tld in standard_tlds):
        return True

    # Check for excessive hyphens
    if domain.count('-') > 2:  # Change this threshold as needed
        return True

    # Check for common brand misspellings
    common_brands = ['apple', 'microsoft', 'google', 'amazon', 'facebook', 'meta', 'ebay']  # Add more brands as needed
    for brand in common_brands:
        if brand in domain:
            # Check for misspellings by replacing each character in the brand name and seeing if the result is in the domain
            for i in range(len(brand)):
                for char in 'abcdefghijklmnopqrstuvwxyz':
                    misspelling = brand[:i] + char + brand[i + 1:]
                    if misspelling in domain and misspelling != brand:
                        return True

    return False

def check_ssl_certificate(url):
    # Parse the URL and replace the scheme with HTTPS
    parsed_url = urlparse(url)
    https_url = parsed_url._replace(scheme="https")

    # Convert the parsed URL back to a string
    https_url = urlunparse(https_url)

    try:
        response = requests.get(https_url, timeout=5)
        return False  # SSL exists
    except SSLError:
        return True  # SSL error
    except:
        return False  # Any other error

def check_domain_age(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_info = whois(domain)
    creation_date = domain_info.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    domain_age = (datetime.datetime.now() - creation_date).days
    if domain_age < 365:  # less than 1 year
        return True
    return False

def check_website_content(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Remove HTML tags, JavaScript, CSS, and special characters
    for script in soup(["script", "style"]):
        script.decompose()

    text = soup.get_text()
    words = re.findall(r'\b[a-z]+\b', text.lower())
    spell = SpellChecker()
    misspelled = spell.unknown(words)
    
    if len(misspelled) > len(words) * 0.01:  # if more than 1% of words are misspelled
        return True
    return False

@csrf_exempt
def check_product(request):
    if request.method == 'POST':
        url = request.POST.get('url', '')

        checks = [check_ssl_certificate, check_domain, check_domain_age, check_website_content]
        check_names = ["Non-SSL Certificate", "Suspicious Domain", "Domain Age Less Than a Year", "Website Content Contains Misspelled Words"]

        # Create a dictionary where the keys are the names of the checks and the values are the results
        check_results = {name: check(url) for name, check in zip(check_names, checks)}

        # Calculate the 'fakeness' score as the proportion of checks that were failed
        fakeness = sum(check_results.values()) / len(checks) * 100

        # Include the names of the failed checks in the response
        failed_checks = [name for name, passed in check_results.items() if passed]

        return JsonResponse({'result': fakeness, 'points': failed_checks})
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


def my_view(request):
    return render(request, 'fake_product.html')
