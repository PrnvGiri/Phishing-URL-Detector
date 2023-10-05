import socket
from urllib.parse import urlparse
import whois

def get_ip_address(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def get_creation_date(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            return creation_date[0]
        else:
            return creation_date
    except whois.parser.PywhoisError:
        return None

if __name__ == "__main__":
    url = input("Enter the URL to retrieve information: ")

    ip_address = get_ip_address(url)
    creation_date = get_creation_date(url)

    if ip_address:
        print(f"IP Address: {ip_address}")
    else:
        print("Unable to retrieve IP address for the given URL.")

    if creation_date:
        print(f"Creation Date: {creation_date}")
    else:
        print("Unable to retrieve creation date for the given URL.")
