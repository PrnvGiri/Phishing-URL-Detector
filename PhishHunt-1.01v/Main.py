from API import get_prediction
import requests
import socket
import whois

# path to trained model
model_path = r"D:\TechTitan\PhishHunt-1.01v\Malicious_URL_Prediction.h5"

# input url
url ='https://www.facebook.com/'

# returns probability of url being malicious
prediction = get_prediction(url,model_path)
print(prediction)

# Get website content
response = requests.get(url)

# Extract domain name from the URL
domain_name = url.split('//')[-1].split('/')[0]

# Get creation date of the website using whois
try:
    domain_info = whois.whois(domain_name)
    creation_date = domain_info.creation_date
except Exception as e:
    creation_date = "Not available"

# Print the extracted details
print(f"Domain Name: {domain_name}")
print(f"Creation Date: {creation_date}")
