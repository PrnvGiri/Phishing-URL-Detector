import socket
import whois
from urllib.parse import urlparse
from flask import Flask, request, render_template
from API import get_prediction  # Import your get_prediction function

app = Flask(__name__)

@app.route('/static/logo.png')
def serve_logo():
    return app.send_static_file('logo.png')

@app.route('/static/fake.png')
def serve_fake():
    return app.send_static_file('fake.png')

@app.route('/')
def index():
    return render_template('index.html')

def get_ip_address(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        else:
            return "Invalid URL"
    except socket.gaierror:
        return "Unable to resolve the IP address"

def get_creation_date(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            domain_info = whois.whois(hostname)
            if domain_info.creation_date is None:
                return "Creation date information not found"
            elif isinstance(domain_info.creation_date, list):
                return domain_info.creation_date[0].strftime('%Y-%m-%d %H:%M:%S')
            else:
                return domain_info.creation_date.strftime('%Y-%m-%d %H:%M:%S')
        else:
            return "Invalid URL"
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/verify', methods=['POST'])
def verify_url():
    # Get the URL from the form
    url = request.form.get('phishing_url')

    # Path to your trained model
    model_path = r"D:\Hackathon\PhishHunt-1.01v\Malicious_URL_Prediction.h5"

    # Get the prediction
    prediction = get_prediction(url, model_path)

    # Get IP address and creation date
    ip_address = get_ip_address(url)
    creation_date = get_creation_date(url)

    return render_template("result.html", url=url, ip_address=ip_address, creation_date=creation_date, result=prediction)

if __name__ == '__main__':
    app.run(debug=True)
