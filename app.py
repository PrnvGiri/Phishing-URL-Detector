from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from feature_extractor import FeatureExtractor
import os
import tensorflow as tf
from tensorflow.keras.models import load_model
import whois
from urllib.parse import urlparse
import dns.resolver
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Load model and scaler
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')

print(f"Loading model from {MODEL_PATH}...")
try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("Model and Scaler loaded successfully.")
    else:
        print("Model or Scaler file not found.")
        model = None
        scaler = None
except Exception as e:
    print(f"Error loading resources: {e}")
    model = None
    scaler = None

# --- Helper Functions ---

def get_dns_info(domain):
    records = {"A": [], "MX": [], "NS": [], "TXT": []}
    try:
        for rtype in records.keys():
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
    except Exception as e:
        print(f"DNS Error: {e}")
    return records

def scrape_site_data(url):
    data = {
        "title": "N/A",
        "description": "N/A",
        "has_login_form": False, 
        "server_header": "Unknown"
    }
    try:
        # Timeout is crucial for safety
        response = requests.get(url, timeout=3, headers={"User-Agent": "PhishNetra-Scanner/1.0"})
        data["server_header"] = response.headers.get("Server", "Unknown")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        if soup.title:
            data["title"] = soup.title.string.strip()
            
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            data["description"] = meta_desc.get('content', '').strip()
            
        # Check for password inputs
        if soup.find('input', {'type': 'password'}):
            data["has_login_form"] = True
            
    except Exception:
        # Fallback if scraping fails (common for phishing sites that are down or blocking bots)
        pass
    return data

def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = urlparse(url).path.split('/')[0]
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        return {
            "registrar": w.registrar or "Unknown",
            "org": w.org or "Hidden",
            "country": w.country or "Unknown",
            "creation_date": str(creation) if creation else "Unknown"
        }
    except:
        return {"registrar": "Failed", "org": "N/A", "country": "N/A", "creation_date": "N/A"}

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model or not scaler:
        return jsonify({'error': 'Model not loaded'}), 500

    data = request.json
    url = data.get('url')
    if not url: return jsonify({'error': 'No URL provided'}), 400

    if not url.startswith(('http://', 'https://')): url = 'http://' + url

    try:
        # 1. Feature Extraction & Prediction
        extractor = FeatureExtractor()
        features = extractor.extract_features(url)
        feature_names = extractor.get_feature_names()
        df = pd.DataFrame([features], columns=feature_names)
        df_scaled = scaler.transform(df)
        model_prob = float(model.predict(df_scaled)[0][0])
        
        # 2. Heuristic Logic
        final_prob = model_prob
        reasons = []
        override = False
        
        # Keywords
        susp = features.get('SuspiciousKeywords', 0)
        if susp > 0:
            override = True
            final_prob = max(final_prob, min(0.99, 0.85 + (0.05 * (susp-1))))
            reasons.append(f"Detected {susp} suspicious keywords")
            
        # IP / Shortener / Entropy
        if features.get('IsDomainIP', 0) == 1:
            override = True; final_prob = max(final_prob, 0.95); reasons.append("IP Address detected")
        if features.get('IsShortened', 0) == 1:
            override = True; final_prob = max(final_prob, 0.75); reasons.append("URL Shortener detected")
        if features.get('Entropy', 0) > 4.5:
            override = True; final_prob = max(final_prob, 0.70); reasons.append("High Entropy (Randomness)")

        # 3. Deep Analysis (DNS, Whois, Scraping)
        domain = urlparse(url).netloc
        
        # Domain Info (Whois)
        domain_info = get_domain_info(url)
        
        # DNS Records
        dns_info = get_dns_info(domain)
        
        # Scraping (Content Analysis)
        site_data = scrape_site_data(url)
        
        # Check for phishing via scraping
        if site_data['has_login_form'] and final_prob > 0.4:
            # If it looks vaguely phishy AND has a password field, boost risk
            final_prob = max(final_prob, 0.85)
            reasons.append("Login form detected on suspicious site")

        is_phishing = final_prob > 0.5
        result = "Phishing" if is_phishing else "Legitimate"
        confidence = final_prob if is_phishing else (1 - final_prob)

        return jsonify({
            'url': url,
            'result': result,
            'probability': confidence,
            'features': features,
            'reasons': reasons,
            'domain_info': domain_info,
            'dns_info': dns_info,
            'site_data': site_data
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
