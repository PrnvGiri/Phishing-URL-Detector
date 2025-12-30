from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from feature_extractor import FeatureExtractor
import os
import tensorflow as tf
# Optimize TensorFlow for Low RAM (CPU only)
try:
    tf.config.set_visible_devices([], 'GPU')
except:
    pass

from tensorflow.keras.models import load_model
import whois
from urllib.parse import urlparse
import dns.resolver
import requests
from bs4 import BeautifulSoup
import difflib
from whitelist import TOP_DOMAINS, SENSITIVE_ROOTS

app = Flask(__name__)

# --- CONFIG ---
# Load model and scaler
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')

# --- CONFIG ---
# Load model and scaler
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model.h5')
SCALER_PATH = os.path.join(BASE_DIR, 'scaler.pkl')

model = None
scaler = None

def get_model_and_scaler():
    global model, scaler
    if model is None or scaler is None:
        print(" [INFO] Lazy loading model & scaler...")
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                model = load_model(MODEL_PATH)
                scaler = joblib.load(SCALER_PATH)
                print(" [SUCCESS] Resources loaded.")
            else:
                print(f" [ERROR] Files missing at {BASE_DIR}")
        except Exception as e:
            print(f" [CRITICAL] Load failed: {e}")
    return model, scaler

# --- HELPER FUNCTIONS ---

def get_dns_info(domain):
    records = {"A": [], "MX": [], "NS": [], "TXT": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2 # Short timeout
        resolver.timeout = 2
        
        for rtype in records.keys():
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
    except Exception as e:
        print(f"DNS Error for {domain}: {e}")
    return records

def scrape_site_data(url):
    data = { "title": "N/A", "description": "N/A", "has_login_form": False, "server_header": "Unknown" }
    try:
        # Strict timeout to prevent hanging
        response = requests.get(url, timeout=2.5, headers={"User-Agent": "PhishNetra/1.0"})
        data["server_header"] = response.headers.get("Server", "Unknown")
        
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.title: data["title"] = soup.title.string.strip()[:50] # Truncate
        
        meta = soup.find('meta', attrs={'name': 'description'})
        if meta: data["description"] = meta.get('content', '').strip()[:100]
            
        if soup.find('input', {'type': 'password'}): data["has_login_form"] = True
    except:
        pass
    return data

def get_domain_info(url):
    try:
        domain = urlparse(url).netloc
        if not domain: domain = urlparse(url).path.split('/')[0]
        
        # PyWhois can be slow
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        
        return {
            "registrar": str(w.registrar)[:30] or "Unknown",
            "org": str(w.org)[:30] or "Hidden",
            "country": str(w.country) or "Unknown",
            "creation_date": str(creation) if creation else "Unknown"
        }
    except:
        return {"registrar": "Failed", "org": "N/A", "country": "N/A", "creation_date": "N/A"}

# --- ROUTES ---

def perform_deep_analysis(url, current_prob=0.0):
    domain_info = {}
    dns_info = {}
    site_data = {}
    reasons = [] # Extra reasons found during deep scan
    final_prob = current_prob

    try:
        domain_info = get_domain_info(url)
    except Exception as e:
        print(f" [WARN] Whois failed: {e}")

    try:
        domain = urlparse(url).netloc
        dns_info = get_dns_info(domain)
    except Exception as e:
        print(f" [WARN] DNS failed: {e}")

    try:
        site_data = scrape_site_data(url)
        # If not already confident phishing, check login form
        # We only penalize if prob is already suspicious (>0.4) to avoid FPs on legit login pages
        if site_data.get('has_login_form') and final_prob > 0.4:
            final_prob = max(final_prob, 0.85)
            reasons.append("Login form detected on suspicious site")
    except Exception as e:
        print(f" [WARN] Scraping failed: {e}")
        
    return domain_info, dns_info, site_data, final_prob, reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({"status": "online", "message": "Service is running. Model loads on first request."}), 200

@app.route('/predict', methods=['POST'])
def predict():
    print(" [INFO] Received prediction request")
    
    # Lazy Load
    model, scaler = get_model_and_scaler()
    
    if not model or not scaler:
        print(" [ERROR] Model not loaded")
        return jsonify({'error': 'Model failed to initialize. Check server logs.'}), 500

    try:
        req_data = request.get_json(force=True, silent=True)
        if not req_data: return jsonify({'error': 'Invalid JSON'}), 400
        
        url = req_data.get('url')
        if not url: return jsonify({'error': 'No URL provided'}), 400
        
        if not url.startswith(('http://', 'https://')): url = 'http://' + url
        print(f" [INFO] Analyzing: {url}")
        
        # --- FEATURE EXTRACTION (Need this for chart even for whitelist) ---
        extractor = FeatureExtractor()
        features = extractor.extract_features(url)
        
        # --- PHASE 0: ENTERPRISE VERIFICATION (Whitelist & Typosquatting) ---
        domain = urlparse(url).netloc.lower()
        if domain.startswith('www.'): domain = domain[4:]
        
        # 1. Whitelist Check (Instant Safe but with details)
        if domain in TOP_DOMAINS:
            print(f" [INFO] Whitelisted Domain: {domain}")
            
            # Perform deep analysis for UI population, but ignore the probability result
            d_info, dns_info, s_data, _, _ = perform_deep_analysis(url, 0.0)
            
            return jsonify({
                'url': url, 'result': 'Legitimate', 'probability': 0.01,
                'features': features, 
                'reasons': ["Verified Safe Domain (Whitelist)"],
                'domain_info': d_info, 'dns_info': dns_info, 'site_data': s_data
            })
            
        # 2. Typosquatting Check (Fuzzy match against whitelist)
        typo_reasons = []
        is_typosquat = False
        
        if domain not in SENSITIVE_ROOTS:
            for safe_domain in TOP_DOMAINS:
                ratio = difflib.SequenceMatcher(None, domain, safe_domain).ratio()
                if 0.80 < ratio < 1.0:
                    if not domain.endswith("." + safe_domain):
                        is_typosquat = True
                        typo_reasons.append(f"Impersonation attempt of {safe_domain} ({int(ratio*100)}% match)")
                        break
        
        if is_typosquat:
             print(f" [INFO] Typosquatting Detected: {domain}")
             return jsonify({
                'url': url, 'result': 'Phishing', 'probability': 0.99,
                'features': features, 'reasons': typo_reasons + ["Detected via Typosquatting Engine"],
                'domain_info': {}, 'dns_info': {}, 'site_data': {}
            })

        # --- PHASE 1: AI & HEURISTICS ---
        
        # 2. Prediction (Fast)
        feature_names = extractor.get_feature_names()
        df = pd.DataFrame([features], columns=feature_names)
        df_scaled = scaler.transform(df)
        model_prob = float(model.predict(df_scaled)[0][0])
        print(f" [INFO] Neural Prob: {model_prob}")

        # 3. Heuristics (Instant)
        final_prob = model_prob
        reasons = []
        
        susp = features.get('SuspiciousKeywords', 0)
        if susp > 0:
            final_prob = max(final_prob, min(0.99, 0.85 + (0.05 * (susp-1)))); reasons.append(f"Detected {susp} suspicious keywords")
        if features.get('IsDomainIP', 0) == 1:
            final_prob = max(final_prob, 0.95); reasons.append("IP Address detected")
        if features.get('IsShortened', 0) == 1:
            final_prob = max(final_prob, 0.75); reasons.append("URL Shortener detected")
        if features.get('Entropy', 0) > 4.5:
            final_prob = max(final_prob, 0.70); reasons.append("High Entropy (Randomness)")

        # 4. Deep Analysis (Slow - Potentially Failures)
        domain_info, dns_info, site_data, final_prob, deep_reasons = perform_deep_analysis(url, final_prob)
        reasons.extend(deep_reasons)
        is_phishing = final_prob > 0.5
        result = "Phishing" if is_phishing else "Legitimate"
        confidence = final_prob if is_phishing else (1 - final_prob)
        
        print(" [INFO] Analysis Complete. Returning response.")
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
        print(f" [CRITICAL] Prediction loop error: {e}")
        return jsonify({'error': 'Internal Analysis Error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
