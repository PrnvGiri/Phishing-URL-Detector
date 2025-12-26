# PhishNetra - Advanced AI Phishing URL Detector

![PhishNetra Banner](https://via.placeholder.com/1000x300/090c14/6366f1?text=PhishNetra+AI+Threat+Intelligence)

**PhishNetra** is a next-generation threat intelligence system designed to detect sophisticated phishing attacks. It combines a **Deep Neural Network** (TensorFlow/Keras) with **Expert Heuristics** and **Deep Reconnaissance** tools to provide a comprehensive security verdict for any URL.

## 🌟 Key Features

### 🧠 Hybrid Detection Engine
- **Neural Network Core**: A dense feed-forward network trained on 230,000+ URLs.
- **Lexical Analysis**: Extracts 19+ structural features (Entropy, Length, Special Chars).
- **Heuristic Override**: Zero-tolerance policy for high-severity threats (e.g., suspicious keywords, IP hostnames).

### 🕵️ Deep Reconnaissance
- **Domain Intelligence**: Automated `Whois` lookup (Registrar, Org, Country, Age).
- **DNS Enumeration**: Resolves `A`, `MX`, `NS` records to verify infrastructure.
- **Safe Scraping**: Analyzes page content (headers, title, login forms) without executing malicious scripts.

### 🎨 Flowa UI
- **Premium Aesthetic**: Glassmorphism, floating background elements, and smooth animations.
- **Visual Analytics**: Interactive **Radar Charts** to visualize risk vectors.
- **Mobile Responsive**: Fully optimized for all devices.

---

## 🛠️ Installation & Run Locally

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/PhishNetra.git
    cd PhishNetra
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python app.py
    ```

4.  **Access the Dashboard**
    Open `http://localhost:5000` in your browser.

---

## 📦 Project Structure

```
PhishNetra/
├── dataset/                  # Training data (PhiUSIIL)
├── static/
│   ├── style.css            # Flowa UI Styling
│   └── script.js            # Frontend Logic (Charts, API)
├── templates/
│   └── index.html           # Main Dashboard
├── app.py                   # Flask Backend & API Routes
├── feature_extractor.py     # Feature Engineering Logic
├── train_model.py           # Neural Network Training Script
├── model.h5                 # Trained Keras Model
├── scaler.pkl               # Feature Scaler
├── requirements.txt         # Dependencies
└── Procfile                 # Deployment Configuration
```

---

## 🛡️ Technologies Used

-   **Backend**: Flask, Python
-   **AI/ML**: TensorFlow, Keras, Scikit-learn, Pandas
-   **Recon**: Dnspython, Python-whois, BeautifulSoup
-   **Frontend**: HTML5, CSS3, JavaScript, Chart.js, Lucide Icons

---

## ⚠️ Disclaimer
This tool is for educational and defensive security purposes only. Do not use it to analyze URLs you do not have permission to scan if local laws prohibit it.

---

**Powered by PhishNetra AI**
