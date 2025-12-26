# PhishNetra - Advanced AI Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Backend-black?style=for-the-badge&logo=flask&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-Deep%20Learning-orange?style=for-the-badge&logo=tensorflow&logoColor=white)
![Status](https://img.shields.io/badge/Status-Live-success?style=for-the-badge)

**PhishNetra** is a next-generation threat intelligence system designed to detect sophisticated phishing attacks. It combines a **Deep Neural Network** (TensorFlow/Keras) with **Expert Heuristics** and **Deep Reconnaissance** tools to provide a comprehensive security verdict for any URL.

### 🚀 [**Try it Live Here**](https://phishnetra-app.onrender.com/)

---

## 🌟 Key Features

### 🧠 Hybrid Detection Engine
- **Neural Network Core**: A dense feed-forward network trained on **230,000+ URLs**.
- **Lexical Analysis**: Extracts 19+ structural features (Entropy, Length, Special Chars) to identify anomalies.
- **Heuristic Override**: Implements a zero-tolerance policy for high-severity threats (e.g., suspicious keywords, IP hostnames).

### 🕵️ Deep Reconnaissance
- **Domain Intelligence**: Automated Whois lookup (Registrar, Organization, Country, Domain Age).
- **DNS Enumeration**: Resolves A, MX, and NS records to verify infrastructure legitimacy.
- **Safe Scraping**: Analyzes page content (headers, page titles, login forms) without executing malicious scripts.

### 🎨 Flowa UI
- **Premium Aesthetic**: Features Glassmorphism, floating background elements, and smooth animations.
- **Visual Analytics**: Includes interactive **Radar Charts** to visualize risk vectors at a glance.
- **Mobile Responsive**: Fully optimized for desktop, tablet, and mobile devices.

---

## 🛠️ Installation & Run Locally

Follow these steps to set up PhishNetra on your local machine.

### 1. Clone the Repository

    git clone https://github.com/yourusername/PhishNetra.git
    cd PhishNetra

### 2. Install Dependencies
Ensure you have Python installed, then run:

    pip install -r requirements.txt

### 3. Run the Application
Start the Flask server:

    python app.py

### 4. Access the Dashboard
Open your browser and navigate to:

    http://localhost:5000

---

## 📦 Project Structure

    PhishNetra/
    ├── dataset/                  # Training data (PhiUSIIL)
    ├── static/
    │   ├── style.css             # Flowa UI Styling
    │   └── script.js             # Frontend Logic (Charts, API)
    ├── templates/
    │   └── index.html            # Main Dashboard
    ├── app.py                    # Flask Backend & API Routes
    ├── feature_extractor.py      # Feature Engineering Logic
    ├── train_model.py            # Neural Network Training Script
    ├── model.h5                  # Trained Keras Model
    ├── scaler.pkl                # Feature Scaler
    ├── requirements.txt          # Dependencies
    └── Procfile                  # Deployment Configuration

---

## 🛡️ Technologies Used

| Category | Technologies |
| :--- | :--- |
| **Backend** | Flask, Python 3.x |
| **AI / ML** | TensorFlow, Keras, Scikit-learn, Pandas, NumPy |
| **Reconnaissance** | Dnspython, Python-whois, BeautifulSoup |
| **Frontend** | HTML5, CSS3 (Glassmorphism), JavaScript, Chart.js, Lucide Icons |

---

## ⚠️ Disclaimer

> This tool is developed for **educational and defensive security purposes only**. 
> Please do not use it to analyze URLs you do not have permission to scan if local laws prohibit it. The developers are not responsible for any misuse of this tool.

---

<p align="center">
  <strong>Powered by PhishNetra AI</strong>
</p>
