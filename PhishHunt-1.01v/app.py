from flask import Flask, render_template, request, jsonify
from API import get_prediction

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

@app.route('/verify', methods=['POST'])
def verify_url():
    # Get the URL from the form
    url = request.form.get('phishing_url')

    # Path to your trained model
    model_path = r"D:\PhishHunt-1.02v_\PhishHunt-1.01v\Malicious_URL_Prediction.h5"

    # Get the prediction
    prediction = get_prediction(url, model_path)

    return render_template('result.html', result=prediction)

if __name__ == '__main__':
    app.run(debug=True)
