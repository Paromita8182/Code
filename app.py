from flask import Flask, render_template, request, jsonify
from predictions import URLPrediction
import random
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import urllib.parse
from urllib.parse import urlparse, urljoin
import re
import pytz
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dateutil import parser
from features_extraction import URLFeatureExtractor
from predictions import URLPrediction

api_keys = {
    "whois": "at_Nv9eGpwH5sNL3IB97ts57t4aRUdwz",
    "ahrefs": "141b02baeamsh56630f5db299b43p1dc7b4jsn728427db79ed",
    "opr": "kw8cw0400ogc4cg404w8ok8kko0440c4s4cow0w4",
    "google": "AIzaSyAUsxImoS7oD7_FxpXjmeJ_h8HL_ajUQJI",
    "cse_id": "6663c195cebc14c2d"
}

app = Flask(__name__)

# Dummy function simulating the URL classification script
def classify_url(url, api_keys):
    # Extract Features
    extractor = URLFeatureExtractor(api_keys=api_keys, url=url)
    features_df = extractor.extract_features()

    # Run Prediction
    url_predictor = URLPrediction()  # Create an instance of the class
    prediction = url_predictor.predict(features_df)  # Get the prediction

    return prediction

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    
    result = classify_url(url, api_keys)  # Feed the URL to the script
    return jsonify({'result': result})


if __name__ == '__main__':
    app.run(debug=True)
