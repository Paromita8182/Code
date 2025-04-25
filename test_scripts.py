from features_extraction import URLFeatureExtractor
from predictions import URLPrediction

api_keys = {
    "whois": "at_Nv9eGpwH5sNL3IB97ts57t4aRUdwz",
    "ahrefs": "141b02baeamsh56630f5db299b43p1dc7b4jsn728427db79ed",
    "opr": "kw8cw0400ogc4cg404w8ok8kko0440c4s4cow0w4",
    "google": "AIzaSyAUsxImoS7oD7_FxpXjmeJ_h8HL_ajUQJI",
    "cse_id": "6663c195cebc14c2d"
}

url = "https://chriswayg.gitbook.io/opencore-visual-beginners-guide/alternatives/usb-mapping-on-windows"

# Extract Features

extractor = URLFeatureExtractor(api_keys=api_keys, url=url)
features_df = extractor.extract_features()

# Run Prediction

url_predictor = URLPrediction()  # Create an instance of the class
prediction = url_predictor.predict(features_df)  # Get the prediction

if prediction == 1:
    print("URL is Phishing!")
elif prediction == 0:
    print("URL is Benign!")
else:
    print("Error in prediction")





