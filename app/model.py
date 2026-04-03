import pickle
import numpy as np
from typing import Tuple
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.features import extract_features

_model = None

def load_model():
    global _model
    model_path = "ml/phishing_model.pkl"

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}. "
            "Please run: python ml/train_model.py"
        )

    with open(model_path, "rb") as f:
        _model = pickle.load(f)

    print("ML model loaded successfully!")
    return _model

def predict_url(url: str) -> Tuple[str, float]:
    global _model

    if _model is None:
        load_model()

    features = extract_features(url)
    features_array = np.array(features).reshape(1, -1)

    probabilities = _model.predict_proba(features_array)[0]
    risk_score = float(probabilities[1])

    if risk_score >= 0.5:
        prediction = "Phishing"
    else:
        prediction = "Safe"

    return prediction, round(risk_score, 4)