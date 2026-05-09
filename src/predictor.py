"""
Loads a trained model and classifies a new Terraform snippet,
returning the predicted risk level, confidence scores, and a plain-English
explanation of which security indicators triggered the prediction.
"""

import os
import joblib
import pandas as pd

from src.feature_extractor import extract_features, explain_features

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs", "models")


def load_model(model_name: str = "RandomForest"):
    """Loads a saved model bundle from outputs/models/."""
    path = os.path.join(MODELS_DIR, f"{model_name.lower()}.joblib")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model file not found: {path}\n"
            "Run main.py --train first to train and save the models."
        )
    return joblib.load(path)


def predict(snippet: str, model_name: str = "RandomForest") -> dict:
    """
    Classifies a Terraform snippet and returns a structured result.

    Parameters
    ----------
    snippet    : raw Terraform HCL text
    model_name : "RandomForest" or "DecisionTree"

    Returns
    -------
    dict with keys:
        risk_level   – predicted class label (Low / Medium / High)
        probabilities – dict of {label: probability} (None for DT without proba)
        features      – extracted feature dict
        reason        – human-readable explanation string
    """
    bundle = load_model(model_name)
    clf     = bundle["model"]
    le      = bundle["label_encoder"]
    feat_names = bundle["feature_names"]

    features = extract_features(snippet)
    X = pd.DataFrame([features])[feat_names]

    pred_enc  = clf.predict(X)[0]
    risk_level = le.inverse_transform([pred_enc])[0]

    # Probability scores when available
    probabilities = None
    if hasattr(clf, "predict_proba"):
        proba_arr = clf.predict_proba(X)[0]
        probabilities = {
            label: round(float(prob), 4)
            for label, prob in zip(le.classes_, proba_arr)
        }

    reason = explain_features(features)

    return {
        "risk_level":    risk_level,
        "probabilities": probabilities,
        "features":      features,
        "reason":        reason,
    }


def print_prediction(result: dict):
    """Pretty-prints a prediction result to stdout."""
    print("\n" + "=" * 55)
    print(f"  Risk Level  : {result['risk_level']}")
    if result["probabilities"]:
        prob_str = "  |  ".join(
            f"{k}: {v:.1%}" for k, v in result["probabilities"].items()
        )
        print(f"  Confidence  : {prob_str}")
    print(f"  Reason      : {result['reason']}")
    print("  Triggered Features:")
    for feat, val in result["features"].items():
        if feat != "count_sensitive_indicators" and val:
            print(f"    • {feat}")
    print(f"  Total Indicators: {result['features']['count_sensitive_indicators']}")
    print("=" * 55)
