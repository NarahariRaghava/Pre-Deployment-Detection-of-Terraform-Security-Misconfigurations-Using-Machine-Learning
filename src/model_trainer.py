"""
Trains RandomForest and DecisionTree classifiers on the extracted feature set,
evaluates them, and saves all outputs (metrics JSON, confusion matrix image,
feature importance chart) to the outputs/ folder.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend for saving figures
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.preprocessing import LabelEncoder

from src.feature_extractor import extract_features

LABEL_ORDER = ["Low", "Medium", "High"]
OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")
MODELS_DIR  = os.path.join(os.path.dirname(__file__), "..", "outputs", "models")


def _load_features(df: pd.DataFrame):
    """Applies feature extraction to every row and returns X, y arrays."""
    feature_rows = df["terraform_snippet"].apply(extract_features)
    X = pd.DataFrame(feature_rows.tolist())
    y = df["risk_label"]
    return X, y


def train_and_evaluate(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42):
    """
    Full training + evaluation pipeline.

    Parameters
    ----------
    df : DataFrame with columns terraform_snippet, risk_label
    test_size : fraction of data held out for testing
    random_state : seed for reproducibility

    Returns
    -------
    dict mapping model name -> trained sklearn estimator
    """
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    X, y = _load_features(df)

    # Encode labels to integers for sklearn (keeps string labels for display)
    le = LabelEncoder()
    le.fit(LABEL_ORDER)
    y_enc = le.transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, random_state=random_state, stratify=y_enc
    )

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=100, max_depth=8, random_state=random_state
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=6, random_state=random_state
        ),
    }

    all_metrics = {}
    # Accumulate plain-text lines for the human-readable report
    text_lines = [
        "Terraform Security Misconfiguration Detector – Evaluation Report",
        "=" * 65,
        f"Dataset size : {len(df)} rows  |  Test fraction : {test_size}",
        f"Random state : {random_state}",
        "",
    ]

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        # output_dict=True for JSON; text version printed separately
        report_dict = classification_report(
            y_test, y_pred,
            target_names=le.classes_,
            output_dict=True,
        )
        report_text = classification_report(y_test, y_pred, target_names=le.classes_)

        all_metrics[name] = {
            "accuracy": round(acc, 4),
            "classification_report": report_dict,
        }

        print(f"\n{'='*50}")
        print(f"Model: {name}")
        print(f"Accuracy: {acc:.4f}")
        print(report_text)

        # Append to plain-text report
        text_lines += [
            f"Model : {name}",
            f"Accuracy : {acc:.4f}",
            report_text,
            "-" * 65,
            "",
        ]

        # Confusion matrix image
        _save_confusion_matrix(y_test, y_pred, le.classes_, name)

        # Feature importance chart (only for tree-based models)
        _save_feature_importance(clf, X.columns.tolist(), name)

        # Persist the trained model bundle for the predictor module
        model_path = os.path.join(MODELS_DIR, f"{name.lower()}.joblib")
        joblib.dump(
            {"model": clf, "label_encoder": le, "feature_names": X.columns.tolist()},
            model_path,
        )
        print(f"Model saved to {model_path}")

    # Write combined metrics as JSON (machine-readable)
    json_path = os.path.join(OUTPUTS_DIR, "evaluation_report.json")
    with open(json_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\nEvaluation report (JSON) saved to {json_path}")

    # Write the same metrics as plain text (human-readable, easy to paste into reports)
    txt_path = os.path.join(OUTPUTS_DIR, "evaluation_report.txt")
    with open(txt_path, "w") as f:
        f.write("\n".join(text_lines))
    print(f"Evaluation report (text) saved to {txt_path}")

    return models


def _save_confusion_matrix(y_true, y_pred, labels, model_name: str):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
        ax=ax,
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title(f"Confusion Matrix – {model_name}")
    path = os.path.join(OUTPUTS_DIR, f"confusion_matrix_{model_name.lower()}.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Confusion matrix saved to {path}")


def _save_feature_importance(clf, feature_names: list, model_name: str):
    if not hasattr(clf, "feature_importances_"):
        return
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(
        range(len(feature_names)),
        importances[indices],
        color="steelblue",
        edgecolor="black",
    )
    ax.set_xticks(range(len(feature_names)))
    ax.set_xticklabels(
        [feature_names[i] for i in indices], rotation=40, ha="right", fontsize=9
    )
    ax.set_ylabel("Importance")
    ax.set_title(f"Feature Importances – {model_name}")
    path = os.path.join(OUTPUTS_DIR, f"feature_importance_{model_name.lower()}.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Feature importance chart saved to {path}")
