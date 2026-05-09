"""
Trains RandomForest, DecisionTree, and LogisticRegression classifiers on the
extracted feature set, evaluates them with cross-validation, and saves all
outputs (metrics JSON, confusion matrix images, feature importance charts)
to the outputs/ folder.
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
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder

from src.feature_extractor import extract_features

LABEL_ORDER  = ["Low", "Medium", "High"]
OUTPUTS_DIR  = os.path.join(os.path.dirname(__file__), "..", "outputs")
MODELS_DIR   = os.path.join(os.path.dirname(__file__), "..", "outputs", "models")


def _load_features(df: pd.DataFrame):
    """Applies feature extraction to every row and returns X, y arrays."""
    feature_rows = df["terraform_snippet"].apply(extract_features)
    X = pd.DataFrame(feature_rows.tolist())
    y = df["risk_label"]
    return X, y


def train_and_evaluate(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42):
    """
    Full training + evaluation pipeline.

    Steps:
    1. Extract features from every snippet.
    2. Train RandomForest, DecisionTree, and LogisticRegression.
    3. Evaluate each model on the held-out test set.
    4. Run 5-fold cross-validation for a more reliable accuracy estimate.
    5. Save confusion matrix, feature importance chart, model files, and reports.

    Parameters
    ----------
    df           : DataFrame with columns terraform_snippet, risk_label
    test_size    : fraction of data held out for testing (default 25%)
    random_state : seed for reproducibility

    Returns
    -------
    dict mapping model name -> trained sklearn estimator
    """
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR,  exist_ok=True)

    X, y = _load_features(df)

    le = LabelEncoder()
    le.fit(LABEL_ORDER)
    y_enc = le.transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, random_state=random_state, stratify=y_enc
    )

    models = {
        # class_weight='balanced' adjusts for real-world class imbalance
        "RandomForest": RandomForestClassifier(
            n_estimators=100, max_depth=8,
            class_weight="balanced", random_state=random_state
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=6,
            class_weight="balanced", random_state=random_state
        ),
        # LogisticRegression as a linear baseline for comparison
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced", random_state=random_state
        ),
    }

    all_metrics = {}
    text_lines = [
        "Terraform Security Misconfiguration Detector – Evaluation Report",
        "=" * 65,
        f"Dataset size : {len(df)} rows  |  Test fraction : {test_size}",
        f"Features     : {X.shape[1]}  |  Random state : {random_state}",
        "",
    ]

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc         = accuracy_score(y_test, y_pred)
        report_dict = classification_report(
            y_test, y_pred, target_names=le.classes_, output_dict=True
        )
        report_text = classification_report(y_test, y_pred, target_names=le.classes_)

        # 5-fold cross-validation on the full dataset for a stable accuracy estimate
        cv_scores = cross_val_score(clf, X, y_enc, cv=5, scoring="accuracy")

        all_metrics[name] = {
            "accuracy":              round(acc, 4),
            "cv_mean_accuracy":      round(cv_scores.mean(), 4),
            "cv_std":                round(cv_scores.std(), 4),
            "classification_report": report_dict,
        }

        print(f"\n{'='*55}")
        print(f"Model    : {name}")
        print(f"Accuracy : {acc:.4f}  |  CV (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        print(report_text)

        text_lines += [
            f"Model    : {name}",
            f"Accuracy : {acc:.4f}",
            f"CV (5-fold mean ± std) : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}",
            report_text,
            "-" * 65,
            "",
        ]

        _save_confusion_matrix(y_test, y_pred, le.classes_, name)
        _save_feature_importance(clf, X.columns.tolist(), name)

        model_path = os.path.join(MODELS_DIR, f"{name.lower().replace(' ', '_')}.joblib")
        joblib.dump(
            {"model": clf, "label_encoder": le, "feature_names": X.columns.tolist()},
            model_path,
        )
        print(f"Model saved → {model_path}")

    # JSON report
    json_path = os.path.join(OUTPUTS_DIR, "evaluation_report.json")
    with open(json_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\nEvaluation report (JSON) → {json_path}")

    # Plain-text report
    txt_path = os.path.join(OUTPUTS_DIR, "evaluation_report.txt")
    with open(txt_path, "w") as f:
        f.write("\n".join(text_lines))
    print(f"Evaluation report (text) → {txt_path}")

    return models


def _save_confusion_matrix(y_true, y_pred, labels, model_name: str):
    cm  = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=labels, yticklabels=labels, ax=ax,
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title(f"Confusion Matrix – {model_name}")
    path = os.path.join(OUTPUTS_DIR, f"confusion_matrix_{model_name.lower().replace(' ', '_')}.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Confusion matrix → {path}")


def _save_feature_importance(clf, feature_names: list, model_name: str):
    """Saves feature importance for tree models; uses |coef| for linear models."""
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
    elif hasattr(clf, "coef_"):
        # For LogisticRegression, use mean absolute coefficient across classes
        importances = np.abs(clf.coef_).mean(axis=0)
    else:
        return

    indices = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(range(len(feature_names)), importances[indices],
           color="steelblue", edgecolor="black")
    ax.set_xticks(range(len(feature_names)))
    ax.set_xticklabels(
        [feature_names[i] for i in indices], rotation=45, ha="right", fontsize=8
    )
    ax.set_ylabel("Importance")
    ax.set_title(f"Feature Importances – {model_name}")
    path = os.path.join(OUTPUTS_DIR, f"feature_importance_{model_name.lower().replace(' ', '_')}.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Feature importance  → {path}")
