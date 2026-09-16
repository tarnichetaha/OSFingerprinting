"""Compute report-ready metrics for the saved OS classifier artifact."""
import json
import os
import sys
import time
import glob
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    log_loss,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import (
    ML_RANDOM_STATE,
    ML_TEST_SIZE,
    MODEL_DIR,
    RESOURCES_DIR,
    resolve_model_artifact_path,
)
from model.train_model import FEATURE_COLUMNS, load_and_preprocess_data
from scripts.pcap_utils import parse_syn_packets_from_pcap
from config import GROUND_TRUTH_PATH, PCAPS_DIR

OUTPUT_PATH = MODEL_DIR / "os_classifier_metrics.json"
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


def calibration_metrics(y_true, probabilities):
    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == y_true).astype(float)
    bins = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    mce = 0.0
    calibration_bins = []
    for index in range(10):
        lower = bins[index]
        upper = bins[index + 1]
        mask = (confidence >= lower) & (confidence <= upper if index == 9 else confidence < upper)
        count = int(mask.sum())
        if count == 0:
            continue
        mean_confidence = float(confidence[mask].mean())
        accuracy = float(correct[mask].mean())
        gap = abs(accuracy - mean_confidence)
        ece += (count / len(y_true)) * gap
        mce = max(mce, gap)
        calibration_bins.append({
            "bin": index,
            "lower": lower,
            "upper": upper,
            "count": count,
            "mean_confidence": mean_confidence,
            "accuracy": accuracy,
        })
    return float(ece), float(mce), calibration_bins


def feature_importance(model):
    booster = model.get_booster()
    gain = booster.get_score(importance_type="gain")
    cover = booster.get_score(importance_type="cover")
    weight = booster.get_score(importance_type="weight")
    rows = []
    for feature in FEATURE_COLUMNS:
        rows.append({
            "feature": feature,
            "gain": float(gain.get(feature, 0.0)),
            "cover": float(cover.get(feature, 0.0)),
            "frequency": int(weight.get(feature, 0.0)),
        })
    return sorted(rows, key=lambda row: row["gain"], reverse=True)


def threshold_metrics(y_true, probabilities):
    predicted = probabilities.argmax(axis=1)
    confidence = probabilities.max(axis=1)
    rows = []
    for threshold in THRESHOLDS:
        kept = confidence >= threshold
        count = int(kept.sum())
        if count:
            precision = float((predicted[kept] == y_true[kept]).mean())
            correct = int((predicted[kept] == y_true[kept]).sum())
            recall = float(correct / len(y_true))
            f1 = float(2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        else:
            precision = recall = f1 = 0.0
        rows.append({
            "threshold": threshold,
            "precision": precision,
            "recall": recall,
            "coverage": float(kept.mean()),
            "f1": f1,
            "count": count,
        })
    return rows


def independent_validation(model, encoder):
    """Evaluate matched SYN flows and per-device majority votes from PCAPs."""
    pcap_files = sorted(glob.glob(str(PCAPS_DIR / "*.pcap")) + glob.glob(str(PCAPS_DIR / "*.pcapng")))
    if not pcap_files:
        return {"available": False, "reason": "No PCAP files found.", "coverage": None}
    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    ground_truth = {key.lower(): value.lower() for key, value in ground_truth.items()}
    records = []
    for path in pcap_files:
        records.extend(parse_syn_packets_from_pcap(path))
    matched = [row for row in records if row["mac_address"] in ground_truth]
    if not matched:
        return {
            "available": False,
            "reason": "No extracted SYN matched ground_truth.json.",
            "coverage": 0.0,
            "ground_truth_devices": len(ground_truth),
            "matched_devices": 0,
        }

    features = np.asarray([[row[name] for name in FEATURE_COLUMNS] for row in matched])
    probabilities = model.predict_proba(features)
    predicted_indices = probabilities.argmax(axis=1)
    predicted_labels = encoder.inverse_transform(predicted_indices)
    true_labels = np.asarray([ground_truth[row["mac_address"]] for row in matched])
    classes = list(encoder.classes_)
    labels = np.arange(len(classes))
    true_indices = encoder.transform(true_labels)
    row_matrix = confusion_matrix(true_indices, predicted_indices, labels=labels)
    row_p, row_r, row_f, _ = precision_recall_fscore_support(
        true_indices, predicted_indices, labels=labels, average="macro", zero_division=0
    )

    device_rows = []
    for mac in sorted({row["mac_address"] for row in matched}):
        indices = [index for index, row in enumerate(matched) if row["mac_address"] == mac]
        votes = predicted_labels[indices]
        values, counts = np.unique(votes, return_counts=True)
        majority = str(values[counts.argmax()])
        true_label = ground_truth[mac]
        device_rows.append({
            "mac_address": mac,
            "true_os": true_label,
            "predicted_os": majority,
            "confidence": float(probabilities[indices].max(axis=1).mean()),
            "correct": majority == true_label,
        })
    device_true = encoder.transform([row["true_os"] for row in device_rows])
    device_pred = encoder.transform([row["predicted_os"] for row in device_rows])
    device_matrix = confusion_matrix(device_true, device_pred, labels=labels)
    device_p, device_r, device_f, _ = precision_recall_fscore_support(
        device_true, device_pred, labels=labels, average="macro", zero_division=0
    )
    row_confidence = probabilities.max(axis=1)
    correct_mask = predicted_indices == true_indices
    return {
        "available": True,
        "pcap_files": [os.path.basename(path) for path in pcap_files],
        "flow_count": len(matched),
        "device_count": len(device_rows),
        "ground_truth_devices": len(ground_truth),
        "matched_devices": len(device_rows),
        "coverage": len(device_rows) / len(ground_truth) if ground_truth else 0.0,
        "flow": {
            "accuracy": float(accuracy_score(true_indices, predicted_indices)),
            "macro_precision": float(row_p),
            "macro_recall": float(row_r),
            "macro_f1": float(row_f),
            "confusion_matrix": row_matrix.tolist(),
            "mean_confidence_correct": float(row_confidence[correct_mask].mean()) if correct_mask.any() else None,
            "mean_confidence_incorrect": float(row_confidence[~correct_mask].mean()) if (~correct_mask).any() else None,
        },
        "device": {
            "accuracy": float(accuracy_score(device_true, device_pred)),
            "macro_precision": float(device_p),
            "macro_recall": float(device_r),
            "macro_f1": float(device_f),
            "confusion_matrix": device_matrix.tolist(),
            "mean_confidence_correct": float(np.mean([row["confidence"] for row in device_rows if row["correct"]])) if any(row["correct"] for row in device_rows) else None,
            "mean_confidence_incorrect": float(np.mean([row["confidence"] for row in device_rows if not row["correct"]])) if any(not row["correct"] for row in device_rows) else None,
        },
    }


def main():
    started = time.perf_counter()
    artifact_path = resolve_model_artifact_path()
    artifact = joblib.load(artifact_path)
    model = artifact["model"]
    encoder = artifact["label_encoder"]

    data = load_and_preprocess_data(str(RESOURCES_DIR))
    X = data[FEATURE_COLUMNS]
    y = encoder.transform(data["OS_LABEL"])
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=ML_TEST_SIZE, random_state=ML_RANDOM_STATE, stratify=y
    )

    probabilities = model.predict_proba(X_test)
    predicted = probabilities.argmax(axis=1)
    classes = list(encoder.classes_)
    report = classification_report(
        y_test, predicted, labels=np.arange(len(classes)), target_names=classes,
        output_dict=True, zero_division=0,
    )
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, predicted, labels=np.arange(len(classes)), zero_division=0,
    )
    matrix = confusion_matrix(y_test, predicted, labels=np.arange(len(classes)))
    specificity = []
    fpr = []
    for index in range(len(classes)):
        true_positive = matrix[index, index]
        false_positive = matrix[:, index].sum() - true_positive
        false_negative = matrix[index, :].sum() - true_positive
        true_negative = matrix.sum() - true_positive - false_positive - false_negative
        specificity.append(float(true_negative / (true_negative + false_positive)))
        fpr.append(float(false_positive / (false_positive + true_negative)))

    one_hot = label_binarize(y_test, classes=np.arange(len(classes)))
    ece, mce, bins = calibration_metrics(y_test, probabilities)
    try:
        auc_ovr = float(roc_auc_score(one_hot, probabilities, multi_class="ovr", average="macro"))
        auc_ovo = float(roc_auc_score(one_hot, probabilities, multi_class="ovo", average="macro"))
    except ValueError:
        auc_ovr = auc_ovo = None

    # XGBoost does not serialize evals_result() in this artifact; reuse the
    # history emitted by the existing training run.
    saved_metrics = {}
    if OUTPUT_PATH.exists():
        saved_metrics = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
    history = saved_metrics.get("training_history", {})
    train_logloss = history.get("train_mlogloss", [])
    test_logloss = history.get("test_mlogloss", [])
    train_accuracy = history.get("train_accuracy", [])
    test_accuracy = history.get("test_accuracy", [])
    selected_iterations = list(range(0, len(train_logloss), 10))
    if train_logloss and len(train_logloss) - 1 not in selected_iterations:
        selected_iterations.append(len(train_logloss) - 1)
    history_table = [
        {
            "iteration": index + 1,
            "train_logloss": train_logloss[index],
            "test_logloss": test_logloss[index],
            "train_accuracy": train_accuracy[index],
            "test_accuracy": test_accuracy[index],
        }
        for index in selected_iterations
    ]

    sample_size = min(10000, len(X_test))
    inference_started = time.perf_counter()
    model.predict_proba(X_test.iloc[:sample_size])
    inference_seconds = time.perf_counter() - inference_started
    ece_brier = float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))
    independent = independent_validation(model, encoder)

    metrics = {
        "metric_version": 1,
        "artifact_path": str(artifact_path),
        "classes": classes,
        "feature_names": FEATURE_COLUMNS,
        "holdout": {
            "accuracy": float(accuracy_score(y_test, predicted)),
            "macro_precision": float(precision.mean()),
            "macro_recall": float(recall.mean()),
            "macro_f1": float(f1.mean()),
            "weighted_precision": float(report["weighted avg"]["precision"]),
            "weighted_recall": float(report["weighted avg"]["recall"]),
            "weighted_f1": float(report["weighted avg"]["f1-score"]),
            "micro_precision": float(precision_recall_fscore_support(y_test, predicted, average="micro")[0]),
            "micro_recall": float(precision_recall_fscore_support(y_test, predicted, average="micro")[1]),
            "micro_f1": float(precision_recall_fscore_support(y_test, predicted, average="micro")[2]),
            "log_loss": float(log_loss(y_test, probabilities, labels=np.arange(len(classes)))),
            "brier_score_multiclass": ece_brier,
            "auc_roc_ovr_macro": auc_ovr,
            "auc_roc_ovo_macro": auc_ovo,
            "train_size": int(len(X_train)),
            "test_size": int(len(X_test)),
        },
        "per_class": [
            {
                "class": classes[index],
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
                "specificity": specificity[index],
                "fpr": fpr[index],
            }
            for index in range(len(classes))
        ],
        "confusion_matrix": matrix.tolist(),
        "calibration": {"ece_10_bins": ece, "mce_10_bins": mce, "bins": bins},
        "training_history_sampled": history_table,
        "feature_importance": feature_importance(model),
        "confidence_thresholds": threshold_metrics(y_test, probabilities),
        "timing": {
            "training_seconds": None,
            "training_seconds_note": "Not recorded by the existing training script; the saved artifact does not contain this value.",
            "inference_sample_size": sample_size,
            "inference_total_seconds": inference_seconds,
            "inference_seconds_per_packet": inference_seconds / sample_size,
            "model_size_mb": os.path.getsize(artifact_path) / (1024 * 1024),
        },
        "independent_validation": independent,
        "generated_seconds": time.time(),
        "generation_elapsed_seconds": time.perf_counter() - started,
    }
    MODEL_DIR.mkdir(exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT_PATH), "holdout": metrics["holdout"], "elapsed": metrics["generation_elapsed_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
