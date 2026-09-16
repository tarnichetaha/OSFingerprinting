import os
import glob
import json
import time
import sys
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from typing import Dict, List, Any
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

SRC_DIR = Path(__file__).resolve().parents[1]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from scripts.pcap_utils import parse_syn_packets_from_pcap, round_ttl
from config import GROUND_TRUTH_PATH, PCAPS_DIR, resolve_model_artifact_path


def load_ground_truth(gt_path: str = str(GROUND_TRUTH_PATH)) -> Dict[str, str]:
    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"Ground truth file not found: {gt_path}")
    with open(gt_path, "r", encoding="utf-8") as f:
        gt = json.load(f)
    # Ensure lowercase MACs
    return {k.lower(): v.lower() for k, v in gt.items()}


def validate():
    start_time = time.time()
    
    print("=" * 80)
    print("STAGE 2 VALIDATION: INDEPENDENT REAL-WORLD PCAP TESTING")
    print("=" * 80)
    print("NOTE: Cross-network transfer to live PCAPs typically shows lower performance")
    print("than held-out test splits. This is expected due to network environment variations.\n")

    # 1. Load paired model artifact
    artifact_path = resolve_model_artifact_path()
    if not artifact_path.exists():
        raise FileNotFoundError(f"Model artifact pair missing at {artifact_path}. Run train_model.py first.")

    artifact = joblib.load(artifact_path)
    model = artifact["model"]
    label_encoder = artifact["label_encoder"]
    expected_features = artifact["feature_names"]
    
    # 2. Verify feature names & order
    booster_features = model.get_booster().feature_names
    print(f"[MODEL VERIFICATION] Expected Features: {expected_features}")
    print(f"[MODEL VERIFICATION] Booster Features : {booster_features}")
    assert booster_features == expected_features, "Model feature names mismatch!"
    print("[MODEL VERIFICATION] Feature names and order confirmed.\n")

    # 3. Load Ground Truth map
    ground_truth = load_ground_truth()
    print(f"Loaded Ground Truth map ({len(ground_truth)} devices):")
    for mac, os_label in ground_truth.items():
        print(f"  MAC: {mac} -> True OS: {os_label}")

    # 4. Parse PCAPs / PCAPNGs
    pcap_files = sorted(glob.glob(str(PCAPS_DIR / "*.pcap")) + glob.glob(str(PCAPS_DIR / "*.pcapng")))
    if not pcap_files:
        raise FileNotFoundError("No .pcap or .pcapng files found in pcaps/ directory")

    all_records = []
    for pcap_path in pcap_files:
        filename = os.path.basename(pcap_path)
        records = parse_syn_packets_from_pcap(pcap_path)
        print(f"\n[{filename}] Extracted {len(records)} TCP SYN packet flows")
        for r in records:
            r["pcap"] = filename
            all_records.append(r)

    if not all_records:
        print("ERROR: No TCP SYN packets extracted from PCAP files.")
        return

    df_pcap = pd.DataFrame(all_records)
    print(f"\nTotal Extracted PCAP SYN Flows: {len(df_pcap)}")

    # Filter to devices in Ground Truth
    df_eval = df_pcap[df_pcap["mac_address"].isin(ground_truth.keys())].copy()
    if df_eval.empty:
        print("WARNING: No PCAP flows matched any MAC address in ground_truth.json!")
        return

    df_eval["true_os"] = df_eval["mac_address"].map(ground_truth)
    print(f"Matched {len(df_eval)} SYN flows belonging to ground-truth labeled devices.")

    # 5. Model Inference on Live SYN Flows
    X_val = df_eval[expected_features]
    probas = model.predict_proba(X_val)
    pred_indices = np.argmax(probas, axis=1)
    df_eval["predicted_os"] = label_encoder.inverse_transform(pred_indices)
    df_eval["confidence"] = np.max(probas, axis=1)

    # Add class probability columns for detailed analysis
    for idx, cls_name in enumerate(label_encoder.classes_):
        df_eval[f"prob_{cls_name}"] = probas[:, idx]

    # 6. Stage 2 Row-Level Evaluation
    print("\n" + "=" * 80)
    print("STAGE 2: ROW-LEVEL EVALUATION (PER SYN PACKET)")
    print("=" * 80)
    
    y_true_row = df_eval["true_os"]
    y_pred_row = df_eval["predicted_os"]
    
    row_prec, row_rec, row_f1, _ = precision_recall_fscore_support(
        y_true_row, y_pred_row, average="macro", zero_division=0
    )
    row_acc = (y_true_row == y_pred_row).mean()

    print(f"Row-Level Macro Precision : {row_prec:.4f}")
    print(f"Row-Level Macro Recall    : {row_rec:.4f}")
    print(f"Row-Level Macro F1 Score  : {row_f1:.4f}")
    print(f"Row-Level Raw Accuracy    : {row_acc:.4f} ({ (y_true_row == y_pred_row).sum() } / { len(df_eval) })")
    
    print("\nRow-Level Classification Report:")
    print(classification_report(y_true_row, y_pred_row, zero_division=0, digits=4))

    print("Row-Level Confusion Matrix:")
    labels_present = sorted(list(set(y_true_row.unique()) | set(y_pred_row.unique())))
    cm_row = confusion_matrix(y_true_row, y_pred_row, labels=labels_present)
    cm_df = pd.DataFrame(cm_row, index=[f"True_{c}" for c in labels_present], columns=[f"Pred_{c}" for c in labels_present])
    print(cm_df.to_string())

    # 7. Stage 2 Per-Device Majority Vote Evaluation
    print("\n" + "=" * 80)
    print("STAGE 2: PER-DEVICE MAJORITY-VOTE EVALUATION")
    print("=" * 80)

    device_results = []
    for mac, group in df_eval.groupby("mac_address"):
        true_os = ground_truth[mac]
        n_flows = len(group)
        
        # Majority vote
        vote_counts = group["predicted_os"].value_counts()
        majority_os = vote_counts.index[0]
        mean_conf = group["confidence"].mean()
        is_correct = (majority_os == true_os)
        
        device_results.append({
            "mac_address": mac,
            "true_os": true_os,
            "majority_predicted_os": majority_os,
            "n_flows": n_flows,
            "mean_confidence": mean_conf,
            "correct": is_correct,
            "vote_breakdown": dict(vote_counts)
        })

    df_devices = pd.DataFrame(device_results)
    
    print(df_devices[["mac_address", "true_os", "majority_predicted_os", "n_flows", "mean_confidence", "correct"]].to_string(index=False))

    device_acc = df_devices["correct"].mean()
    print(f"\nPer-Device Majority Vote Accuracy: {device_acc:.4f} ({df_devices['correct'].sum()} / {len(df_devices)} devices correct)")

    # 8. Detailed Device Investigation (High-Confidence Conflicting Predictions)
    print("\n" + "=" * 80)
    print("INVESTIGATION: HIGH-CONFIDENCE CONFLICTING PREDICTIONS PER DEVICE")
    print("=" * 80)
    
    HIGH_CONF_THRESH = 0.70
    conflicts_found = False
    
    for mac, group in df_eval.groupby("mac_address"):
        true_os = ground_truth[mac]
        high_conf = group[group["confidence"] >= HIGH_CONF_THRESH]
        unique_high_conf_preds = high_conf["predicted_os"].unique()
        
        if len(unique_high_conf_preds) > 1 or (true_os not in unique_high_conf_preds and len(unique_high_conf_preds) > 0):
            conflicts_found = True
            print(f"\n[CONFLICT DETECTED] MAC: {mac} (True OS: {true_os})")
            print(f"  Observed {len(group)} flows. High-confidence (>= {HIGH_CONF_THRESH}) predictions span: {list(unique_high_conf_preds)}")
            print("  Detailed breakdown of differing SYN feature signatures:")
            
            signature_groups = group.groupby(["SRC_PORT", "TCP_SYN_SIZE", "TCP_WIN", "TCP_MSS", "TTL", "predicted_os"])
            for sig, sig_df in signature_groups:
                src_p, syn_sz, win, mss, ttl, pred_os = sig
                mean_conf = sig_df["confidence"].mean()
                flow_cnt = len(sig_df)
                print(f"    - Flows={flow_cnt:2d} | Feature Vector: [Port={src_p}, Size={syn_sz}, Win={win}, MSS={mss}, TTL={ttl}] => Pred: '{pred_os}' (Mean Conf: {mean_conf:.4f})")
    
    if not conflicts_found:
        print("No devices exhibited conflicting high-confidence predictions across flows.")

    print("\n" + "=" * 80)
    print(f"Stage 2 Validation Complete. Executed in {time.time() - start_time:.2f} seconds.")
    print("=" * 80)


if __name__ == "__main__":
    validate()
