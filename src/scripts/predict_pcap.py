import sys
import os
import glob
import time
import joblib
import pandas as pd
import numpy as np
from typing import Dict, List, Any

from scripts.pcap_utils import parse_syn_packets_from_pcap
from config import PCAPS_DIR, resolve_model_artifact_path


def predict_pcap(pcap_path: str, model_path: str | None = None):
    start_time = time.time()
    if model_path is None:
        model_path = str(resolve_model_artifact_path())
    
    print("=" * 80)
    print("PCAP STANDALONE OS INFERENCE PIPELINE")
    print("=" * 80)
    print(f"Target PCAP File  : {pcap_path}")
    print(f"Model Artifact    : {model_path}")

    # 1. Load paired model artifact
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model artifact missing at '{model_path}'. Please run train_model.py first.")

    artifact = joblib.load(model_path)
    model = artifact["model"]
    label_encoder = artifact["label_encoder"]
    expected_features = artifact["feature_names"]

    # 2. Verify model feature names
    booster_features = model.get_booster().feature_names
    print(f"\n[DIAGNOSTIC] Loaded Feature Order: {expected_features}")
    print(f"[DIAGNOSTIC] Booster Feature Order : {booster_features}")
    assert booster_features == expected_features, "Feature order mismatch in loaded model booster!"
    print("[DIAGNOSTIC] Feature names verified successfully.")

    # 3. Parse SYN packets from PCAP
    print(f"\n[DIAGNOSTIC] Extracting TCP SYN packets from '{pcap_path}'...")
    records = parse_syn_packets_from_pcap(pcap_path)
    
    if not records:
        print(f"\nWARNING: No TCP SYN packets (flags == 'S') found in '{pcap_path}'.")
        print("Output Summary Table:")
        print("mac_address | predicted_os | confidence | n_flows_observed")
        return

    df_pcap = pd.DataFrame(records)
    total_syns = len(df_pcap)
    unique_macs = df_pcap["mac_address"].nunique()
    
    print(f"[DIAGNOSTIC] Extracted {total_syns:,} TCP SYN packets across {unique_macs} unique MAC addresses.")

    # 4. Predict probabilities per SYN packet
    X_infer = df_pcap[expected_features]
    probas = model.predict_proba(X_infer)
    pred_indices = np.argmax(probas, axis=1)
    
    df_pcap["predicted_os"] = label_encoder.inverse_transform(pred_indices)
    df_pcap["confidence"] = np.max(probas, axis=1)

    # 5. Aggregate per MAC Address
    summary_list = []
    for mac, group in df_pcap.groupby("mac_address"):
        n_flows = len(group)
        # Majority vote label
        vote_counts = group["predicted_os"].value_counts()
        majority_os = vote_counts.index[0]
        mean_confidence = group["confidence"].mean()
        
        summary_list.append({
            "mac_address": mac,
            "predicted_os": majority_os,
            "confidence": round(float(mean_confidence), 4),
            "n_flows_observed": n_flows
        })

    df_summary = pd.DataFrame(summary_list)
    df_summary = df_summary.sort_values(by="n_flows_observed", ascending=False).reset_index(drop=True)

    # 6. Display Result Table
    print("\n" + "=" * 80)
    print("DEVICE OS PREDICTION TABLE")
    print("=" * 80)
    print(df_summary.to_string(index=False))
    print("=" * 80)
    print(f"Inference completed in {time.time() - start_time:.3f} seconds.")
    print("=" * 80 + "\n")


def main():
    if len(sys.argv) > 1:
        pcap_target = sys.argv[1]
    else:
        # Default fallback to test pcap/pcapng if none specified
        default_pcaps = sorted(glob.glob(str(PCAPS_DIR / "*.pcap")) + glob.glob(str(PCAPS_DIR / "*.pcapng")))
        if default_pcaps:
            pcap_target = default_pcaps[0]
            print(f"No PCAP argument provided. Using default: {pcap_target}")
        else:
            print("Usage: python predict_pcap.py <path_to_pcap_or_pcapng>")
            sys.exit(1)

    predict_pcap(pcap_target)


if __name__ == "__main__":
    main()
