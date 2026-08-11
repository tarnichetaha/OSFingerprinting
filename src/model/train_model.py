import os
import glob
import time
import joblib
import numpy as np
import pandas as pd
from typing import List, Tuple

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
import xgboost as xgb
from config import MODEL_DIR, RESOURCES_DIR

# 5 common features available in both training data & single SYN packet
FEATURE_COLUMNS = ["SRC_PORT", "TCP_SYN_SIZE", "TCP_WIN", "TCP_MSS", "TTL"]
TARGET_COLUMN = "OS_LABEL"


def round_ttl(ttl: int) -> int:
    """Rounds TTL to nearest higher power of two (32, 64, 128, 256)."""
    if ttl <= 0:
        return 64
    if ttl <= 32:
        return 32
    elif ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 256


def load_and_preprocess_data(data_dir: str = str(RESOURCES_DIR)) -> pd.DataFrame:
    """
    Loads training CSVs (subnet1-4, local) and performs sequential preprocessing (steps 1-6):
    1. Drop rows where TCP_SYN_SIZE == 0
    2. Drop rows where TCP_WIN == 0
    3. Merge 'ios' label into 'macos'
    4. Confirm TTL is power-of-two rounded (round if needed)
    5. Print row counts before and after each cleaning step
    6. Deduplicate on flow keys / feature tuples
    """
    csv_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV datasets found in {data_dir}")

    print("=" * 80)
    print("STEP 0: LOADING DATASETS")
    print("=" * 80)
    
    dfs = []
    total_raw_rows = 0

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        # Load only necessary columns to optimize memory usage
        df_head = pd.read_csv(filepath, nrows=2)
        available_cols = df_head.columns.tolist()
        
        load_cols = [c for c in (FEATURE_COLUMNS + [TARGET_COLUMN, "DST_PORT", "SRC_IP", "DST_IP"]) if c in available_cols]
        df = pd.read_csv(filepath, usecols=load_cols)
        
        raw_count = len(df)
        total_raw_rows += raw_count
        print(f"[{filename}] Loaded {raw_count:,} raw rows")
        
        # Track initial file row count
        current_count = raw_count
        
        # Step 1: Drop rows where TCP_SYN_SIZE == 0
        df = df[df["TCP_SYN_SIZE"] != 0]
        step1_count = len(df)
        print(f"  Step 1 (Drop TCP_SYN_SIZE==0): {current_count:,} -> {step1_count:,} (Dropped {current_count - step1_count:,})")
        current_count = step1_count

        # Step 2: Drop rows where TCP_WIN == 0
        df = df[df["TCP_WIN"] != 0]
        step2_count = len(df)
        print(f"  Step 2 (Drop TCP_WIN==0): {current_count:,} -> {step2_count:,} (Dropped {current_count - step2_count:,})")
        current_count = step2_count

        # Step 3: Merge 'ios' label into 'macos'
        ios_count = (df[TARGET_COLUMN] == "ios").sum()
        df[TARGET_COLUMN] = df[TARGET_COLUMN].replace({"ios": "macos"})
        print(f"  Step 3 (Merge 'ios' -> 'macos'): Merged {ios_count:,} 'ios' rows into 'macos'")

        # Step 4: Confirm/round TTL values
        unrounded_mask = ~df["TTL"].isin([32, 64, 128, 256])
        unrounded_count = unrounded_mask.sum()
        if unrounded_count > 0:
            print(f"  Step 4 (TTL Check): Rounding {unrounded_count:,} non-standard TTL values to power of two...")
            df["TTL"] = df["TTL"].apply(round_ttl)
        else:
            print(f"  Step 4 (TTL Check): Confirmed all TTL values are power-of-two rounded.")

        # Step 6: Deduplicate on (SRC_IP, SRC_PORT, DST_IP, DST_PORT) where possible, or feature tuple
        flow_key_cols = [c for c in ["SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT"] if c in df.columns]
        if len(flow_key_cols) >= 2:
            df = df.drop_duplicates(subset=flow_key_cols)
            print(f"  Step 6 (Flow Key Dedup on {flow_key_cols}): {current_count:,} -> {len(df):,} (Dropped {current_count - len(df):,})")
        else:
            # Fallback for datasets without DST_PORT or IP (e.g. local.csv): deduplicate on exact feature + target rows
            dedup_cols = FEATURE_COLUMNS + [TARGET_COLUMN]
            df = df.drop_duplicates(subset=dedup_cols)
            print(f"  Step 6 (Feature Row Dedup on {dedup_cols}): {current_count:,} -> {len(df):,} (Dropped {current_count - len(df):,})")
        
        step6_count = len(df)
        
        dfs.append(df[FEATURE_COLUMNS + [TARGET_COLUMN]])

    merged_df = pd.concat(dfs, ignore_index=True)
    
    print("\n" + "=" * 80)
    print("PREPROCESSING AUDIT SUMMARY (STEP 5)")
    print("=" * 80)
    print(f"Total Raw Input Rows across all files: {total_raw_rows:,}")
    print(f"Final Preprocessed Training Pool Rows: {len(merged_df):,}")
    print(f"Overall Data Reduction: {total_raw_rows - len(merged_df):,} rows ({(1 - len(merged_df)/total_raw_rows)*100:.2f}% dropped/deduplicated)")
    
    return merged_df


def train_and_evaluate():
    start_time = time.time()
    df = load_and_preprocess_data()

    X = df[FEATURE_COLUMNS]
    y_raw = df[TARGET_COLUMN]

    print("\n" + "=" * 80)
    print("CLASS DISTRIBUTION (BEFORE SPLIT & FIT)")
    print("=" * 80)
    class_dist = y_raw.value_counts()
    for cls_name, count in class_dist.items():
        print(f"  Class '{cls_name}': {count:,} samples ({count / len(df) * 100:.2f}%)")

    # Encode string labels with LabelEncoder
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_raw)
    classes = label_encoder.classes_
    print(f"\nLabelEncoder classes mapping: {dict(enumerate(classes))}")

    # Stratified Train / Test split (Stage 1 validation split)
    print("\nPerforming Stratified 80/20 Train/Test split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )

    # Compute balanced sample weights for XGBoost fitting
    sample_weights = compute_sample_weight("balanced", y_train)

    print("\nClass distribution in Training Set:")
    train_dist = pd.Series(label_encoder.inverse_transform(y_train)).value_counts()
    for cls_name, count in train_dist.items():
        print(f"  Class '{cls_name}': {count:,} samples ({count / len(y_train) * 100:.2f}%)")

    print("\nTraining XGBoost Classifier (objective='multi:softprob')...")
    model = xgb.XGBClassifier(
        objective="multi:softprob",
        eval_metric="mlogloss",
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train, sample_weight=sample_weights)

    # Log booster feature names
    booster_feature_names = model.get_booster().feature_names
    print(f"\nLogged Booster Feature Names: {booster_feature_names}")
    assert booster_feature_names == FEATURE_COLUMNS, f"Feature mismatch! Model expects {booster_feature_names}, configured {FEATURE_COLUMNS}"

    # Stage 1 Evaluation on Held-Out Test Split
    print("\n" + "=" * 80)
    print("STAGE 1 EVALUATION (HELD-OUT TEST SPLIT)")
    print("=" * 80)
    
    y_pred = model.predict(X_test)
    y_pred_labels = label_encoder.inverse_transform(y_pred)
    y_test_labels = label_encoder.inverse_transform(y_test)

    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
    raw_acc = (y_test == y_pred).mean()

    print(f"Headline Evaluation Metrics (Macro-Averaged):")
    print(f"  Macro Precision : {precision:.4f}")
    print(f"  Macro Recall    : {recall:.4f}")
    print(f"  Macro F1 Score  : {f1:.4f}")
    print(f"  (Contextual Raw Accuracy: {raw_acc:.4f})")
    
    print("\nDetailed Classification Report:")
    print(classification_report(y_test_labels, y_pred_labels, digits=4))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test_labels, y_pred_labels, labels=classes)
    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in classes], columns=[f"Pred_{c}" for c in classes])
    print(cm_df.to_string())

    # Save artifact pair (model + LabelEncoder)
    MODEL_DIR.mkdir(exist_ok=True)
    artifact_path = MODEL_DIR / "os_classifier_pair.joblib"
    
    artifact = {
        "model": model,
        "label_encoder": label_encoder,
        "feature_names": FEATURE_COLUMNS,
    }
    
    joblib.dump(artifact, artifact_path)
    print("\n" + "=" * 80)
    print(f"SUCCESS: Saved paired artifact (Model + LabelEncoder) to: {artifact_path}")
    print(f"Total script execution time: {time.time() - start_time:.2f} seconds")
    print("=" * 80)


if __name__ == "__main__":
    train_and_evaluate()
