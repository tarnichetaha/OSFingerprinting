# Annex: Key Implementation Extracts

The following extracts show the main technical path of the OS fingerprinting system. They are shortened for readability; the complete implementations remain in the referenced source files.

## A. Shared Machine-Learning Configuration

Source: `src/config.py`

```python
FEATURE_COLUMNS = ["SRC_PORT", "TCP_SYN_SIZE", "TCP_WIN", "TCP_MSS", "TTL"]
TARGET_COLUMN = "OS_LABEL"
ML_TEST_SIZE = 0.20
ML_RANDOM_STATE = 42

XGB_CLASSIFIER_PARAMS = {
    "objective": "multi:softprob",
    "eval_metric": ["mlogloss", "merror"],
    "n_estimators": 150,
    "max_depth": 6,
    "learning_rate": 0.1,
    "random_state": ML_RANDOM_STATE,
    "n_jobs": -1,
}
```

These constants guarantee that training and inference use the same feature order and reproducible split settings.

## B. TTL Normalization

Source: `src/scripts/pcap_utils.py`

```python
def round_ttl(ttl: int) -> int:
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
```

The observed TTL is mapped to the nearest higher conventional initial-TTL value, reducing variation caused by network hops.

## C. TCP SYN Feature Extraction

Source: `src/scripts/pcap_utils.py`

```python
if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
    continue

tcp = pkt[TCP]
# SYN set and ACK not set: initial TCP SYN only
if (int(tcp.flags) & 0x12) != 0x02:
    continue

records.append({
    "mac_address": str(pkt[Ether].src).lower(),
    "flow_key": (str(pkt[IP].src), int(tcp.sport),
                  str(pkt[IP].dst), int(tcp.dport)),
    "SRC_PORT": int(tcp.sport),
    "TCP_SYN_SIZE": len(pkt[IP]),
    "TCP_WIN": int(tcp.window),
    "TCP_MSS": extract_mss_from_tcp_options(tcp),
    "TTL": round_ttl(int(pkt[IP].ttl)),
})
```

The classifier uses five passive TCP/IP characteristics: source port, SYN packet size, TCP window, MSS, and normalized TTL.

## D. Dataset Preprocessing

Source: `src/model/train_model.py`

```python
# Remove invalid observations
df = df[df["TCP_SYN_SIZE"] != 0]
df = df[df["TCP_WIN"] != 0]

# Consolidate equivalent labels
df[TARGET_COLUMN] = df[TARGET_COLUMN].replace({"ios": "macos"})

# Normalize non-standard TTL values
unrounded = ~df["TTL"].isin([32, 64, 128, 256])
if unrounded.any():
    df["TTL"] = df["TTL"].apply(round_ttl)

# Remove duplicate flows where identifying columns exist
flow_key_cols = [c for c in ["SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT"]
                 if c in df.columns]
if len(flow_key_cols) >= 2:
    df = df.drop_duplicates(subset=flow_key_cols)
else:
    df = df.drop_duplicates(subset=FEATURE_COLUMNS + [TARGET_COLUMN])
```

The preprocessing stage removes invalid values, merges the iOS class into macOS, normalizes TTL values, and limits duplicate influence during training.

## E. Model Training and Held-Out Evaluation

Source: `src/model/train_model.py`

```python
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y_raw)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=ML_TEST_SIZE,
    random_state=ML_RANDOM_STATE,
    stratify=y_encoded,
)

sample_weights = compute_sample_weight("balanced", y_train)
model = xgb.XGBClassifier(**XGB_CLASSIFIER_PARAMS)

model.fit(
    X_train,
    y_train,
    sample_weight=sample_weights,
    eval_set=[(X_train, y_train), (X_test, y_test)],
    verbose=False,
)

predicted = model.predict(X_test)
precision, recall, f1, _ = precision_recall_fscore_support(
    y_test, predicted, average="macro"
)
raw_accuracy = (y_test == predicted).mean()
```

A stratified 80/20 split is used. Balanced sample weights reduce the effect of class imbalance. The model is evaluated using macro precision, macro recall, macro F1, and raw accuracy.

## F. Runtime Probability-Based Inference

Source: `src/scripts/parse_pcap.py`

```python
artifact = joblib.load(model_artifact_path)
ml_model = artifact["model"]
label_encoder = artifact["label_encoder"]
expected_features = artifact["feature_names"]

features = pd.DataFrame([{
    "SRC_PORT": src_port,
    "TCP_SYN_SIZE": tcp_syn_size,
    "TCP_WIN": tcp_win,
    "TCP_MSS": tcp_mss,
    "TTL": ttl_rounded,
}])[expected_features]

probabilities = ml_model.predict_proba(features)
predicted_index = np.argmax(probabilities, axis=1)[0]
os_guess = str(label_encoder.inverse_transform([predicted_index])[0])
confidence = float(np.max(probabilities, axis=1)[0])
```

The saved model, label encoder, and feature order are loaded together. The highest class probability becomes the predicted OS and is retained as a confidence value.

## G. Per-Device Majority Vote

Source: `src/scripts/predict_pcap.py`

```python
for mac, group in df_pcap.groupby("mac_address"):
    vote_counts = group["predicted_os"].value_counts()
    majority_os = vote_counts.index[0]
    mean_confidence = group["confidence"].mean()

    summary_list.append({
        "mac_address": mac,
        "predicted_os": majority_os,
        "confidence": round(float(mean_confidence), 4),
        "n_flows_observed": len(group),
    })
```

Multiple SYN observations are aggregated per MAC address. The most frequent predicted label is reported as the device-level OS, together with mean confidence and the number of observed flows.

## H. Saved Training Curves

Source: `src/model/train_model.py`

```python
evals_result = model.evals_result()
training_history = {
    "train_mlogloss": evals_result["validation_0"]["mlogloss"],
    "test_mlogloss": evals_result["validation_1"]["mlogloss"],
    "train_accuracy": [1 - e for e in evals_result["validation_0"]["merror"]],
    "test_accuracy": [1 - e for e in evals_result["validation_1"]["merror"]],
}

save_training_graphs(training_history)
```

The training and test loss and accuracy curves are saved as `models/training_loss.png` and `models/training_accuracy.png`.
