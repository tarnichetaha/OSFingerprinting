from pathlib import Path
import json
import pandas as pd
from scapy.all import PcapReader, Ether, IP, TCP
import joblib
import xgboost as xgb

pcap_path = Path('pcaps/test2.pcap')
gt_path = Path('resources/ground_truth.json')
model_path = Path('models/xgb_os_classifier.json')
encoder_path = Path('models/label_encoder.pkl')

with gt_path.open('r', encoding='utf-8') as f:
    gt = {k.lower(): v for k, v in json.load(f).items()}

rows = []
for pkt in PcapReader(str(pcap_path)):
    if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
        continue
    if pkt[TCP].flags != 'S':
        continue
    mac = pkt[Ether].src.lower()
    if mac not in gt:
        continue
    mss = None
    for opt in pkt[TCP].options:
        if opt[0] == 'MSS':
            mss = opt[1]
            break
    rows.append({
        'mac_address': mac,
        'src_ip': pkt[IP].src,
        'dst_ip': pkt[IP].dst,
        'src_port': pkt[TCP].sport,
        'dst_port': pkt[TCP].dport,
        'TCP_SYN_SIZE': len(pkt),
        'TCP_WIN': pkt[TCP].window,
        'TCP_MSS': mss,
        'TTL': pkt[IP].ttl,
        'true_label': gt[mac],
    })

print('Loaded ground truth MACs:', sorted(gt.keys()))
print('Total SYN rows:', len(rows))

if not rows:
    raise SystemExit('No validation rows from pcap/gt')

df = pd.DataFrame(rows)
print('Rows by MAC:')
print(df['mac_address'].value_counts().to_string())
print('Unique flows overall:', len(df.drop_duplicates(subset=['src_ip','src_port','dst_ip','dst_port'])))
print('Unique flows by MAC:')
print(df.drop_duplicates(subset=['src_ip','src_port','dst_ip','dst_port'])['mac_address'].value_counts().to_string())

for mac in df['mac_address'].unique():
    subset = df[df['mac_address'] == mac]
    dup = subset.duplicated(subset=['src_ip','src_port','dst_ip','dst_port'], keep=False)
    print(f'--- {mac} duplicates: {dup.sum()} of {len(subset)} rows ---')
    if dup.any():
        print(subset[dup].head(10).to_string(index=False))

if model_path.exists() and encoder_path.exists():
    model = xgb.XGBClassifier()
    model.load_model(str(model_path))
    label_encoder = joblib.load(str(encoder_path))

    def ttl_round(ttl: int) -> int:
        ttl = int(ttl)
        if ttl <= 1:
            return 1
        power = 1
        while power < ttl:
            power *= 2
        return power

    val = df.copy()
    val['TTL_raw'] = val['TTL']
    val['TTL_rounded'] = val['TTL'].apply(ttl_round)
    val['TTL'] = val['TTL_rounded']
    val['SRC_PORT'] = val['src_port']
    val['TCP_SYN_SIZE'] = val['TCP_SYN_SIZE']
    val['TCP_WIN'] = val['TCP_WIN']
    val['TCP_MSS'] = val['TCP_MSS']

    features = ['SRC_PORT', 'TCP_SYN_SIZE', 'TCP_WIN', 'TCP_MSS', 'TTL']
    probs = model.predict_proba(val[features])
    labels = label_encoder.inverse_transform(probs.argmax(axis=1))
    val['predicted_label'] = labels
    val['confidence'] = probs.max(axis=1)

    print('\nPrediction summary:')
    print(val[['mac_address', 'true_label', 'predicted_label', 'confidence']].value_counts().to_string())
    print('\nTop wrong predictions by confidence:')
    wrong = val[val['predicted_label'] != val['true_label']]
    if wrong.empty:
        print('None')
    else:
        print(wrong.sort_values('confidence', ascending=False).head(20).to_string(index=False))
    print('\nFeature sample for android misclassified rows:')
    android_wrong = val[(val['mac_address'] == 'f2:bf:11:4a:79:b6') & (val['predicted_label'] != val['true_label'])]
    print(android_wrong[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'TTL', 'TTL_rounded', 'TCP_WIN', 'TCP_MSS', 'true_label', 'predicted_label', 'confidence']].drop_duplicates().head(20).to_string(index=False))
    print('\nFeature sample for android correct rows:')
    android_correct = val[(val['mac_address'] == 'f2:bf:11:4a:79:b6') & (val['predicted_label'] == val['true_label'])]
    print(android_correct[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'TTL', 'TTL_rounded', 'TCP_WIN', 'TCP_MSS', 'true_label', 'predicted_label', 'confidence']].drop_duplicates().head(20).to_string(index=False))

    print('\nSRC_PORT distribution by MAC:')
    for mac, group in val.groupby('mac_address'):
        print(mac, group['src_port'].value_counts().head(10).to_string())
else:
    print('No trained model or label encoder found in models/')
