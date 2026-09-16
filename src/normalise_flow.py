"""
    normalise_flow.py

    Converts CESNET flow-CSV records into ML-ready features.
    Unlike normalise.py (DHCP/pcap-derived features), this operates on
    pre-computed ipfixprobe flow fields -- no raw packet parsing involved.
"""
import pandas as pd
from pandas.api.types import is_numeric_dtype

NONE_TOKEN = "NONE"

# local1 doesn't have every column subnet1-4 have -- these are missing there
LOCAL_MISSING_COLUMNS = [
    'DST_PORT', 'TCP_WIN_REV', 'PACKETS', 'PACKETS_REV', 'BYTES', 'BYTES_REV',
    'TCP_OPTIONS', 'TCP_OPTIONS_REV', 'DIR_BIT_FIELD', 'FLOW_END_REASON',
    'L3_FLAGS', 'L3_FLAGS_REV', 'TCP_FLAGS', 'TTL_REV'
]

WELL_KNOWN_PORT_MAX = 1024


def normalize_port(port):
    """
    Bucket ports into coarse categories rather than using raw port numbers
    directly -- thousands of unique ephemeral port values would blow up
    cardinality and mostly add noise, not signal.
    """
    if pd.isna(port):
        return NONE_TOKEN
    port = int(port)
    if port < WELL_KNOWN_PORT_MAX:
        return f"WELLKNOWN_{port}"   # keep specific well-known ports (80, 443, 53...) as-is, they carry real signal
    if port < 49152:
        return "REGISTERED"
    return "EPHEMERAL"


def unpack_bitfield(value, n_bits=8, prefix="opt"):
    """
    Generic bitmask unpacking -- each bit becomes its own boolean feature.
    NOTE: exact bit-to-TCP-option mapping is not confirmed from dataset docs.
    If you find the real mapping (e.g. bit0=SACK, bit1=timestamp...), replace
    this with named fields for better interpretability.
    """
    if pd.isna(value):
        value = 0
    value = int(value)
    return {f"{prefix}_bit{i}": (value >> i) & 1 for i in range(n_bits)}


def normalize_protocol(proto):
    if pd.isna(proto):
        return NONE_TOKEN
    return str(int(proto))


def normalize_tcp_flags(flags):
    if pd.isna(flags):
        return NONE_TOKEN
    return str(int(flags))


def normalize_row(row, has_full_columns=True):
    """
    Apply normalizers to a single raw flow record (dict-like, e.g. from
    df.to_dict(orient='records')).
    """
    features = {
        'label':        row.get('OS_LABEL'),

        # Numeric, used directly -- tree models handle raw scale fine
        'tcp_syn_size': row.get('TCP_SYN_SIZE', 0) or 0,
        'tcp_win':      row.get('TCP_WIN', 0) or 0,
        'tcp_mss':      row.get('TCP_MSS', 0) or 0,
        'ttl':          row.get('TTL', 0) or 0,   # dataset already rounds to nearest power of 2

        'src_port_bucket': normalize_port(row.get('SRC_PORT')),
        'protocol':        normalize_protocol(row.get('PROTOCOL')),
    }

    if has_full_columns:
        features.update({
            'dst_port_bucket': normalize_port(row.get('DST_PORT')),
            'tcp_win_rev':     row.get('TCP_WIN_REV', 0) or 0,
            'packets':         row.get('PACKETS', 0) or 0,
            'packets_rev':     row.get('PACKETS_REV', 0) or 0,
            'bytes':           row.get('BYTES', 0) or 0,
            'bytes_rev':       row.get('BYTES_REV', 0) or 0,
            'tcp_flags':       normalize_tcp_flags(row.get('TCP_FLAGS')),
            'ttl_rev':         row.get('TTL_REV', 0) or 0,
        })
        features.update(unpack_bitfield(row.get('TCP_OPTIONS'), prefix="tcpopt"))
        features.update(unpack_bitfield(row.get('TCP_OPTIONS_REV'), prefix="tcpopt_rev"))

    return features


def build_feature_matrix(df_raw, encode=True):
    """
    df_raw: DataFrame from load_flow_csv.load_all_subnets()

    Returns:
        X : DataFrame of features (numeric + factorized categoricals)
        y : Series of labels (OS_LABEL)
        encoders : dict of {column: {category: code}} for categorical columns only
    """
    has_full = 'DST_PORT' in df_raw.columns

    normalized_rows = [normalize_row(r, has_full_columns=has_full)
                       for r in df_raw.to_dict(orient='records')]
    df = pd.DataFrame(normalized_rows)

    y = df['label']
    feature_cols = [c for c in df.columns if c != 'label']
    df_features = df[feature_cols]

    if not encode:
        return df_features, y, None

    categorical_cols = [c for c in feature_cols
                         if not is_numeric_dtype(df_features[c])]
    numeric_cols = [c for c in feature_cols if c not in categorical_cols]

    encoders = {}
    encoded = df_features[numeric_cols].apply(pd.to_numeric, errors='coerce').copy()

    for col in categorical_cols:
        codes, uniques = pd.factorize(df_features[col])
        encoded[col] = codes
        encoders[col] = {val: i for i, val in enumerate(uniques)}

    return encoded, y, encoders


def encode_new_row(raw_row, encoders, has_full_columns=True):
    """Normalize + encode a single new flow record at inference time."""
    normalized = normalize_row(raw_row, has_full_columns=has_full_columns)
    encoded = {}
    for col, val in normalized.items():
        if col == 'label':
            continue
        if col in encoders:
            encoded[col] = encoders[col].get(val, -1)
        else:
            encoded[col] = val
    return encoded