import sqlite3 as sql
import json
import uuid
import re
from datetime import datetime, timezone
from config import DATABASE_PATH, DB_DEBUG
from database.models import Device, Evidence

DEVICE_COLUMNS = [
    "mac_address", "mac_oui", "vendor_name", "hostname",
    "first_seen", "last_seen", "ip_address_current",
    "inferred_os_family", "inferred_os_version", "inferred_device_type",
    "inferred_manufacturer", "inferred_model",
    "confidence_os_family", "confidence_os_version", "confidence_device_type",
    "source",
]

EVIDENCE_COLUMNS = [
    "evidence_id", "mac_address", "signal_type", "raw_data",
    "matched_signature", "match_confidence", "observed_at", "source",
]

LEGACY_DEVICE_COLUMNS = ("confidence_manufacturer", "confidence_model")


def get_connection():
    return sql.connect(DATABASE_PATH)


def get_cursor(conn):
    return conn.cursor()


def close_connection(conn):
    conn.close()


def execute_query(conn, query, params=None, commit=None):
    cur = get_cursor(conn)
    if DB_DEBUG:
        print('=' * 150)
        print(f'In db connection: {conn}'
              f'Executing query: {query}'
              f'params: {params}')
        print('=' * 150)
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)

    if commit is None:
        stmt = query.lstrip().upper()
        commit = not stmt.startswith(("SELECT", "PRAGMA", "WITH", "EXPLAIN"))
    if commit:
        conn.commit()
    return cur


def create_tables():
    conn = get_connection()
    cur = get_cursor(conn)

    cur.execute(
        "CREATE TABLE IF NOT EXISTS sources ("
        "source_name    TEXT PRIMARY KEY, "
        "source_type    TEXT, "          # 'pcap' | 'live'
        "first_seen     TIMESTAMP, "
        "last_seen      TIMESTAMP, "
        "packet_count   INTEGER DEFAULT 0, "
        "evidence_count INTEGER DEFAULT 0"
        ")"
    )

    cur.execute(
        "CREATE TABLE IF NOT EXISTS devices ("
        "mac_address            TEXT PRIMARY KEY, "
        "mac_oui                TEXT, "
        "vendor_name            TEXT DEFAULT 'Not Recorded', "
        "hostname               TEXT DEFAULT 'Not Recorded', "
        "first_seen             TIMESTAMP, "
        "last_seen              TIMESTAMP, "
        "ip_address_current     TEXT, "
        "inferred_os_family     TEXT DEFAULT 'Not Recorded', "
        "inferred_os_version    TEXT DEFAULT 'Not Recorded', "
        "inferred_device_type   TEXT DEFAULT 'Not Recorded', "
        "inferred_manufacturer  TEXT DEFAULT 'Not Recorded', "
        "inferred_model         TEXT DEFAULT 'Not Recorded', "
        "confidence_os_family   REAL DEFAULT 0.0, "
        "confidence_os_version  REAL DEFAULT 0.0, "
        "confidence_device_type REAL DEFAULT 0.0, "
        "source                 TEXT"
        ")"
    )

    cur.execute(
        "CREATE TABLE IF NOT EXISTS evidence ("
        "evidence_id        TEXT, "
        "mac_address        TEXT NOT NULL, "
        "signal_type        TEXT NOT NULL, "
        "raw_data           TEXT, "
        "matched_signature  TEXT, "
        "match_confidence   REAL, "
        "observed_at        TIMESTAMP, "
        "source             TEXT, "
        "FOREIGN KEY (mac_address) REFERENCES devices (mac_address), "
        "UNIQUE (mac_address, signal_type, source)"
        ")"
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_mac ON evidence (mac_address)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_source ON evidence (source)")

    # Best-effort schema cleanup for legacy device confidence columns removed from the model.
    for col_name in LEGACY_DEVICE_COLUMNS:
        try:
            cur.execute(f"ALTER TABLE devices DROP COLUMN {col_name}")
        except sql.OperationalError:
            # Column might not exist, or SQLite build may not support DROP COLUMN.
            pass

    conn.commit()
    close_connection(conn)


# ---------- sources ----------

def register_source(source_name: str, source_type: str):
    """Insert or touch a sources row. Call once at start of each parse/capture session."""
    conn = get_connection()
    now = datetime.now(timezone.utc)
    execute_query(
        conn,
        "INSERT INTO sources (source_name, source_type, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(source_name) DO UPDATE SET last_seen=excluded.last_seen",
        (source_name, source_type, now, now),
    )
    close_connection(conn)


def update_source_stats(source_name: str, packet_delta: int = 0, evidence_delta: int = 0):
    """Increment packet/evidence counters for a source and refresh last_seen."""
    conn = get_connection()
    now = datetime.now(timezone.utc)
    execute_query(
        conn,
        "UPDATE sources SET "
        "packet_count   = packet_count   + ?, "
        "evidence_count = evidence_count + ?, "
        "last_seen      = ? "
        "WHERE source_name = ?",
        (packet_delta, evidence_delta, now, source_name),
    )
    close_connection(conn)


def get_all_sources() -> list[dict]:
    """Return all sources rows as dicts."""
    conn = get_connection()
    cur = execute_query(conn, "SELECT source_name, source_type, first_seen, last_seen, packet_count, evidence_count FROM sources ORDER BY last_seen DESC")
    rows = cur.fetchall()
    close_connection(conn)
    keys = ["source_name", "source_type", "first_seen", "last_seen", "packet_count", "evidence_count"]
    return [dict(zip(keys, row)) for row in rows]


def get_source_summary(source_name: str) -> dict:
    """Aggregate stats for one source: device count, signal type breakdown, OS family distribution."""
    conn = get_connection()

    # Base source row
    cur = execute_query(
        conn,
        "SELECT source_name, source_type, first_seen, last_seen, packet_count, evidence_count "
        "FROM sources WHERE source_name = ?",
        (source_name,),
    )
    row = cur.fetchone()
    if not row:
        close_connection(conn)
        return {}
    summary = {
        "source_name": row[0], "source_type": row[1],
        "first_seen": row[2], "last_seen": row[3],
        "packet_count": row[4], "evidence_count": row[5],
    }

    # Device count
    cur = execute_query(conn, "SELECT COUNT(DISTINCT mac_address) FROM evidence WHERE source = ?", (source_name,))
    summary["device_count"] = cur.fetchone()[0]

    # Signal type breakdown  {signal_type: count}
    cur = execute_query(
        conn,
        "SELECT signal_type, COUNT(*) FROM evidence WHERE source = ? GROUP BY signal_type ORDER BY COUNT(*) DESC",
        (source_name,),
    )
    summary["signal_type_counts"] = {r[0]: r[1] for r in cur.fetchall()}

    # OS family distribution across devices seen in this source
    cur = execute_query(
        conn,
        "SELECT d.inferred_os_family, COUNT(*) "
        "FROM devices d "
        "INNER JOIN evidence e ON e.mac_address = d.mac_address "
        "WHERE e.source = ? "
        "GROUP BY d.inferred_os_family ORDER BY COUNT(*) DESC",
        (source_name,),
    )
    summary["os_distribution"] = {r[0]: r[1] for r in cur.fetchall()}

    close_connection(conn)
    return summary


# ---------- devices ----------

def _device_to_params(device):
    return tuple(getattr(device, col) for col in DEVICE_COLUMNS)


def upsert_device(device):
    conn = get_connection()
    placeholders = ", ".join("?" for _ in DEVICE_COLUMNS)
    update_clause = ", ".join(
        f"{col}=excluded.{col}" for col in DEVICE_COLUMNS
        if col not in ("mac_address", "first_seen")   # never overwrite these on conflict
    )
    query = (
        f"INSERT INTO devices ({', '.join(DEVICE_COLUMNS)}) VALUES ({placeholders}) "
        f"ON CONFLICT(mac_address) DO UPDATE SET {update_clause}"
    )
    execute_query(conn, query, _device_to_params(device))
    close_connection(conn)


def upsert_device_batch(devices):
    if not devices:
        return
    conn = get_connection()
    placeholders = ", ".join("?" for _ in DEVICE_COLUMNS)
    update_clause = ", ".join(
        f"{col}=excluded.{col}" for col in DEVICE_COLUMNS
        if col not in ("mac_address", "first_seen")
    )
    query = (
        f"INSERT INTO devices ({', '.join(DEVICE_COLUMNS)}) VALUES ({placeholders}) "
        f"ON CONFLICT(mac_address) DO UPDATE SET {update_clause}"
    )
    cur = get_cursor(conn)
    cur.executemany(query, [_device_to_params(d) for d in devices])
    conn.commit()
    close_connection(conn)


def get_all_devices():
    conn = get_connection()
    cur = execute_query(conn, f"SELECT {', '.join(DEVICE_COLUMNS)} FROM devices")
    rows = cur.fetchall()
    close_connection(conn)
    return [Device(*row) for row in rows]


def get_all_macs():
    conn = get_connection()
    cur = execute_query(conn, "SELECT mac_address FROM devices")
    macs = [row[0] for row in cur.fetchall()]
    close_connection(conn)
    return macs


def get_device_by_mac(mac_address, include_evidence: bool = True):
    conn = get_connection()
    cur = execute_query(
        conn, f"SELECT {', '.join(DEVICE_COLUMNS)} FROM devices WHERE mac_address = ?", (mac_address,)
    )
    row = cur.fetchone()
    close_connection(conn)
    if not row:
        return None
    device = Device(*row)
    if include_evidence:
        device.evidence = get_evidence_for_device(mac_address)
    return device


def get_devices_by_source(source_name: str) -> list:
    """Return Device objects for all MACs that have at least one evidence row from source_name."""
    conn = get_connection()
    cur = execute_query(
        conn,
        f"SELECT DISTINCT {', '.join('d.' + c for c in DEVICE_COLUMNS)} "
        "FROM devices d "
        "INNER JOIN evidence e ON e.mac_address = d.mac_address "
        "WHERE e.source = ?",
        (source_name,),
    )
    rows = cur.fetchall()
    close_connection(conn)
    return [Device(*row) for row in rows]


# ---------- evidence ----------

def add_evidence(mac_address, signal_type, raw_data, matched_signature=None,
                 match_confidence=None, source: str | None = None, observed_at=None):
    """One row per (mac_address, signal_type, source) — upserts in place on conflict."""
    conn = get_connection()
    query = (
        f"INSERT INTO evidence ({', '.join(EVIDENCE_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in EVIDENCE_COLUMNS)}) "
        "ON CONFLICT(mac_address, signal_type, source) DO UPDATE SET "
        "raw_data=excluded.raw_data, "
        "matched_signature=excluded.matched_signature, "
        "match_confidence=excluded.match_confidence, "
        "observed_at=excluded.observed_at"
    )
    params = (
        str(uuid.uuid4()), mac_address, signal_type, json.dumps(raw_data),
        matched_signature, match_confidence, observed_at or datetime.now(timezone.utc), source,
    )
    execute_query(conn, query, params)
    close_connection(conn)

    update_device_from_evidence(mac_address)


def get_evidence_for_device(mac_address):
    conn = get_connection()
    cur = execute_query(
        conn,
        f"SELECT {', '.join(EVIDENCE_COLUMNS)} FROM evidence WHERE mac_address = ? ORDER BY observed_at",
        (mac_address,),
    )
    rows = cur.fetchall()
    close_connection(conn)
    result = []
    for row in rows:
        d = dict(zip(EVIDENCE_COLUMNS, row))
        d["raw_data"] = json.loads(d["raw_data"]) if d["raw_data"] else {}
        result.append(Evidence(**{k: v for k, v in d.items() if k != "source"}))
    return result


def get_evidence_by_source(source_name: str) -> list:
    """Return all evidence rows tagged with source_name."""
    conn = get_connection()
    cur = execute_query(
        conn,
        f"SELECT {', '.join(EVIDENCE_COLUMNS)} FROM evidence WHERE source = ? ORDER BY observed_at DESC",
        (source_name,),
    )
    rows = cur.fetchall()
    close_connection(conn)
    result = []
    for row in rows:
        d = dict(zip(EVIDENCE_COLUMNS, row))
        d["raw_data"] = json.loads(d["raw_data"]) if d["raw_data"] else {}
        result.append(Evidence(**{k: v for k, v in d.items() if k != "source"}))
    return result


def get_evidence_by_signal_type(mac_address, signal_type):
    """Convenience filter — scoring engine will want this a lot."""
    conn = get_connection()
    cur = execute_query(
        conn,
        f"SELECT {', '.join(EVIDENCE_COLUMNS)} FROM evidence "
        "WHERE mac_address = ? AND signal_type = ? ORDER BY observed_at",
        (mac_address, signal_type),
    )
    rows = cur.fetchall()
    close_connection(conn)
    result = []
    for row in rows:
        d = dict(zip(EVIDENCE_COLUMNS, row))
        d["raw_data"] = json.loads(d["raw_data"]) if d["raw_data"] else {}
        result.append(Evidence(**{k: v for k, v in d.items() if k != "source"}))
    return result


# ---------- aggregation hook ----------

def _coerce_text(value):
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _score_device_from_evidence(mac_address, all_evidence, source=None):
    """Minimal, deterministic evidence scorer used to hydrate the device row."""
    existing = get_device_by_mac(mac_address, include_evidence=False)
    now = datetime.now(timezone.utc)

    device = existing or Device(mac_address=mac_address, first_seen=now)
    device.last_seen = now
    device.mac_oui = mac_address[:8].upper().replace(':', '-') if mac_address else None
    if source and not device.source:
        device.source = source

    hostname = None
    vendor_hint = None
    os_hint = None
    os_version = None
    device_type = None
    manufacturer = None
    model = None
    latest_ip = None
    os_conf = 0.0
    conf_device_type = 0.0

    for evidence in all_evidence:
        raw = evidence.raw_data or {}

        # Capture latest IP address (prefer non-zero IP over 0.0.0.0)
        if isinstance(raw, dict) and "ip_address" in raw and raw["ip_address"]:
            ip_val = str(raw["ip_address"]).strip()
            if ip_val != "0.0.0.0":
                latest_ip = ip_val
            elif not latest_ip:
                latest_ip = ip_val

        if evidence.signal_type == "dhcp":
            hostname_candidate = _coerce_text(raw.get("hostname"))
            if hostname_candidate:
                hostname = hostname_candidate

            vendor_class = _coerce_text(raw.get("option_60_vendor_class"))
            if vendor_class:
                vendor_hint = vendor_class
                vendor_class_lower = vendor_class.lower()
                if "android" in vendor_class_lower:
                    manufacturer = "Google"
                    device_type = "Mobile"
                    os_hint = os_hint or "Android"
                    ver_match = re.search(r"android-dhcp-(\d+)", vendor_class_lower)
                    if ver_match:
                        os_version = ver_match.group(1)
                elif "iphone" in vendor_class_lower or "ipad" in vendor_class_lower:
                    manufacturer = "Apple"
                    device_type = "Mobile"
                    os_hint = os_hint or "iOS"
                elif "msft" in vendor_class_lower or "windows" in vendor_class_lower:
                    manufacturer = "Microsoft"
                    device_type = "Computer"
                    os_hint = os_hint or "Windows"
                    if "msft 5.0" in vendor_class_lower:
                        os_version = os_version or "10/11"
                elif "linux" in vendor_class_lower or "udhcp" in vendor_class_lower:
                    manufacturer = "Linux Vendor"
                    device_type = "Embedded"
                    os_hint = os_hint or "Linux"

        elif evidence.signal_type == "tcp_ip" and evidence.matched_signature:
            os_hint = evidence.matched_signature
            if evidence.match_confidence is not None:
                os_conf = float(evidence.match_confidence)

        elif evidence.signal_type == "http":
            user_agent = _coerce_text(raw.get("user_agent"))
            if user_agent:
                user_agent_lower = user_agent.lower()
                if "android" in user_agent_lower:
                    device_type = "Mobile"
                    manufacturer = manufacturer or "Google"
                    os_hint = os_hint or "Android"
                    ver_match = re.search(r"android\s+([0-9\.]+)", user_agent_lower)
                    if ver_match:
                        os_version = ver_match.group(1)
                elif "iphone" in user_agent_lower or "ipad" in user_agent_lower:
                    device_type = "Mobile"
                    manufacturer = manufacturer or "Apple"
                    os_hint = os_hint or "iOS"
                    ver_match = re.search(r"os\s+([0-9_]+)", user_agent_lower)
                    if ver_match:
                        os_version = ver_match.group(1).replace("_", ".")
                elif "windows" in user_agent_lower:
                    device_type = device_type or "Computer"
                    manufacturer = manufacturer or "Microsoft"
                    os_hint = os_hint or "Windows"
                    if "windows nt 10.0" in user_agent_lower:
                        os_version = "10/11"
                    elif "windows nt 6.1" in user_agent_lower:
                        os_version = "7"

                model_match = re.search(r"(?:SM-|iPhone|iPad|Pixel|A[0-9]+|MacBook|Surface)", user_agent, re.I)
                if model_match:
                    model = model_match.group(0)

        elif evidence.signal_type == "active_os_probe":
            # Highest-trust signal — nmap active OS scan.
            if evidence.matched_signature and evidence.match_confidence is not None:
                os_hint = evidence.matched_signature
                os_conf = max(os_conf, float(evidence.match_confidence))

        elif evidence.signal_type == "active_port_scan":
            # Port-based device type inference from nmap open port list.
            if evidence.matched_signature and evidence.match_confidence is not None:
                conf = float(evidence.match_confidence)
                if conf > conf_device_type:
                    device_type = evidence.matched_signature
                    conf_device_type = conf

    if latest_ip:
        device.ip_address_current = latest_ip
    if hostname:
        device.hostname = hostname
    if vendor_hint:
        device.vendor_name = vendor_hint
    if os_hint:
        device.inferred_os_family = os_hint.capitalize() if os_hint.islower() else os_hint
        if os_conf > 0.0:
            device.confidence_os_family = round(os_conf, 4)
    if os_version:
        device.inferred_os_version = os_version
        device.confidence_os_version = 0.85
    if device_type:
        device.inferred_device_type = device_type
        if conf_device_type > 0.0:
            device.confidence_device_type = round(conf_device_type, 4)
    if manufacturer:
        device.inferred_manufacturer = manufacturer
    if model:
        device.inferred_model = model

    # Keep the device row from being "Not Recorded" when we clearly saw structured evidence.
    if device.hostname == "Not Recorded":
        device.hostname = "Unknown"
    if device.inferred_os_family == "Not Recorded" and os_hint is None:
        device.inferred_os_family = "Unknown"
    if device.inferred_device_type == "Not Recorded" and device_type is None:
        device.inferred_device_type = "Unknown"

    return device


def update_device_from_evidence(mac_address, source=None):
    """Recompute one device row from all evidence for this MAC and upsert the result."""
    all_evidence = get_evidence_for_device(mac_address)
    if not all_evidence:
        return

    device = _score_device_from_evidence(mac_address, all_evidence, source=source)
    upsert_device(device)


def add_evidence_batch(evidence_list, source: str | None = None):
    """Bulk upsert — one row per (mac_address, signal_type, source). Does NOT trigger device recomputation; caller recomputes after."""
    if not evidence_list:
        return
    conn = get_connection()
    fallback_observed_at = datetime.now(timezone.utc)
    query = (
        f"INSERT INTO evidence ({', '.join(EVIDENCE_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in EVIDENCE_COLUMNS)}) "
        "ON CONFLICT(mac_address, signal_type, source) DO UPDATE SET "
        "raw_data=excluded.raw_data, "
        "matched_signature=excluded.matched_signature, "
        "match_confidence=excluded.match_confidence, "
        "observed_at=excluded.observed_at"
    )
    params_list = [
        (
            str(uuid.uuid4()), e.mac_address, e.signal_type, json.dumps(e.raw_data),
            e.matched_signature, e.match_confidence, e.observed_at or fallback_observed_at,
            source,
        )
        for e in evidence_list
    ]
    cur = get_cursor(conn)
    cur.executemany(query, params_list)
    conn.commit()
    close_connection(conn)


def update_devices_from_evidence(mac_addresses, source=None):
    """Batch version — recompute once per MAC touched in this batch."""
    unique_macs = mac_addresses if isinstance(mac_addresses, set) else set(mac_addresses)
    for mac in unique_macs:
        update_device_from_evidence(mac, source=source)


def get_recent_evidence(limit: int = 50) -> list:
    """Return the most recent evidence rows across all devices, newest first."""
    conn = get_connection()
    cur = execute_query(
        conn,
        f"SELECT {', '.join(EVIDENCE_COLUMNS)} FROM evidence ORDER BY observed_at DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    close_connection(conn)
    result = []
    for row in rows:
        d = dict(zip(EVIDENCE_COLUMNS, row))
        d["raw_data"] = json.loads(d["raw_data"]) if d["raw_data"] else {}
        result.append(Evidence(**{k: v for k, v in d.items() if k != "source"}))
    return result


def main():
    create_tables()


if __name__ == "__main__":
    main()