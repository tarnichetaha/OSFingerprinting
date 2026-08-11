# OS Fingerprinting

Passive and on-demand OS fingerprinting pipeline backed by SQLite and a small Flask dashboard.

## Layout

`main.py`
Parses a PCAP into the database.

`dashboard/`
Flask UI and API endpoints.

`src/config.py`
Canonical project paths, runtime settings, and shared constants.

`src/database/`
SQLite schema and query helpers.

`src/scripts/`
Capture and inference flows:
- `parsepcap.py` for offline PCAP ingestion
- `live_capture.py` for passive live sniffing
- `active_probe.py` for on-demand active probing
- `predict_pcap.py` for standalone model inference on a capture

`src/model/`
Training and validation scripts for the ML classifier.

`resources/`
Fingerprints, training CSVs, and ground-truth inputs.

`pcaps/`
Capture files consumed by parsing and validation.

## Entry Points

Run the parser:

```bash
python main.py
```

Run the dashboard:

```bash
python dashboard/app.py
```

Run live capture:

```bash
python src/scripts/live_capture.py --iface WiFi
```

## Refactor Notes

The project now resolves database, resource, PCAP, and model artifact paths from `src/config.py` instead of relying on the current working directory. That removes most of the path duplication across entry points and makes the folder structure easier to follow.
