# OS Fingerprinting

Showcase implementation of passive and on-demand OS fingerprinting from
network traffic. The repository is intended for code reading and demonstration
only, not production deployment.

## Public Repository Policy

This repository is released under the terms in [LICENSE](LICENSE). The source
is available for inspection; no permission is granted to use, reproduce, copy,
modify, distribute, or create derivative works without written permission.

Private captures, subnet datasets, SQLite runtime data, and ground-truth files
are intentionally excluded from the repository. The public training dataset
can be obtained directly from
[Zenodo](https://zenodo.org/records/14703490).

The Fingerbank API key is supplied through the `FINGERBANK_API_KEY` environment
variable and is never stored in the repository.

RustScan and Nmap are optional external tools and are not bundled here. Their
license and attribution information is in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

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
Public fingerprint resources only. Training CSVs and ground-truth inputs are local files.

`pcaps/`
Local capture files consumed by parsing and validation; captures are not committed.

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
