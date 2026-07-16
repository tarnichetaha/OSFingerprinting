# Project Plan — Passive OS Fingerprinting via Network Traffic Analysis

## Goal

Build a **passive network fingerprinting tool** that reads packet captures (PCAP files), identifies all devices on the network, and determines as much information as possible about each device **without sending any active probes**. All extracted data is stored in a local SQLite database for later review.

---

## Approach & Methodology

Passive fingerprinting relies on observing legitimate network traffic and inferring OS / device characteristics from protocol-specific artifacts. This implementation uses **four complementary techniques**:

| # | Technique | Protocol / Field | What It Reveals |
|---|-----------|------------------|-----------------|
| 1 | **TTL Analysis** | IP header TTL field | OS family (Linux / Windows / Network Gear) |
| 2 | **DHCP Fingerprinting** | DHCP Options 55 + 60 | Exact OS via **Fingerbank API** |
| 3 | **Hostname Extraction** | DHCP Option 12 | Device hostname |
| 4 | **HTTP User-Agent** | HTTP `User-Agent` header | Browser / OS hints |

---

## Project Structure

```
OSFingerprinting/
├── main.py                   # Entry point (launches parsing)
├── pyproject.toml            # Project metadata & dependencies
├── requirements              # Dependency list
├── plan.md                   # This file
├── src/
│   ├── models.py             # Device data model
│   ├── config.py             # API keys, thresholds, debug flag
│   ├── parsepcap.py          # PCAP reader & main orchestration loop
│   ├── FPutils.py            # Fingerprinting logic for each technique
│   └── dbutils.py            # SQLite CRUD operations
├── pcaps/                    # Place PCAP files here
├── logs/                     # Debug logs (auto-created)
└── OSFP_db.db                # SQLite database (auto-created)
```

---

## Component Breakdown

### 1. `src/models.py` — Device Data Model

The `Device` class holds every attribute we can learn about a network device:

| Attribute | Meaning | Source |
|-----------|---------|--------|
| `mac_address` | MAC address (primary key) | Ethernet header (src) |
| `is_randomized_mac` | Whether MAC is randomized | 2ⁿᵈ LSB of 1ˢᵗ byte |
| `hostname` | Device hostname | DHCP Option 12 |
| `os_opt55` | OS identified via DHCP fingerprint | Fingerbank API (Opt 55 + 60) |
| `os_ttl` | OS family from TTL | TTL value in IP header |
| `vendor_identity` | Hardware vendor | OUI lookup (planned) |
| `http_user_agent` | HTTP User-Agent string | HTTP payload parsing |
| `ev_*` fields | Evidence / confidence for each value | Tracks how each field was determined |

**Key design decision**: Each data attribute has a parallel `ev_` (evidence) field that records the source and confidence. This preserves the audit trail of *how* we know what we know.

---

### 2. `src/config.py` — Configuration

Centralises all tunable parameters:
- **`URL`** — Fingerbank API endpoint for DHCP fingerprint lookup
- **`API_KEY`** — Authentication key for the Fingerbank API
- **`SCORE_THRESHOLD`** — Minimum confidence score from Fingerbank (if below this, retry without MAC to avoid MAC-based scoring bias)
- **`DEBUG`** — Enables verbose console logging and API response logging to `logs/api_reponses.log`

---

### 3. `src/parsepcap.py` — Orchestration Engine (Core Loop)

This is the heart of the application. The parsing loop:

```
for each packet in PCAP file:
    1. Skip if no Ether/IP layers
    2. Get source MAC address
    3. Lookup/cache Device object (check DB first, then RAM cache)
    4. If randomized MAC → mark it immediately
    5. For TCP packets → TTL analysis + HTTP User-Agent parsing
    6. For DHCP packets → hostname extraction + API fingerprinting
    7. If any data changed → queue for DB update
    8. Flush queue every 100 devices (batch insert for performance)
```

**Performance features:**
- **RAM caching** — Devices are kept in a dictionary (`cached_devices`) to avoid redundant DB reads for repeat MACs
- **Batch DB updates** — Writes are accumulated and flushed every 100 updates using `executemany()`
- **Packet limit** — Currently capped at 200,000 packets for quick iteration during development

---

### 4. `src/FPutils.py` — Fingerprinting Functions

#### 4a. TTL-Based OS Detection (`get_os_from_ttl`)

Uses the initial TTL (or highest observed TTL) to guess the OS family:

| TTL Range | OS / Device Type |
|-----------|-----------------|
| ≤ 64 | **Linux** / Unix / macOS / Android |
| 65–128 | **Windows** (usually 128) |
| > 128 | **Network Gear** (routers, switches — often 255) |

*Limitation: Coarse-grained — can't distinguish between e.g., Ubuntu vs Fedora, or Windows 10 vs Windows 11. This is a fallback when no DHCP or HTTP data is available.*

#### 4b. DHCP Fingerprinting (`get_device_info_from_dhcp_opt`)

Extracts two critical DHCP options and queries the **Fingerbank API**:

- **Option 55 (Parameter Request List)** — This is a list of DHCP option codes the client requests. The **order** of these codes forms a unique fingerprint of the DHCP client implementation, which is often OS-specific.
- **Option 60 (Vendor Class Identifier)** — The client explicitly identifies its vendor/OS type (e.g., `MSFT 5.0` for Windows, `udhcp` for embedded Linux).

These are sent to Fingerbank, which returns:
- **OS name** (e.g., `Windows 10 Pro`, `Ubuntu 22.04`, `Android 14`, `iOS 17.3`)
- **Confidence score** (0–100)
- **Vendor identity**

**Why DHCP can identify exact versions:** The DHCP Parameter Request List (Option 55) is an ordered list of option codes the client requests. Different OS versions request different sets of options in different orders. For example:
- Windows 10 might request: `1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252`
- Windows 11 might request a slightly different set or order
- Android 13 vs Android 14 have different DHCP client implementations with different option request patterns

The Vendor Class Identifier (Option 60) also often contains version strings:
- `MSFT 5.0` → Windows
- `Android-dhcp-14` → Android 14
- `udhcp 1.30.3` → Embedded Linux
- `dhcpcd-5.5.6` → Linux (older)
- `iOS 17.3` → iPhone/iPad

If the score is below the threshold (50) and a MAC was included, the request is retried **without the MAC** to get an unbiased API result.

#### 4c. Hostname Extraction (`get_hostname_from_dhcp`)

Reads DHCP **Option 12 (Host Name)** — the hostname the device sends during DHCP negotiation. This often reveals:
- Device model / manufacturer (e.g., `desktop-ABC123`, `iPhone-de-victor`)
- Username / owner hints (privacy concern)

#### 4d. HTTP User-Agent Parsing (`parse_http_user_agent`)

Scans raw TCP payloads for HTTP request headers and extracts the `User-Agent` field. This provides:
- Browser name and version
- Underlying OS (e.g., `Windows NT 10.0`, `Linux Android 14`)
- Device model (in some cases, e.g., `SM-S24`)

**Version extraction from User-Agent strings:** The raw UA string contains rich version information that can be parsed:

| User-Agent Fragment | OS Version |
|---------------------|------------|
| `Windows NT 10.0` | Windows 10 / 11 |
| `Windows NT 6.1` | Windows 7 |
| `Windows NT 6.2` | Windows 8 |
| `Windows NT 6.3` | Windows 8.1 |
| `Android 14` | Android 14 |
| `Android 13` | Android 13 |
| `Mac OS X 10_15_7` | macOS Catalina (10.15) |
| `Mac OS X 14_0` | macOS Sonoma (14.0) |
| `iPhone OS 17_3` | iOS 17.3 |
| `CrOS x86_64 14588.98.0` | Chrome OS build |

*Note: The current implementation stores the raw UA string but does not yet parse it for structured OS version extraction. This is a planned enhancement.*

#### 4e. Randomized MAC Detection (`is_randomized_mac`)

Checks the **second least significant bit of the first byte** of the MAC address:
- **0** → Universally administered (real) MAC
- **1** → Locally administered (randomized/private) MAC

Randomized MACs are **not sent to Fingerbank** for vendor lookup, avoiding wasted API calls.

---

### 5. `src/dbutils.py` — Database Layer

Uses **SQLite** with a dynamic table-per-PCAP-file strategy (`[filename]` as table name).

**Table schema:**
```sql
CREATE TABLE [pcap_filename] (
    mac_address          TEXT PRIMARY KEY,
    is_randomized_mac    BOOLEAN DEFAULT FALSE,
    hostname             TEXT DEFAULT 'Not Recorded',
    net_config           TEXT DEFAULT 'Not Recorded',
    os                   TEXT DEFAULT 'Not Recorded',
    vendor_identity      TEXT DEFAULT 'Not Recorded',
    ev_hostname          TEXT DEFAULT 'Not Recorded',
    ev_net_config        TEXT DEFAULT 'Not Recorded',
    ev_os                NUMBER DEFAULT -1,
    ev_vendor_identity   TEXT DEFAULT 'Not Recorded',
    http_user_agent      TEXT DEFAULT 'Not Recorded',
    ev_http_user_agent   TEXT DEFAULT 'Not Recorded'
)
```

**Key functions:**
- `add_device_or_update()` — Insert or update a single device (used for targeted updates)
- `add_device_batch()` — Batch insert/update for performance (used during bulk parsing)
- `get_device_by_mac()` — Check if a device already exists in DB
- `get_all_devices()` / `get_all_macs()` — Retrieve data for reporting

---

## Data Flow Summary

```
PCAP File
    │
    ▼
┌─────────────────────────────────────────────┐
│  parse_pcap()                               │
│  ┌───────────────────────────────────────┐  │
│  │  For each packet:                     │  │
│  │  1. Get src MAC → cache Device obj   │  │
│  │  2. If DHCP:                         │  │
│  │     → Extract hostname (Opt 12)      │  │
│  │     → Extract Opt 55 + 60            │  │
│  │     → Call Fingerbank API → OS       │  │
│  │  3. If TCP:                          │  │
│  │     → TTL analysis → OS family       │  │
│  │     → Parse HTTP User-Agent          │  │
│  │  4. Queue for DB update              │  │
│  └───────────────────────────────────────┘  │
└──────────────┬──────────────────────────────┘
               │ batch insert (every 100)
               ▼
┌──────────────────────────────────────────────┐
│  SQLite Database (OSFP_db.db)                  │
│  Table: [pcap_filename]                        │
│  ┌────────────┬──────────┬─────────┬────────┐ │
│  │ mac_addr   │ hostname │ os      │ vendor │ │
│  ├────────────┼──────────┼─────────┼────────┤ │
│  │ AA:BB:...  │ my-pc    │ Windows │ Dell   │ │
│  │ CC:DD:...  │ iphone   │ iOS     │ Apple  │ │
│  └────────────┴──────────┴─────────┴────────┘ │
└──────────────────────────────────────────────────┘
```

---

## Implementation Status

| Step | Status | Description |
|------|--------|-------------|
| TTL-based OS detection | ✅ Done | `get_os_from_ttl()` — coarse OS family |
| DHCP fingerprinting (Opt 55 + 60) | ✅ Done | `get_device_info_from_dhcp_opt()` + Fingerbank API |
| Hostname extraction (Opt 12) | ✅ Done | `get_hostname_from_dhcp()` |
| HTTP User-Agent parsing | ✅ Done | `parse_http_user_agent()` |
| Randomized MAC detection | ✅ Done | `is_randomized_mac()` |
| DB schema & batch writes | ✅ Done | `dbutils.py` with batch inserts |
| Vendor identity from OUI | ❌ Not yet | First 3 bytes of MAC → OUI lookup table |
| Passive live capture | ❌ Not yet | Currently reads PCAP files; could use Scapy's `sniff()` for live traffic |
| Confidence scoring / cross-referencing | ❌ Not yet | Merge TTL, DHCP, and HTTP results into a single confidence-weighted OS verdict |

---

## Version Detection Capabilities — Summary

| Technique | Can detect OS family? | Can detect exact version? | Reliability |
|-----------|----------------------|--------------------------|-------------|
| **TTL Analysis** | ✅ Yes (Linux/Windows/Network Gear) | ❌ No | Low (coarse) |
| **DHCP Fingerprinting (Fingerbank API)** | ✅ Yes | ✅ **Yes** (e.g., "Windows 10 Pro 22H2") | **High** (best method) |
| **HTTP User-Agent** | ✅ Yes | ✅ **Yes** (e.g., "Windows NT 10.0" = Win 10/11) | Medium (user-spoofable) |
| **DHCP Option 60 (Vendor Class ID)** | ✅ Yes | ✅ Sometimes (e.g., "Android-dhcp-14") | Medium (part of Fingerbank query) |

**Current best approach for version detection:** The Fingerbank API (via DHCP Opt 55 + 60) is the most reliable method. It has a large database of DHCP fingerprints mapped to specific OS versions. The HTTP User-Agent is a good secondary source but can be spoofed by the user or altered by privacy-focused browsers.

---

## Next Steps

1. **OUI-based vendor identification** — Build a local lookup table mapping the first 3 MAC bytes (OUI) to manufacturer names, eliminating the need for a redundant Fingerbank API call for vendor identity.
2. **Structured UA parsing** — Add a function to parse the raw User-Agent string and extract structured OS name + version (e.g., `Windows NT 10.0` → `{"os": "Windows", "version": "10/11"}`).
3. **Confidence-weighted OS merging** — When multiple techniques disagree (e.g., TTL says Linux but DHCP says Windows), implement a scoring system to pick the most reliable result (DHCP > HTTP UA > TTL).
4. **Live packet capture** — Extend beyond PCAP files to support real-time sniffing with Scapy's `sniff()`, optionally filtering out the monitoring machine's own traffic.
5. **Reporting / dashboard** — Add a simple CLI or web view to query the database and display the fingerprinting results in a human-readable format.
