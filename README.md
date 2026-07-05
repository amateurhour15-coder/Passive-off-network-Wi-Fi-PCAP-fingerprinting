# Multi-Role Passive Wi-Fi PCAP Fingerprinting Toolkit

A Python toolkit for **passive off-network Wi-Fi fingerprinting** from `.pcap` captures.

The project now includes:
- `fingerprint_parsers.py` — low-level 802.11 frame parsing and fingerprint generation
- `fingerprint_engine.py` — train/playback CLI for classification and metrics
- `extract_training_data.py` — automated training-data extraction from multi-device captures using WPS grouping

---

## Project Structure

```text
├── README.md
├── fingerprint_parsers.py
├── fingerprint_engine.py
└── extract_training_data.py
```

---

## What Each File Does

### `fingerprint_parsers.py`
Core parser and fingerprint builder.

Highlights:
- Parses 802.11 management frames from Scapy (`Dot11`/`Dot11Elt`)
- Classifies frame role as:
  - `Client-Probe` (subtype 4)
  - `AP-Beacon` (subtype 0)
  - `AP-Response` (subtype 5)
  - `AdHoc-Peer` (when IBSS capability bit is set)
- Builds fingerprint strings from:
  - IE sequence
  - HT capabilities
  - VHT capabilities
  - Vendor IE payload hash
- Extracts WPS metadata from vendor IE (`00:50:F2:04`) when present
- Flags transmitter MAC as randomized vs hardware/valid
- Provides embedded default `PORTABLE_KNOWLEDGE_BASE`

---

### `fingerprint_engine.py`
Main CLI for manual training and playback classification.

Features:
- Training from one or more PCAP files (supports wildcards via `glob`)
- Playback/classification against in-memory or imported JSON DB
- Optional DB import/export (`--db-import`, `--db-export`)
- Probability thresholding (`--threshold`) for low-confidence filtering
- Quiet mode (`--quiet`) to suppress per-frame output
- Metrics and unique-device roster summaries

Classification behavior:
- **Definitive** match when captured WPS fingerprint matches stored WPS data
- **Probabilistic** match via `model_samples` distribution
- **Filtered** when below threshold
- **Unknown** when no fingerprint hash exists in DB

---

### `extract_training_data.py` (new)
Automated extractor for building/expanding a training database from mixed-device captures.

What it does:
- Reads packets and fingerprints using `generate_fingerprint_string`
- Groups frames by WPS identity tuple: `make|model_name|model_num`
- Tracks per-device:
  - MAC addresses
  - network roles
  - fingerprint counts
  - total frame counts
- Applies a minimum frame threshold (`--min-frames`, default `5`)
- Writes output in the DB format used by `fingerprint_engine.py`
- Supports appending into an existing DB (`--append`)

Notes:
- Frames without WPS data are counted and reported, but cannot be auto-grouped by device identity
- By default it prevents accidental overwrite unless `--append` is provided

---

## Installation

Tested on Ubuntu 24.04.

```bash
sudo apt update
sudo apt install -y python3-pip python3-scapy wireless-tools iw aircrack-ng
```

---

## Usage

## 1) Manual training with `fingerprint_engine.py`

```bash
python3 fingerprint_engine.py \
  --train samples/device1.pcap \
  --type "Smartphone" \
  --make "Apple" \
  --model "iPhone 15" \
  --db-export trained_db.json
```

Train with multiple files/wildcards:

```bash
python3 fingerprint_engine.py \
  --train samples/*.pcap \
  --type "Smartphone" \
  --make "Apple" \
  --model "iPhone 15" \
  --db-import trained_db.json \
  --db-export trained_db.json
```

## 2) Playback/classification

Use embedded database only:

```bash
python3 fingerprint_engine.py --play capture.pcap
```

Use external database:

```bash
python3 fingerprint_engine.py \
  --db-import trained_db.json \
  --play capture.pcap
```

Playback with probability threshold and quiet mode:

```bash
python3 fingerprint_engine.py \
  --db-import trained_db.json \
  --play capture.pcap \
  --threshold 10.0 \
  --quiet
```

## 3) Automated extraction with `extract_training_data.py`

Create a new training DB from a multi-device capture:

```bash
python3 extract_training_data.py capture_multi_device.pcap -o trained_db.json
```

Require more frames per detected device:

```bash
python3 extract_training_data.py capture_multi_device.pcap \
  -o trained_db.json \
  --min-frames 20
```

Append extracted data to an existing DB:

```bash
python3 extract_training_data.py capture_new_site.pcap \
  -o trained_db.json \
  --append
```

---

## Data Model (DB JSON)

Fingerprint keys map to entries like:

```json
{
  "IE:[...]_HT:[...]_VHT:[...]_VENDOR_FLAGS:[...]": {
    "network_role": "Client-Probe",
    "device_type": "Smartphone",
    "make": "Apple",
    "model_samples": {
      "iPhone 15": 120
    },
    "wps_fingerprints": [
      "{'wps_make': 'Apple', 'wps_model_name': 'iPhone', 'wps_model_num': 'Axxxx'}"
    ]
  }
}
```

---

## Typical Workflow

1. Capture traffic into `.pcap` files.
2. Build/expand DB using either:
   - manual labeling with `fingerprint_engine.py --train`, or
   - auto-grouping with `extract_training_data.py`.
3. Run playback classification with `fingerprint_engine.py --play`.
4. Tune `--threshold` for stricter output in noisy environments.

---

## Legal / Ethical Use

Use only on networks and environments where you have explicit authorization to collect and analyze traffic. Ensure compliance with local laws, policies, and privacy requirements.
