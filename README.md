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




Multi-Role Passive Wi-Fi PCAP Fingerprint Engine
A modular, high-performance Python framework engineered for Ubuntu 24.04 to passively fingerprint, identify, and audit wireless assets entirely from raw packet capture files (`.pcap`).
By evaluating unencrypted 802.11 Management frames (Probe Requests, Beacons, and Probe Responses), this system isolates static layer-2 physical parameters—such as Information Element (IE) sequences, High Throughput (HT) capabilities, and Very High Throughput (VHT) capabilities—to identify specific device manufacturers, types, and models. This multi-layered tracking approach remains highly effective even when devices actively rotate their MAC addresses via aggressive randomisation schemas.
---
🚀 Key Capabilities
Multi-Role Infrastructure Auditing: Captures and classifies Client Devices (`Client-Probe`), Enterprise Access Points (`AP-Beacon`/`AP-Response`), Range Extenders, and Peer Mesh Networks (`AdHoc-Peer`).
Cross-Layer Fingerprinting: Parses IE field sequences, HT/VHT silicon parameters, and proprietary vendor identifiers.
Split System Architecture: Clean operational separation of concerns across a processing parse module and a command-line interface execution layer.
Multi-Model Tracking Framework: Seamlessly aggregates and links multiple distinct device models from a single manufacturer to a matching hardware footprint matrix over time.
Advanced Chipset Anti-Collision: Implements deep vendor flag hashing, plain-text WPS TLV attribute scraping, and Inter-Frame Spacing (IFS) timing metrics to isolate unique devices running identical internal silicon components.
Probabilistic Estimation Matrix: Dynamically scores and ranks overlapping rules based on historical sample ratios to estimate the closest match configuration.
High-Speed Silence Operations: Features a performance optimization engine to disable line-by-line logging, maximizing throughput speeds when diagnosing huge, unfiltered corporate site captures.
Unique Device Roster Analytics: Outputs a consolidated hardware asset register mapping the single highest-confidence identity resolved for every unique MAC address discovered.
---
📂 Project Structure
Maintain both files inside the same operational working directory to preserve dependency imports:
```text
├── fingerprint\_parsers.py  <- Core Layer-2 Processing, MAC validation, \& WPS Scrapers
└── fingerprint\_engine.py   <- CLI Control Logic, Database File I/O, \& Playback Streamers
```
`fingerprint\_parsers.py`: Handles raw bit manipulation, isolates randomized MAC variants from valid hardware burned-in addresses, parses plain-text attributes, and hashes internal vendor flags to break chipset identity ties.
`fingerprint\_engine.py`: Functions as the user-facing execution core, managing command-line inputs, running training datasets, and simulating streams for live classification.
---
🛠 Prerequisites & Installation (Ubuntu 24.04)
Ensure your system packages are updated and install the required wireless utilities and Python library dependencies:
```bash
sudo apt update
sudo apt install python3-pip python3-scapy wireless-tools iw aircrack-ng -y

```
---
📡 Live Environment Setup (Monitor Mode)
To capture raw off-network probe requests natively on Ubuntu 24.04, put your wireless interface into Monitor Mode.
Terminate interfering background processes:
```bash
   sudo airmon-ng check kill
   ```
(Note: Run `sudo systemctl restart NetworkManager` later to restore normal internet connections).
Enable Monitor Mode via `iw`:
```bash
   # Find your interface name (e.g., wlan0)
   iw dev

   # Put the card down, switch modes, and bring it up
   sudo ip link set wlan0 down
   sudo iw wlan0 set monitor control
   sudo ip link set wlan0 up

   # Verify 'type monitor' is now active
   iw dev
   ```
🚀 Usage Guide
1. Simple Playback Classification (Built-in DB)
Run a target packet capture through the script using the default, hardcoded portable knowledge base rules:
```bash
python3 fingerprint\_engine.py --play environmental\_scan.pcap
```
2. Training the Model
To map a new device profile, pass the capture file along with its specific type, manufacturer (make), and model:
```bash
python3 fingerprint\_engine.py \\
  --train sample\_iphone14.pcap \\
  --type "Smartphone" \\
  --make "Apple" \\
  --model "iPhone 14" \\
  --db-export field\_signatures.json
```
3. Appending Multi-Model Variants / Bulk Multi-File Wildcards Over Time
If a newer device uses the same internal wireless chipset configuration, or if you have multiple clean-room files to ingest at once, run the training command with folder wildcards. The script automatically resolves and appends the entries natively:
```bash
python3 fingerprint\_engine.py \\
  --db-import field\_signatures.json \\
  --train captured\_samples/\*.pcap \\
  --type "Smartphone" \\
  --make "Apple" \\
  --model "iPhone 15" \\
  --db-export field\_signatures.json
```
4. Running Playback with an External Database
Execute traffic analysis across your accumulated or transported ruleset matrix:
```bash
python3 fingerprint\_engine.py \\
  --db-import field\_signatures.json \\
  --play crowded\_mall\_capture.pcap
```
5. Running Playback with a Probability Threshold
To filter out statistical noise and drop candidate models whose distribution falls below a certain percentage limit (e.g., hiding device variations making up less than 10.0% of total matched signature samples):
```bash
python3 fingerprint\_engine.py \\
  --db-import field\_signatures.json \\
  --play environmental\_scan.pcap \\
  --threshold 10.0
```
6. High-Speed Silent Playback (Troubleshooting Large Captures)
When auditing large infrastructure site captures containing an overwhelming volume of frame records, use the `--quiet` flag to silence line-by-line log output. This optimizes CPU performance by skipping terminal rendering bottlenecks while preserving comprehensive output logs at the completion of a file scan:
```bash
python3 fingerprint\_engine.py --play troubleshooting\_site\_A.pcap --quiet
```
---
📊 Fingerprint Schema Blueprint
The classification strings generated by this engine are designed to survive MAC layer spoofing by tracking rigid layer-2 physical parameters:
```text
IE:\[0-1-45-127-191-221]\_HT:\[2D04]\_VHT:\[FF010400]\_VENDOR\_FLAGS:\[0017F2010203...]
└───① IE Sequence        └──② HT   └──③ VHT       └──④ Custom Vendor Hash
```
IE Sequence: Driver/Software stack field ordering framework.
HT Capabilities: 802.11n hardware chip parameter limitations.
VHT Capabilities: 802.11ac radio capability/antenna metrics.
Vendor Flags: Hashed proprietary software-defined ecosystem markings embedded directly inside frames.
---
🛠 Contextual Multi-Layer Anti-Collision Hierarchy
To resolve signature overlap caused by multiple vendors deploying identical chipsets, this engine relies on a multi-layer evaluation hierarchy during playback processing:
MAC Address Decoupling: Parses the local/global assignment bit. If a hardware address is valid (not randomized), it extracts the MAC OUI to instantly verify the device manufacturer.
Deep Vendor Hashing (IE 221): Captures and hashes the raw content bytes of manufacturer tags. Different OS stacks configure varying software-defined flags inside matching hardware profiles.
WPS Attribute Scraping: Automatically targets Microsoft WPS attributes (`OUI 00:50:F2:04`) inside the vendor elements. It parses internal data elements to pull plain-text values for `Manufacturer`, `Model Name`, and `Model Number` sent straight by the device firmware.
Statistical Probability Estimation Matrix: If all hardware elements match identically and zero plain-text attributes exist, the engine calculates real-time distribution percentages based on historical training density metrics (`model\_samples`). Conflicting signatures are printed in ranked hierarchy order (e.g., `Model\_A (75.0%) / Model\_B (25.0%)`).
Behavioral Timing (Inter-Frame Spacing): Measures transmission gaps (`IFS`) during traffic playback to flag aggressive automated probing routines compared to static low-power sleep structures.
---
📈 Analysis Report Dashboards
Once a `.pcap` analysis processing phase completes, the console outputs two distinct reporting blocks:
1. Captured Unique Device Roster
A clean hardware inventory map documenting the top-quality profile identity assigned to every individual distinct `MAC Address` spotted over-the-air:
```text
==========================================================================================
                     CAPTURED UNIQUE DEVICE ROSTER BREAKDOWN                 
==========================================================================================
 MAC ADDRESS        | ROLE          | MAC SYSTEM   | RESOLVED IDENTITY MATRIX / PROFILE
------------------------------------------------------------------------------------------
 00:15:99:A2:BC:11  | AP-Beacon     | Valid/HW     | Access-Point (Cisco HW Match)
 4E:C1:28:9F:54:33  | Client-Probe  | Randomized   | Smartphone (Apple -> iPhone 15 (100.0%))
 D2:A4:88:E2:19:0B  | AdHoc-Peer    | Randomized   | Mobile-Mesh-Node (RaspberryPi -> Pi-4-B-AdHoc)
==========================================================================================
```
2. Passive Frame Classification Metrics
A global score tracking system showing how well the capture files map to your trained rules:
```text
==========================================================================================
                 PASSIVE FRAME CLASSIFICATION PERFORMANCE METRICS             
==========================================================================================
 Total Radio Frames Processed : 1245 
 Total Unique MACs Documented : 42   
------------------------------------------------------------------------------------------
 🎯 Definitive Hardware Matches  : 231   (18.6%) \[WPS/OUI Verified]
 📊 Probabilistic Model Matches : 712   (57.2%) \[Matrix Resolved]
 🛑 Low Confidence (Filtered)   : 54    (4.3%)  \[Below Threshold]
 ❓ Completely Untrained Sigs   : 248   (19.9%) \[No DB Entry]
------------------------------------------------------------------------------------------
 OVERALL CAPTURE CLASSIFICATION SUCCESS RATE : 75.74%
==========================================================================================
```
---
💾 Permanent Embedding
To make your newly gathered signatures fully portable without managing independent JSON files, copy the contents of your exported `.json` file and paste it directly into the `PORTABLE\_KNOWLEDGE\_BASE` dictionary block at the top of the `fingerprint\_parsers.py` source code.
