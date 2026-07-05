# Passive Off-Network Wi-Fi PCAP Fingerprint Engine

A modular, lightweight, and portable Python engine designed for **Ubuntu 24.04** to passively fingerprint and identify Wi-Fi devices from packet captures (`.pcap`). 

By parsing unencrypted 802.11 Management frames (Probe Requests), this tool extracts unique hardware layer signatures—such as **Information Element (IE) sequences**, **High Throughput (HT) capabilities**, and **Very High Throughput (VHT) capabilities**—to identify specific device manufacturers, types, and models even when aggressive MAC address randomisation is active.

---

## Features
- **Cross-Layer Fingerprinting:** Extracts IE order, HT/VHT chip capabilities, and vendor OUIs.
- **Split Architecture:** Clean separation of concerns with parsing logic separated from the execution core.
- **Multi-Model Tracking:** Links multiple model numbers from a specific manufacturer to a single physical hardware profile over time.
- **Advanced Chipset Anti-Collision:** Combines deep vendor flag hashing, plain-text WPS extraction, and timing analysis to prevent false positives from identical chipsets.
- **Zero-Dependency Portability:** Features an embedded knowledge base inside the script file alongside dynamic JSON import/export controls.
- **Dual Engine Modes:** Supports offline signature training (Make, Type, and Model) and simulated live playback classification.

---

## 📂 Project Architecture

The engine is split across two core files to maintain a clean codebase:

```text
├── fingerprint_parsers.py  <- Core Layer-2 Processing, MAC validation, & WPS Scrapers
└── fingerprint_engine.py   <- CLI Control Logic, Database File I/O, & Playback Streamers
```

*   **`fingerprint_parsers.py`**: Handles the raw bit manipulation, isolates randomized MAC variants from valid hardware burned-in addresses, parses plain-text attributes, and hashes internal vendor flags to break chipset identity ties.
*   **`fingerprint_engine.py`**: Functions as the user-facing execution core, managing command-line inputs, running training datasets, and simulating streams for live classification.

---

## 🛠 Prerequisites & Installation (Ubuntu 24.04)

Ensure your system packages are updated and install the required wireless utilities and Python library dependencies:

```bash
sudo apt update
sudo apt install python3-pip python3-scapy wireless-tools iw iwlwifi-guest-tools -y
```

---

## 📡 Live Environment Setup (Monitor Mode)

To capture raw off-network probe requests natively on Ubuntu 24.04, put your wireless interface into **Monitor Mode**.

1. **Terminate interfering background processes:**
   ```bash
   sudo airmon-ng check kill
   ```
   *(Note: Run `sudo systemctl restart NetworkManager` later to restore normal internet connections).*

2. **Enable Monitor Mode via `iw`:**
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

---

## 🚀 Usage Guide

### 1. Simple Playback Classification (Built-in DB)
Run a target packet capture through the script using the default, hardcoded portable knowledge base rules:
```bash
python3 fingerprint_engine.py --play environmental_scan.pcap
```

### 2. Training the Model
To map a new device profile, pass the capture file along with its specific type, manufacturer (make), and model:
```bash
python3 fingerprint_engine.py \
  --train sample_iphone14.pcap \
  --type "Smartphone" \
  --make "Apple" \
  --model "iPhone 14" \
  --db-export field_signatures.json
```

### 3. Appending Multi-Model Variants Over Time
If a newer device uses the same internal wireless chipset configuration, train it again with the same `--type` and `--make` but a different `--model` name. The script automatically appends the model to the existing signature array:
```bash
python3 fingerprint_engine.py \
  --db-import field_signatures.json \
  --train sample_iphone15.pcap \
  --type "Smartphone" \
  --make "Apple" \
  --model "iPhone 15" \
  --db-export field_signatures.json
```

### 4. Running Playback with an External Database
Execute traffic analysis across your accumulated or transported ruleset matrix:
```bash
python3 fingerprint_engine.py \
  --db-import field_signatures.json \
  --play crowded_mall_capture.pcap
```

---

## 🛠 Anti-Collision & Context Filtering

To resolve signature overlap caused by multiple vendors using identical Wi-Fi chipsets, this engine uses a multi-layer contextual evaluation strategy during playback:

1. **MAC Address Decoupling:** Parses the local/global assignment bit. If a hardware address is valid (not randomized), it extracts the MAC OUI to instantly verify the device manufacturer.
2. **Deep Vendor Hashing (IE 221):** Captures and hashes the raw content bytes of manufacturer tags. Different OS stacks configure varying software-defined flags inside matching hardware profiles.
3. **WPS Data Extraction:** Automatically targets Microsoft WPS attributes (`OUI 00:50:F2:04`) inside the vendor elements. It parses internal data elements to pull plain-text values for `Manufacturer`, `Model Name`, and `Model Number` sent straight by the device firmware.
4. **Behavioral Timing (Inter-Frame Spacing):** Measures transmission gaps (`IFS`) during traffic playback to flag aggressive automated probing routines compared to static low-power sleep structures.

---

## 📊 Fingerprint Schema Blueprint

The classification strings generated by this engine are designed to survive MAC layer spoofing by tracking rigid layer-2 physical parameters:

```text
IE:[0-1-45-127-191-221]_HT:[2D04]_VHT:[FF010400]_VENDOR_FLAGS:[0017F2010203...]
└───① IE Sequence        └──② HT   └──③ VHT       └──④ Custom Vendor Hash
```

1. **IE Sequence:** Driver/Software stack field ordering framework.
2. **HT Capabilities:** 802.11n hardware chip parameter limitations.
3. **VHT Capabilities:** 802.11ac radio capability/antenna metrics.
4. **Vendor Flags:** Hashed proprietary software-defined ecosystem markings embedded directly inside frames.

---

## 💾 Permanent Embedding
To make your newly gathered signatures fully portable without managing independent JSON files, copy the contents of your exported `.json` file and paste it directly into the `PORTABLE_KNOWLEDGE_BASE` dictionary block at the top of the `fingerprint_parsers.py` source code.
