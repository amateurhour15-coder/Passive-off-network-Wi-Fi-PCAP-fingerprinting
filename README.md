# Passive Off-Network Wi-Fi PCAP Fingerprint Engine

A modular, high-performance Python framework designed for **Ubuntu 24.04** to passively fingerprint, identify, and audit Wi-Fi devices entirely from raw packet capture files (`.pcap`).

By evaluating unencrypted 802.11 Management frames (Probe Requests), this system isolates static layer-2 physical parameters—such as **Information Element (IE) sequences**, **High Throughput (HT) capabilities**, and **Very High Throughput (VHT) capabilities**—to identify specific device manufacturers, types, and models. This multi-layered tracking approach remains highly effective even when devices actively rotate their MAC addresses via aggressive randomisation schemas.

---

## 🚀 Key Capabilities
- **Cross-Layer Fingerprinting:** Parses IE field sequences, HT/VHT silicon parameters, and proprietary vendor identifiers.
- **Split System Architecture:** Clean operational separation of concerns across a processing parse module and a command-line interface execution layer.
- **Multi-Model Tracking Framework:** Seamlessly aggregates and links multiple distinct device models from a single manufacturer to a matching hardware footprint matrix over time.
- **Advanced Chipset Anti-Collision:** Implements deep vendor flag hashing, plain-text WPS TLV attribute scraping, and Inter-Frame Spacing (IFS) timing metrics to isolate unique devices running identical internal silicon components.
- **Probabilistic Estimation Matrix:** Dynamically scores and ranks overlapping rules based on historical sample ratios to estimate the closest match configuration.
- **High-Speed Silence Operations:** Features a performance optimization engine to disable line-by-line logging, maximizing throughput speeds when diagnosing huge, unfiltered corporate site captures.
- **Unique Device Roster Analytics:** Outputs a consolidated hardware asset register mapping the single highest-confidence identity resolved for every unique MAC address discovered.

---

## 📂 Project Structure

Maintain both files inside the same operational working directory to preserve dependency imports:

```text
├── fingerprint_parsers.py   iPhone 15 (100.0%))   
 D2:A4:88:E2:19:0B  | Randomized   | Unknown Device Signature                   
================================================================================
```

### 2. Passive Frame Classification Metrics
A global score tracking system showing how well the capture files map to your trained rules:
```text
================================================================================
