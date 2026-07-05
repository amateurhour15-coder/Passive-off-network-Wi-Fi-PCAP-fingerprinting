#!/usr/bin/env python3
"""
Automated Training Data Extraction Tool
Extracts device fingerprints from multi-device PCAP files using WPS identification
"""

import sys
import os
import json
import argparse
from collections import defaultdict
from scapy.all import PcapReader

from fingerprint_parsers import generate_fingerprint_string

class DeviceGroup:
    """Represents a group of frames from the same physical device."""
    
    def __init__(self, wps_make=None, wps_model=None, wps_model_num=None):
        self.wps_make = wps_make or "Unknown"
        self.wps_model = wps_model or "Unknown"
        self.wps_model_num = wps_model_num or "Unknown"
        self.fingerprints = defaultdict(int)
        self.mac_addresses = set()
        self.network_roles = set()
        self.total_frames = 0
    
    def add_fingerprint(self, fp_hash, mac_address, network_role):
        """Add a fingerprint to this device group."""
        self.fingerprints[fp_hash] += 1
        self.mac_addresses.add(mac_address)
        self.network_roles.add(network_role)
        self.total_frames += 1
    
    def get_device_name(self):
        """Generate a device name from WPS data."""
        if self.wps_model_num and self.wps_model_num != "Unknown":
            return f"{self.wps_make} {self.wps_model_num}"
        elif self.wps_model and self.wps_model != "Unknown":
            return f"{self.wps_make} {self.wps_model}"
        else:
            return f"{self.wps_make} Device"
    
    def to_training_entry(self):
        """Convert to training database entry format."""
        device_name = self.get_device_name()
        
        # Determine device type based on network roles
        if "AP-Beacon" in self.network_roles or "AP-Response" in self.network_roles:
            device_type = "Access-Point"
        else:
            device_type = "Client"
        
        # Build model samples dict with fingerprint counts
        model_samples = {}
        for fp_hash, count in self.fingerprints.items():
            model_samples[device_name] = count
        
        return {
            "device_type": device_type,
            "make": self.wps_make,
            "model_name": self.wps_model,
            "model_number": self.wps_model_num,
            "mac_addresses": list(self.mac_addresses),
            "network_roles": list(self.network_roles),
            "total_frames": self.total_frames,
            "unique_fingerprints": len(self.fingerprints),
            "fingerprints": dict(self.fingerprints)
        }


def extract_training_data(pcap_path, min_frames=5, output_file=None, append=False):
    """Extract training data from PCAP using WPS-based device grouping.
    
    Args:
        pcap_path: Path to PCAP file
        min_frames: Minimum frames required to include a device
        output_file: Output JSON file path
        append: If True, append to existing file instead of overwriting
    
    Returns:
        Dictionary of training data
    """
    print(f"[*] Extracting training data from: {pcap_path}")
    print(f"[*] Minimum frames per device: {min_frames}")
    
    # Load existing database if appending
    existing_db = {}
    if append and output_file and os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                existing_db = json.load(f)
            print(f"[+] Loaded existing database with {len(existing_db)} entries")
        except Exception as e:
            print(f"[-] Warning: Could not load existing file: {e}")
            print("[*] Creating new database")
    
    # Group devices by WPS signature
    devices_by_wps = {}
    devices_without_wps = []
    total_frames = 0
    wps_frames = 0
    
    with PcapReader(pcap_path) as pcap_file:
        for packet in pcap_file:
            result = generate_fingerprint_string(packet)
            if result:
                fp_hash, context = result
                total_frames += 1
                
                mac = context.get("mac_address", "Unknown")
                role = context["network_role"]
                wps_data = context.get("wps", {})
                
                if wps_data:
                    wps_frames += 1
                    # Create WPS signature key
                    wps_make = wps_data.get("wps_make", "Unknown")
                    wps_model = wps_data.get("wps_model_name", "Unknown")
                    wps_model_num = wps_data.get("wps_model_num", "Unknown")
                    
                    wps_key = f"{wps_make}|{wps_model}|{wps_model_num}"
                    
                    if wps_key not in devices_by_wps:
                        devices_by_wps[wps_key] = DeviceGroup(wps_make, wps_model, wps_model_num)
                    
                    devices_by_wps[wps_key].add_fingerprint(fp_hash, mac, role)
                else:
                    # Store frames without WPS for potential manual review
                    devices_without_wps.append({
                        "mac": mac,
                        "role": role,
                        "fingerprint": fp_hash
                    })
    
    print(f"\n[*] Processing complete:")
    print(f"    Total frames processed: {total_frames}")
    print(f"    Frames with WPS data: {wps_frames}")
    print(f"    Unique devices identified via WPS: {len(devices_by_wps)}")
    print(f"    Frames without WPS: {len(devices_without_wps)}")
    
    # Filter devices by minimum frame count
    valid_devices = {}
    for wps_key, device in devices_by_wps.items():
        if device.total_frames >= min_frames:
            valid_devices[wps_key] = device
    
    print(f"    Devices meeting minimum frame threshold: {len(valid_devices)}")
    
    # Build training database
    training_db = dict(existing_db)  # Start with existing data if appending
    
    for wps_key, device in valid_devices.items():
        device_name = device.get_device_name()
        device_entry = device.to_training_entry()
        
        # Add each fingerprint to training database
        for fp_hash, count in device.fingerprints.items():
            if fp_hash not in training_db:
                training_db[fp_hash] = {
                    "network_role": list(device.network_roles)[0] if device.network_roles else "Unknown",
                    "device_type": device_entry["device_type"],
                    "make": device.wps_make,
                    "model_samples": {device_name: count},
                    "wps_fingerprints": [str(wps_data) for wps_data in [wps_key.split('|')] if wps_data]
                }
            else:
                # Update existing entry
                if device_name in training_db[fp_hash]["model_samples"]:
                    training_db[fp_hash]["model_samples"][device_name] += count
                else:
                    training_db[fp_hash]["model_samples"][device_name] = count
    
    # Print device summary
    print("\n" + "="*80)
    print("IDENTIFIED DEVICES")
    print("="*80)
    for i, (wps_key, device) in enumerate(valid_devices.items(), 1):
        device_name = device.get_device_name()
        device_entry = device.to_training_entry()
        mac_list = list(device.mac_addresses)
        print(f"\nDevice #{i}: {device_name}")
        print(f"  Type: {device_entry['device_type']}")
        print(f"  MACs: {', '.join(mac_list[:5])}" + 
              (f" ... ({len(mac_list)} total)" if len(mac_list) > 5 else ""))
        print(f"  Roles: {', '.join(device.network_roles)}")
        print(f"  Frames: {device.total_frames}")
        print(f"  Unique fingerprints: {len(device.fingerprints)}")
    
    # Handle frames without WPS
    if devices_without_wps:
        print(f"\n[*] Warning: {len(devices_without_wps)} frames without WPS data")
        print("    These frames cannot be automatically grouped by device.")
        print("    Consider manual labeling or additional capture with WPS-enabled devices.")
    
    # Save to file
    if output_file:
        # Output just the training database (no metadata or devices array)
        with open(output_file, 'w') as f:
            json.dump(training_db, f, indent=4)
        
        action = "Appended to" if append else "Saved to"
        print(f"\n[+] Training data {action}: {output_file}")
        print(f"    Total database entries: {len(training_db)}")
    
    return training_db


def main():
    parser = argparse.ArgumentParser(
        description="Extract training data from multi-device PCAP files using WPS identification"
    )
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("-o", "--output", default="trained_db.json", 
                       help="Output JSON file path (default: trained_db.json)")
    parser.add_argument("--min-frames", type=int, default=5,
                       help="Minimum frames per device to include (default: 5)")
    parser.add_argument("--append", action="store_true",
                       help="Append to existing trained_db.json instead of overwriting")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        print(f"[-] Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    # Prevent overwrite of existing file
    if os.path.exists(args.output) and not args.append:
        print(f"[-] Error: Output file already exists: {args.output}")
        print(f"[*] Use --append flag to add to existing file, or specify a different output file with -o")
        sys.exit(1)
    
    extract_training_data(args.pcap, args.min_frames, args.output, args.append)


if __name__ == "__main__":
    main()
