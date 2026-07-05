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


def extract_training_data(pcap_path, min_frames=5, output_file=None):
    """Extract training data from PCAP using WPS-based device grouping.
    
    Args:
        pcap_path: Path to PCAP file
        min_frames: Minimum frames required to include a device
        output_file: Output JSON file path
    
    Returns:
        Dictionary of training data
    """
    print(f"[*] Extracting training data from: {pcap_path}")
    print(f"[*] Minimum frames per device: {min_frames}")
    
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
    training_db = {}
    device_summary = []
    
    for wps_key, device in valid_devices.items():
        device_name = device.get_device_name()
        device_entry = device.to_training_entry()
        device_summary.append(device_entry)
        
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
                training_db[fp_hash]["model_samples"][device_name] = count
    
    # Print device summary
    print("\n" + "="*80)
    print("IDENTIFIED DEVICES")
    print("="*80)
    for i, device in enumerate(device_summary, 1):
        print(f"\nDevice #{i}:")
        print(f"  Name: {device['make']} {device['model_number'] or device['model_name']}")
        print(f"  Type: {device['device_type']}")
        print(f"  MACs: {', '.join(device['mac_addresses'][:5])}" + 
              (f" ... ({len(device['mac_addresses'])} total)" if len(device['mac_addresses']) > 5 else ""))
        print(f"  Roles: {', '.join(device['network_roles'])}")
        print(f"  Frames: {device['total_frames']}")
        print(f"  Unique fingerprints: {device['unique_fingerprints']}")
    
    # Handle frames without WPS
    if devices_without_wps:
        print(f"\n[*] Warning: {len(devices_without_wps)} frames without WPS data")
        print("    These frames cannot be automatically grouped by device.")
        print("    Consider manual labeling or additional capture with WPS-enabled devices.")
    
    # Save to file
    if output_file:
        output_data = {
            "metadata": {
                "source_pcap": os.path.basename(pcap_path),
                "total_frames": total_frames,
                "wps_frames": wps_frames,
                "devices_identified": len(valid_devices),
                "min_frames_threshold": min_frames
            },
            "devices": device_summary,
            "training_database": training_db
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n[+] Training data saved to: {output_file}")
        print(f"    Database entries: {len(training_db)}")
    
    return output_data


def main():
    parser = argparse.ArgumentParser(
        description="Extract training data from multi-device PCAP files using WPS identification"
    )
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("--min-frames", type=int, default=5,
                       help="Minimum frames per device to include (default: 5)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        print(f"[-] Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    if not args.output:
        # Generate default output filename
        base_name = os.path.splitext(os.path.basename(args.pcap))[0]
        args.output = f"{base_name}_training_data.json"
    
    extract_training_data(args.pcap, args.min_frames, args.output)


if __name__ == "__main__":
    main()
