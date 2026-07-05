import sys
import os
import json
import argparse
from scapy.all import PcapReader

# Import the core engine layers from Part 1
from fingerprint_parsers import generate_fingerprint_string, PORTABLE_KNOWLEDGE_BASE

def train_model(pcap_path, device_type, make, model_number, working_db):
    """Processes training data adding the new context schema validations."""
    print(f"[*] Training Mode Started: Processing '{pcap_path}'...")
    print(f"[*] Target Assignment: [{make}] {model_number} ({device_type})")
    
    new_sigs = 0
    updated_sigs = 0
    
    with PcapReader(pcap_path) as pcap_file:
        for packet in pcap_file:
            result = generate_fingerprint_string(packet)
            if result:
                fp_hash, context = result
                
                if fp_hash not in working_db:
                    working_db[fp_hash] = {
                        "device_type": device_type,
                        "make": make,
                        "model_numbers": [model_number],
                        "sample_count": 1,
                        "wps_fingerprints": []
                    }
                    new_sigs += 1
                else:
                    working_db[fp_hash]["sample_count"] += 1
                    if model_number not in working_db[fp_hash]["model_numbers"]:
                        working_db[fp_hash]["model_numbers"].append(model_number)
                        updated_sigs += 1
                
                if context["wps"] and context["wps"] not in working_db[fp_hash]["wps_fingerprints"]:
                    working_db[fp_hash]["wps_fingerprints"].append(context["wps"])
                    
    print(f"[+] Complete. Added {new_sigs} new signatures. Appended to {updated_sigs} configurations.")
    return working_db

def playback_and_classify(pcap_path, working_db):
    """Performs live playback analysis leveraging timing metrics, WPS attributes, and MAC validations."""
    print(f"\n[*] Playback Stream Active: Classifying frames with Contextual Tie-Breakers...")
    print(f"{'MAC ADDRESS': 0 and ifs < 5 else ""
                print(f"{mac:<18} | {context['mac_type']:<12} | {context['hardware_make']:<16} | {dev_identity+timing_flag:<30} | {context['signal_strength']} dBm")

def main():
    parser = argparse.ArgumentParser(description="Context-Aware Wi-Fi Fingerprint Engine Split Architecture")
    parser.add_argument("--train", help="Path to the training PCAP file.")
    parser.add_argument("--type", help="General device category (e.g., 'IoT-Device').")
    parser.add_argument("--make", help="Device manufacturer (e.g., 'Tuya').")
    parser.add_argument("--model", help="Specific model designation string.")
    parser.add_argument("--play", help="Path to target PCAP file for contextual classification.")
    parser.add_argument("--db-import", help="Load external database file.")
    parser.add_argument("--db-export", help="Save current database to external file.")
    
    args = parser.parse_args()
    working_db = PORTABLE_KNOWLEDGE_BASE.copy()
    
    if args.db_import and os.path.exists(args.db_import):
        try:
            with open(args.db_import, "r") as f:
                working_db = json.load(f)
            print(f"[+] Imported {len(working_db)} profiles from file.")
        except Exception as e:
            print(f"[-] Database Import failure: {e}"); sys.exit(1)
            
    if args.train:
        if not all([args.type, args.make, args.model]):
            print("[-] Error: Training requires '--type', '--make', AND '--model'."); sys.exit(1)
        working_db = train_model(args.train, args.type, args.make, args.model, working_db)
        
    if args.play:
        if not os.path.exists(args.play): 
            print(f"[-] Error: Target playback file not found: {args.play}"); sys.exit(1)
        playback_and_classify(args.play, working_db)
        
    if args.db_export:
        try:
            with open(args.db_export, "w") as f:
                json.dump(working_db, f, indent=4)
            print(f"[+] Exported running fingerprint database to: {args.db_export}")
        except Exception as e:
            print(f"[-] Database Export failure: {e}")

if __name__ == "__main__":
    main()
