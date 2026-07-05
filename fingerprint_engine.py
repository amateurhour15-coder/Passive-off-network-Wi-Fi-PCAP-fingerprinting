import sys
import os
import json
import argparse
from scapy.all import PcapReader

from fingerprint_parsers import generate_fingerprint_string, PORTABLE_KNOWLEDGE_BASE

def train_model(pcap_path, device_type, make, model_number, working_db):
    print(f"[*] Training: Processing '{pcap_path}'...")
    new_sigs, updated_sigs = 0, 0
    
    with PcapReader(pcap_path) as pcap_file:
        for packet in pcap_file:
            result = generate_fingerprint_string(packet)
            if result:
                fp_hash, context = result
                
                if fp_hash not in working_db:
                    working_db[fp_hash] = {
                        "device_type": device_type,
                        "make": make,
                        "model_samples": {model_number: 1},
                        "wps_fingerprints": []
                    }
                    new_sigs += 1
                else:
                    model_dict = working_db[fp_hash].setdefault("model_samples", {})
                    model_dict[model_number] = model_dict.get(model_number, 0) + 1
                    updated_sigs += 1
                
                if context["wps"] and context["wps"] not in working_db[fp_hash]["wps_fingerprints"]:
                    working_db[fp_hash]["wps_fingerprints"].append(context["wps"])
                    
    print(f"[+] Complete. Added {new_sigs} signatures. Incremented {updated_sigs} context samples.")
    return working_db

def calculate_probability_string(model_samples_dict):
    """Generates a sorted string showing distribution probability ratios across conflicting models."""
    total_samples = sum(model_samples_dict.values())
    if total_samples == 0:
        return "N/A"
        
    # Sort models by highest count first
    sorted_models = sorted(model_samples_dict.items(), key=lambda item: item[1], reverse=True)
    
    prob_strings = []
    for model, count in sorted_models:
        percentage = (count / total_samples) * 100
        prob_strings.append(f"{model} ({percentage:.1f}%)")
        
    return " / ".join(prob_strings)

def playback_and_classify(pcap_path, working_db):
    print(f"\n[*] Playback Stream: Classifying with Probability Matrices...")
    print(f"{'MAC ADDRESS': {distribution})"
                
                timing_flag = f" [IFS: {ifs:.2f}s]" if 0 < ifs < 5 else ""
                print(f"{mac:<18} | {context['mac_type']:<12} | {context['hardware_make']:<15} | {dev_identity+timing_flag:<48} | {context['signal_strength']} dBm")

def main():
    parser = argparse.ArgumentParser(description="Probabilistic Context-Aware Wi-Fi Fingerprint Engine")
    parser.add_argument("--train", help="Path to the training PCAP file.")
    parser.add_argument("--type", help="General device category.")
    parser.add_argument("--make", help="Device manufacturer.")
    parser.add_argument("--model", help="Specific model designation string.")
    parser.add_argument("--play", help="Path to target PCAP file for classification.")
    parser.add_argument("--db-import", help="Load external database file.")
    parser.add_argument("--db-export", help="Save current database to external file.")
    
    args = parser.parse_args()
    working_db = PORTABLE_KNOWLEDGE_BASE.copy()
    
    if args.db_import and os.path.exists(args.db_import):
        with open(args.db_import, "r") as f: working_db = json.load(f)
            
    if args.train:
        if not all([args.type, args.make, args.model]):
            print("[-] Error: Training requires '--type', '--make', AND '--model'."); sys.exit(1)
        working_db = train_model(args.train, args.type, args.make, args.model, working_db)
        
    if args.play:
        if not os.path.exists(args.play): print(f"[-] Error: File not found: {args.play}"); sys.exit(1)
        playback_and_classify(args.play, working_db)
        
    if args.db_export:
        with open(args.db_export, "w") as f: json.dump(working_db, f, indent=4)

if __name__ == "__main__":
    main()
