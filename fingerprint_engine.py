import sys
import os
import json
import argparse
from scapy.all import PcapReader

# Import the core engine layers from Part 1
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

def calculate_probability_string(model_samples_dict, threshold_pct):
    total_samples = sum(model_samples_dict.values())
    if total_samples == 0:
        return None
        
    sorted_models = sorted(model_samples_dict.items(), key=lambda item: item, reverse=True)
    prob_strings = []
    
    for model, count in sorted_models:
        percentage = (count / total_samples) * 100
        if percentage >= threshold_pct:
            prob_strings.append(f"{model} ({percentage:.1f}%)")
        
    if not prob_strings:
        return None
        
    return " / ".join(prob_strings)

def print_metrics_summary(metrics, device_roster):
    """Generates a complete statistics dashboard and a unique MAC identity roster."""
    total = metrics["total_processed"]
    if total == 0:
        print("\n[!] Metrics Error: No probe request frames were processed during this session.")
        return

    # 1. Output the Distinct Unique MAC Address Breakdown Roster
    print("\n" + "="*80)
    print("                     CAPTURED UNIQUE DEVICE ROSTER BREAKDOWN                 ")
    print("="*80)
    print(f" {'MAC ADDRESS': {distribution})"
                            metrics["probabilistic_matches"] += 1
                        else:
                            dev_identity = "Low Confidence Classification (Filtered)"
                            metrics["filtered_matches"] += 1
                else:
                    metrics["unknown_signatures"] += 1
                
                # Keep tracking the device's highest-quality classification label over time
                if mac not in device_roster or device_roster[mac]["identity"] == "Unknown Device Signature":
                    device_roster[mac] = {
                        "mac_type": context["mac_type"],
                        "identity": dev_identity
                    }
                elif "WPS" in dev_identity or "HW Match" in dev_identity:
                    # Upgrade tracking if we find a higher confidence definitive marker on a subsequent frame
                    device_roster[mac]["identity"] = dev_identity
                
                if not quiet_mode:
                    timing_flag = f" [IFS: {ifs:.2f}s]" if 0 < ifs < 5 else ""
                    print(f"{mac:<18} | {context['mac_type']:<12} | {context['hardware_make']:<15} | {dev_identity+timing_flag:<48} | {context['signal_strength']} dBm")

    # Always generate and print the full consolidated metrics dashboards
    print_metrics_summary(metrics, device_roster)

def main():
    parser = argparse.ArgumentParser(description="Probabilistic Context-Aware Wi-Fi Fingerprint Engine")
    parser.add_argument("--train", help="Path to the training PCAP file.")
    parser.add_argument("--type", help="General device category.")
    parser.add_argument("--make", help="Device manufacturer.")
    parser.add_argument("--model", help="Specific model designation string.")
    parser.add_argument("--play", help="Path to target PCAP file for classification.")
    parser.add_argument("--db-import", help="Load external database file.")
    parser.add_argument("--db-export", help="Save current database to external file.")
    parser.add_argument("--threshold", type=float, default=0.0, help="Minimum probability percentage threshold (e.g., 10.0).")
    
    # Speed Optimization Flag
    parser.add_argument("--quiet", action="store_true", help="Silence line-by-line frame logging to maximize parsing speeds.")
    
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
        playback_and_classify(args.play, working_db, args.threshold, args.quiet)
        
    if args.db_export:
        with open(args.db_export, "w") as f: json.dump(working_db, f, indent=4)

if __name__ == "__main__":
    main()
