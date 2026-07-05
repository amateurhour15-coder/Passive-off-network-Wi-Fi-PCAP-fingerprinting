import sys
import os
import json
import argparse
import glob
from scapy.all import PcapReader

# Import the core engine layers from Part 1 module
from fingerprint_parsers import generate_fingerprint_string, PORTABLE_KNOWLEDGE_BASE

def train_model(pcap_path, device_type, make, model_number, working_db):
    """Processes a single training capture file and maps its counts to memory."""
    print(f"[*] Training: Processing '{pcap_path}'...")
    new_sigs, updated_sigs = 0, 0
    
    with PcapReader(pcap_path) as pcap_file:
        for packet in pcap_file:
            result = generate_fingerprint_string(packet)
            if result:
                fp_hash, context = result
                
                if fp_hash not in working_db:
                    working_db[fp_hash] = {
                        "network_role": context["network_role"],
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
                    
    print(f"[+] Complete '{os.path.basename(pcap_path)}': Added {new_sigs} rules. Incremented {updated_sigs} matrix variants.")
    return working_db

def calculate_probability_string(model_samples_dict, threshold_pct):
    """Calculates relative training distribution weights across competing model numbers."""
    total_samples = sum(model_samples_dict.values())
    if total_samples == 0:
        return None
        
    sorted_models = sorted(model_samples_dict.items(), key=lambda item: item, reverse=True)
    prob_strings = []
    
    for model, count in sorted_models:
        percentage = (count / total_samples) * 100
        if percentage >= threshold_pct:
            prob_strings.append(f"{model} ({percentage:.1f}%)")
        
    return " / ".join(prob_strings) if prob_strings else None

def print_metrics_summary(metrics, device_roster):
    """Outputs analytical summaries and distinct MAC address registers."""
    total = metrics["total_processed"]
    if total == 0:
        print("\n[!] Metrics Error: No probe/beacon frames were processed during this session.")
        return

    print("\n" + "="*90)
    print("                     CAPTURED UNIQUE DEVICE ROSTER BREAKDOWN                 ")
    print("="*90)
    print(f" {'MAC ADDRESS':<18} | {'ROLE':<13} | {'MAC SYSTEM':<12} | {'RESOLVED IDENTITY MATRIX / PROFILE':<35}")
    print("-" * 90)
    for mac, info in sorted(device_roster.items()):
        print(f" {mac:<18} | {info['role']:<13} | {info['mac_type']:<12} | {info['identity']:<35}")
    print("="*90)

    definitive_pct = (metrics["definitive_matches"] / total) * 100
    probabilistic_pct = (metrics["probabilistic_matches"] / total) * 100
    filtered_pct = (metrics["filtered_matches"] / total) * 100
    unknown_pct = (metrics["unknown_signatures"] / total) * 100
    success_rate = ((metrics["definitive_matches"] + metrics["probabilistic_matches"]) / total) * 100

    print("\n" + "="*90)
    print("                 PASSIVE FRAME CLASSIFICATION PERFORMANCE METRICS             ")
    print("="*90)
    print(f" Total Radio Frames Processed : {total:<5}")
    print(f" Total Unique MACs Documented : {len(metrics['unique_macs']):<5}")
    print("-" * 90)
    print(f" 🎯 Definitive Hardware Matches  : {metrics['definitive_matches']:<5} ({definitive_pct:.1f}%) [WPS/OUI Verified]")
    print(f" 📊 Probabilistic Model Matches : {metrics['probabilistic_matches']:<5} ({probabilistic_pct:.1f}%) [Matrix Resolved]")
    print(f" 🛑 Low Confidence (Filtered)   : {metrics['filtered_matches']:<5} ({filtered_pct:.1f}%) [Below Threshold]")
    print(f" ❓ Completely Untrained Sigs   : {metrics['unknown_signatures']:<5} ({unknown_pct:.1f}%) [No DB Entry]")
    print("-" * 90)
    print(f" OVERALL CAPTURE CLASSIFICATION SUCCESS RATE : {success_rate:.2f}%")
    print("="*90 + "\n")
def playback_and_classify(pcap_path, working_db, threshold_pct, quiet_mode):
    """Streams a file line by line to calculate classification metrics and resolve tie-breakers."""
    if not quiet_mode:
        print(f"\n[*] Playback Stream: Classifying with Probability Matrices (Threshold: {threshold_pct}%)")
        print(f"{'MAC ADDRESS': {distribution}}")
                            metrics["probabilistic_matches"] += 1
                        else:
                            dev_identity = "Low Confidence Classification (Filtered)"
                            metrics["filtered_matches"] += 1
                else:
                    metrics["unknown_signatures"] += 1
                
                if mac not in device_roster or device_roster[mac]["identity"] == "Unknown Device Signature":
                    device_roster[mac] = {"role": role, "mac_type": context["mac_type"], "identity": dev_identity}
                elif "WPS" in dev_identity or "HW Match" in dev_identity:
                    device_roster[mac]["identity"] = dev_identity
                
                if not quiet_mode:
                    timing_flag = f" [IFS: {ifs:.2f}s]" if 0 < ifs < 5 else ""
                    print(f"{mac:<18} | {role:<13} | {context['mac_type']:<12} | {dev_identity+timing_flag:<43} | {context['signal_strength']} dBm")

    print_metrics_summary(metrics, device_roster)

def main():
    parser = argparse.ArgumentParser(description="Multi-Role Probabilistic Wi-Fi Fingerprint Engine")
    parser.add_argument("--train", nargs="+", help="Path to one or more training PCAP files (supports wildcards).")
    parser.add_argument("--type", help="General device category (e.g., 'Smartphone', 'Access-Point').")
    parser.add_argument("--make", help="Device manufacturer (e.g., 'Apple', 'Cisco').")
    parser.add_argument("--model", help="Specific model designation string (e.g., 'iPhone 15', 'Catalyst-9120').")
    parser.add_argument("--play", help="Path to target PCAP file for classification.")
    parser.add_argument("--db-import", help="Load external database file.")
    parser.add_argument("--db-export", help="Save current database to external file.")
    parser.add_argument("--threshold", type=float, default=0.0, help="Minimum probability threshold percentage.")
    parser.add_argument("--quiet", action="store_true", help="Silence line-by-line frame logging.")
    
    args = parser.parse_args()
    working_db = PORTABLE_KNOWLEDGE_BASE.copy()
    
    if args.db_import and os.path.exists(args.db_import):
        try:
            with open(args.db_import, "r") as f: working_db = json.load(f)
            print(f"[+] Successfully loaded external database rules.")
        except Exception as e:
            print(f"[-] Database Import failure: {e}"); sys.exit(1)
            
    if args.train:
        if not all([args.type, args.make, args.model]):
            print("[-] Error: Training requires '--type', '--make', AND '--model'."); sys.exit(1)
            
        target_files = []
        for pattern in args.train:
            target_files.extend(glob.glob(pattern))
            
        if not target_files:
            print("[-] Error: No valid capture training files matched the input string target.")
            sys.exit(1)
            
        print(f"[*] Found {len(target_files)} training files to process...")
        for pcap_path in target_files:
            if os.path.exists(pcap_path):
                working_db = train_model(pcap_path, args.type, args.make, args.model, working_db)
                
    if args.play:
        if not os.path.exists(args.play): print(f"[-] Error: File not found: {args.play}"); sys.exit(1)
        playback_and_classify(args.play, working_db, args.threshold, args.quiet)
        
    if args.db_export:
        try:
            with open(args.db_export, "w") as f: json.dump(working_db, f, indent=4)
            print(f"[+] Saved updated training parameters to: {args.db_export}")
        except Exception as e:
            print(f"[-] Database Export failure: {e}")

if __name__ == "__main__":
    main()
