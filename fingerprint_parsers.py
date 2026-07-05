import sys
from scapy.all import Dot11, Dot11ProbeReq, Dot11Elt

# ==============================================================================
# PORTABLE KNOWLEDGE BASE REFERENCE
# Baked-in signature profiles used as fallback identification rules.
# ==============================================================================
PORTABLE_KNOWLEDGE_BASE = {
    "IE:[0-1-45-127-191-221]_HT:[2D04]_VHT:[FF010400]_VENDOR_FLAGS:[0017F2010203]": {
        "device_type": "Smartphone",
        "make": "Apple",
        "model_numbers": ["iPhone 14", "iPhone 15"],
        "sample_count": 412,
        "wps_fingerprints": []
    }
}

# Static MAC OUI hardware assignments used when globally unique addresses match
COMMON_MAC_OUIS = {
    "0017F2": "Apple", "00254B": "Apple", "74D435": "Apple",
    "001A11": "Google", "3C5C24": "Google",
    "001599": "Samsung", "8421EE": "Samsung",
    "002682": "Intel", "A4434D": "Intel",
    "0050F2": "Microsoft"
}

def is_mac_randomized(mac_string):
    """
    Checks the local/global bit in the MAC address.
    If the second hex digit is 2, 6, A, or E, it is locally administered (randomized).
    """
    if not mac_string or len(mac_string) < 17:
        return True
    second_char = mac_string[1].upper()
    return second_char in ['2', '6', 'A', 'E']

def parse_wps_attributes(info_payload):
    """Parses IE 221 Vendor Specific payload looking for WPS Data Elements (OUI 0050F204)."""
    if len(info_payload) < 4:
        return None
    
    oui = info_payload[:3].hex().upper()
    oui_type = info_payload[3]
    
    # Microsoft WPS OUI is 00:50:F2, Type is 04
    if oui == "0050F2" and oui_type == 4:
        wps_data = info_payload[4:]
        idx = 0
        wps_metadata = {}
        
        while idx + 4 <= len(wps_data):
            attr_type = int.from_bytes(wps_data[idx:idx+2], byteorder='big')
            attr_len = int.from_bytes(wps_data[idx+2:idx+4], byteorder='big')
            idx += 4
            
            if idx + attr_len > len(wps_data):
                break
                
            attr_val = wps_data[idx:idx+attr_len]
            idx += attr_len
            
            # 0x1021 = Manufacturer, 0x1023 = Model Name, 0x1024 = Model Number
            if attr_type == 0x1021:
                wps_metadata['wps_make'] = attr_val.decode('utf-8', errors='ignore').strip()
            elif attr_type == 0x1023:
                wps_metadata['wps_model_name'] = attr_val.decode('utf-8', errors='ignore').strip()
            elif attr_type == 0x1024:
                wps_metadata['wps_model_num'] = attr_val.decode('utf-8', errors='ignore').strip()
                
        if wps_metadata:
            return wps_metadata
    return None

def generate_fingerprint_string(packet):
    """Extracts structural signatures, deep vendor flags, MAC status, and timing contextual clues."""
    if not packet.haslayer(Dot11ProbeReq):
        return None
        
    dot11_layer = packet.getlayer(Dot11)
    mac_address = dot11_layer.addr2
    
    mac_type = "Randomized" if is_mac_randomized(mac_address) else "Valid/Hardware"
    mac_oui = mac_address.replace(":", "")[:6].upper()
    hardware_make = COMMON_MAC_OUIS.get(mac_oui, "Unknown Manufacturer") if mac_type == "Valid/Hardware" else "N/A (Randomised)"
    
    packet_time = float(packet.time)
    signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else -99
    
    ie_tags = []
    vendor_raw_payloads = []
    wps_extracted = {}
    ht_caps = "0000"
    vht_caps = "00000000"
    
    elt = packet.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        ie_tags.append(str(elt.ID))
        
        if elt.ID == 221 and len(elt.info) >= 3:
            vendor_raw_payloads.append(elt.info.hex().upper())
            wps_info = parse_wps_attributes(elt.info)
            if wps_info:
                wps_extracted.update(wps_info)
                
        elif elt.ID == 45:
            ht_caps = elt.info[:2].hex().upper()
        elif elt.ID == 191:
            vht_caps = elt.info[:4].hex().upper()
            
        elt = elt.payload.getlayer(Dot11Elt)
        
    ie_sequence = "-".join(ie_tags)
    vendor_payload_hash = "|".join(sorted(set(vendor_raw_payloads))) if vendor_raw_payloads else "NONE"
    
    # Generate unique signature hash to insulate against hardware overlap collisions
    fingerprint_hash = (
        f"IE:[{ie_sequence}]_HT:[{ht_caps}]_VHT:[{vht_caps}]_"
        f"VENDOR_FLAGS:[{vendor_payload_hash[:32]}]"
    )
    
    context_data = {
        "mac_address": mac_address,
        "mac_type": mac_type,
        "hardware_make": hardware_make,
        "timestamp": packet_time,
        "signal_strength": signal_strength,
        "wps": wps_extracted
    }
    
    return fingerprint_hash, context_data
