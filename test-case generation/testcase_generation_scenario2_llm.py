import json
import os
import sys
import time
from pprint import pprint

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] Warning: requests not available. Cannot call Ollama.")

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("[!] Warning: openai not available. Cannot call OpenAI GPT.")


OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.1:8b"
OPENAI_API_KEY = "<your openai api key here>"
OPENAI_MODEL = "gpt-4o-mini"


def call_llm_ollama(prompt: str, system_message: str = None, model: str = None) -> str:
    """Call Ollama LLM with the given prompt using chat API."""
    if not REQUESTS_AVAILABLE:
        return None
    
    model = model or OLLAMA_MODEL
    
    try:
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 2000
            }
        }
        
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )
        response.raise_for_status()
        result = response.json()
        return result.get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"[!] Ollama LLM call failed: {e}")
        return None


def call_llm_openai(prompt: str, system_message: str = None, model: str = None) -> str:
    """Call OpenAI GPT with the given prompt."""
    if not OPENAI_AVAILABLE:
        return None
    
    model = model or OPENAI_MODEL
    
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})
        
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
            max_tokens=2000
        )
        
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[!] OpenAI LLM call failed: {e}")
        return None


def call_llm(prompt: str, system_message: str = None, provider: str = "ollama", model: str = None) -> str:
    """Call LLM with the given prompt. Supports both Ollama and OpenAI."""
    if provider.lower() == "ollama":
        return call_llm_ollama(prompt, system_message, model)
    elif provider.lower() == "openai" or provider.lower() == "gpt":
        return call_llm_openai(prompt, system_message, model)
    else:
        print(f"[!] Unknown provider: {provider}. Use 'ollama' or 'openai'")
        return None


def read_test_file(file_path: str) -> str:
    """Read the test.txt file containing Wireshark packet dump."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"[!] Failed to read {file_path}: {e}")
        return None


def extract_fields_with_llm(packet_dump: str, provider: str = "ollama", model: str = None) -> dict:
    """Use LLM to extract all required fields from the packet dump."""
    system_msg = "You are a JSON extraction tool. Your ONLY output must be valid JSON. No explanations, no text before or after JSON."
    
    prompt = f"""{{"eth_dst":"","eth_src":"","ip_src":"","ip_dst":"","src_port":0,"dst_port":0,"verification_tag":"",
    "initial_tsn":0,"ppid":60,"sid":0,"ssn":0,"mcc":"","mnc":"","sst":"","amf_name":"","amf_region_id":"","amf_set_id":"","amf_pointer":"","amf_capacity":0}}

Fill in the above JSON template with values extracted from this packet dump:

{packet_dump}

EXTRACTION METHODOLOGY:

HOW TO FIND VALUES - METHODOLOGY:

TRANSPORT LAYER FIELDS:
1. eth_dst - Search for the packet containing NGSetupRequest (look for "NGSetupRequest" in the protocol field). In that packet's Ethernet II section, find the Destination MAC address field and extract its exact value.
2. eth_src - In the same NGSetupRequest packet's Ethernet II section, find the Source MAC address field and extract its exact value.
3. ip_src - NGSetupResponse travels from AMF to gNB. Find the NGSetupRequest packet (which travels gNB->AMF). In that packet, identify the IP layer. The Destination IP address in NGSetupRequest becomes the Source IP for NGSetupResponse (reverse direction).
4. ip_dst - In the NGSetupRequest packet's IP layer, the Source IP address becomes the Destination IP for NGSetupResponse (reverse direction). Note: Both IPs may be the same if it's a loopback scenario.
5. src_port - NGSetupResponse is AMF to gNB. Find NGSetupRequest packet (gNB to AMF). In its SCTP section, the Destination port becomes the Source port for NGSetupResponse (reverse direction).
6. dst_port - In the NGSetupRequest packet's SCTP section, the Source port becomes the Destination port for NGSetupResponse (reverse direction).
7. verification_tag - Search for INIT-ACK chunk packets. In the SCTP header of INIT-ACK packets, find the Verification tag field. Extract this value (it's the tag the AMF side will use).
8. initial_tsn - Search for packets containing INIT-ACK chunk. Within the INIT-ACK chunk details, locate the "Initial TSN" field. Extract this value (this represents the AMF side's initial TSN).
9. ppid - This is always 60 for NGAP protocol (Payload Protocol Identifier).
10. sid - Search for DATA chunks that would be in the AMF->gNB direction. To identify direction: if NGSetupRequest is gNB to AMF, then AMF to gNB is the reverse. In DATA chunks of that direction, find the Stream identifier (SID) field and extract its value.
11. ssn - In the same DATA chunk used for sid, find the Stream sequence number (SSN) field and extract its value.

NGAP APPLICATION LAYER FIELDS:
12. mcc - Search for the packet containing NGSetupRequest. Within the NGAP section, navigate to protocolIEs (a list of protocol information elements). Search through the items to find one with id-GlobalRANNodeID. Within that item's value structure, locate pLMNIdentity field. Extract the Mobile Country Code (MCC) value from that field.
13. mnc - In the same NGSetupRequest packet, in the same pLMNIdentity field used for mcc, extract the Mobile Network Code (MNC) value.
14. sst - In the NGSetupRequest packet's NGAP section, within protocolIEs, search for an item with id-SupportedTAList. Navigate through its value structure: find SupportedTAList, then broadcastPLMNList, then tAISliceSupportList, then s-NSSAI, then locate the sST field. Extract the sST value.
15. amf_name - Generate a realistic fake AMF name for the attacker (e.g., "fake-amf-attacker")
16. amf_region_id - Generate a realistic fake AMF Region ID (2 hex digits, e.g., "01")
17. amf_set_id - Generate a realistic fake AMF Set ID (4 hex digits, e.g., "0001")
18. amf_pointer - Generate a realistic fake AMF Pointer (2 hex digits, e.g., "00")
19. amf_capacity - Generate a realistic fake AMF Capacity (integer 0-255, e.g., 255)

CRITICAL EXTRACTION RULES:
- ALWAYS extract EXACT values from the packet dump. Do NOT invent or guess values.
- For Ethernet MACs: Extract the exact hex values shown in the packet (format: XX:XX:XX:XX:XX:XX with colons)
- For IP addresses: Check if both source and destination are the same IP (common in loopback scenarios)
- For direction reversal: NGSetupRequest shows gNB to AMF. NGSetupResponse is AMF to gNB, so reverse source/destination.
- For initial_tsn: Only look in INIT-ACK chunks, find the "Initial TSN" field.
- For verification_tag: Look in INIT-ACK chunk packets, SCTP header section.
- For mcc, mnc, sst: These MUST match exactly what the gNB requested in NGSetupRequest (attacker must match gNB's requirements).
- For AMF identity fields: These are attacker-generated fake values, not extracted from packets.

Return ONLY the filled JSON object. No other text.
"""
    
    response = call_llm(prompt, system_msg, provider=provider, model=model)
    if not response:
        return None
    
    response = response.strip()
    
    if response.startswith('{') and response.endswith('}'):
        try:
            parsed = json.loads(response)
            if isinstance(parsed, dict) and len(parsed) >= 15:
                return parsed
        except Exception as e:
            print(f"[!] Failed to parse JSON (direct): {e}")
    
    json_start = response.find('{')
    if json_start >= 0:
        brace_count = 0
        json_end = json_start
        for i in range(json_start, len(response)):
            if response[i] == '{':
                brace_count += 1
            elif response[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = i + 1
                    json_str = response[json_start:json_end]
                    try:
                        parsed = json.loads(json_str)
                        if isinstance(parsed, dict) and len(parsed) >= 15:
                            return parsed
                    except Exception:
                        pass
                    break
    
    json_start = response.find('{')
    json_end = response.rfind('}') + 1
    if json_start >= 0 and json_end > json_start:
        json_str = response[json_start:json_end]
        try:
            parsed = json.loads(json_str)
            if isinstance(parsed, dict) and len(parsed) >= 15:
                return parsed
        except Exception as e:
            print(f"[!] Failed to parse JSON (extracted): {e}")
    
    print(f"[!] First attempt failed. LLM response (first 500 chars): {response[:500]}")
    print(f"[!] Attempting to convert text response to JSON...")
    
    convert_prompt = f"""Convert this text response to valid JSON format. Extract all field values and output ONLY a JSON object:

{response[:2000]}

Required JSON structure:
{{"eth_dst":"","eth_src":"","ip_src":"","ip_dst":"","src_port":0,"dst_port":0,"verification_tag":"","initial_tsn":0,"ppid":60,"sid":0,"ssn":0,"mcc":"","mnc":"","sst":"","amf_name":"","amf_region_id":"","amf_set_id":"","amf_pointer":"","amf_capacity":0}}

Output ONLY the JSON object with filled values. No other text."""
    
    response2 = call_llm(convert_prompt, system_msg, provider=provider, model=model)
    if response2:
        response2 = response2.strip()
        if response2.startswith('{') and response2.endswith('}'):
            try:
                parsed = json.loads(response2)
                if isinstance(parsed, dict) and len(parsed) >= 15:
                    return parsed
            except Exception:
                pass
    
    print(f"[!] ERROR: Failed to extract JSON from LLM response")
    print(f"[!] Full response: {response[:2000]}")
    return None


def output_variables_format(extracted_fields: dict):
    """Output extracted fields in variables:value format."""
    print("\n" + "="*60)
    print("EXTRACTED FIELD VALUES (variables:value format):")
    print("="*60)
    
    for key, value in extracted_fields.items():
        print(f"{key}:{value}")
    
    print("="*60)


def convert_verification_tag(tag_value):
    """Convert verification_tag to hex format if needed."""
    if tag_value is None:
        return None
    
    if isinstance(tag_value, str):
        tag_str = tag_value.strip()
        if tag_str.startswith("0x") or tag_str.startswith("0X"):
            return tag_str.lower()
        try:
            tag_int = int(tag_str, 16)
            return hex(tag_int)
        except ValueError:
            try:
                tag_int = int(tag_str)
                return hex(tag_int)
            except ValueError:
                return None
    elif isinstance(tag_value, int):
        return hex(tag_value)
    else:
        try:
            return hex(int(tag_value))
        except (ValueError, TypeError):
            return None


def make_testcase_dict(extracted_fields: dict):
    """Build testcase from extracted field values. No default values allowed."""
    if "eth_dst" not in extracted_fields or extracted_fields["eth_dst"] is None:
        raise ValueError("eth_dst is required")
    if "eth_src" not in extracted_fields or extracted_fields["eth_src"] is None:
        raise ValueError("eth_src is required")
    if "ip_src" not in extracted_fields or extracted_fields["ip_src"] is None:
        raise ValueError("ip_src is required")
    if "ip_dst" not in extracted_fields or extracted_fields["ip_dst"] is None:
        raise ValueError("ip_dst is required")
    if "src_port" not in extracted_fields or extracted_fields["src_port"] is None:
        raise ValueError("src_port is required")
    if "dst_port" not in extracted_fields or extracted_fields["dst_port"] is None:
        raise ValueError("dst_port is required")
    if "verification_tag" not in extracted_fields or extracted_fields["verification_tag"] is None:
        raise ValueError("verification_tag is required")
    if "initial_tsn" not in extracted_fields or extracted_fields["initial_tsn"] is None:
        raise ValueError("initial_tsn is required")
    if "ppid" not in extracted_fields or extracted_fields["ppid"] is None:
        raise ValueError("ppid is required")
    if "sid" not in extracted_fields or extracted_fields["sid"] is None:
        raise ValueError("sid is required")
    if "ssn" not in extracted_fields or extracted_fields["ssn"] is None:
        raise ValueError("ssn is required")
    if "mcc" not in extracted_fields or extracted_fields["mcc"] is None:
        raise ValueError("mcc is required")
    if "mnc" not in extracted_fields or extracted_fields["mnc"] is None:
        raise ValueError("mnc is required")
    if "sst" not in extracted_fields or extracted_fields["sst"] is None:
        raise ValueError("sst is required")
    if "amf_name" not in extracted_fields or extracted_fields["amf_name"] is None:
        raise ValueError("amf_name is required")
    if "amf_region_id" not in extracted_fields or extracted_fields["amf_region_id"] is None:
        raise ValueError("amf_region_id is required")
    if "amf_set_id" not in extracted_fields or extracted_fields["amf_set_id"] is None:
        raise ValueError("amf_set_id is required")
    if "amf_pointer" not in extracted_fields or extracted_fields["amf_pointer"] is None:
        raise ValueError("amf_pointer is required")
    if "amf_capacity" not in extracted_fields or extracted_fields["amf_capacity"] is None:
        raise ValueError("amf_capacity is required")
    
    eth_dst = extracted_fields["eth_dst"]
    eth_src = extracted_fields["eth_src"]
    ip_src = extracted_fields["ip_src"]
    ip_dst = extracted_fields["ip_dst"]
    src_port = extracted_fields["src_port"]
    dst_port = extracted_fields["dst_port"]
    verification_tag = convert_verification_tag(extracted_fields["verification_tag"])
    initial_tsn = extracted_fields["initial_tsn"]
    ppid = extracted_fields["ppid"]
    sid = extracted_fields["sid"]
    ssn = extracted_fields["ssn"]
    tsn_abs = initial_tsn  # For NGSetupResponse, TSN = initial_tsn from INIT-ACK
    
    mcc = extracted_fields["mcc"]
    mnc = extracted_fields["mnc"]
    sst = extracted_fields["sst"]
    amf_name = extracted_fields["amf_name"]
    amf_region_id = extracted_fields["amf_region_id"]
    amf_set_id = extracted_fields["amf_set_id"]
    amf_pointer = extracted_fields["amf_pointer"]
    amf_capacity = extracted_fields["amf_capacity"]
    
    chunks = [
        {
            "type": "DATA",
            "ppid": int(ppid),
            "sid": int(sid),
            "ssn": int(ssn),
            "tsn_abs": int(tsn_abs),
            "flags": {"B": 1, "E": 1, "U": 0, "I": 0}
        }
    ]
    
    testcase = {
        "protocol": "ngap",
        "message_name": "NGSetupResponse",
        "attack_scenario": "Fake AMF access to gNB",
        "procedure_code": 21,
        "type_of_message": 1,
        "criticality": "reject",
        "test_case": {
            "transport": {
                "l2_ethernet": {
                    "dst_mac": eth_dst,
                    "src_mac": eth_src,
                    "ethertype": "0x0800"
                },
                "ip": {
                    "src_ip": ip_src,
                    "dst_ip": ip_dst,
                    "ttl": 64,
                    "dscp_ecn": "0x00"
                },
                "sctp": {
                    "src_port": int(src_port),
                    "dst_port": int(dst_port),
                    "verification_tag": verification_tag,
                    "initial_tsn": int(initial_tsn),
                    "chunks": chunks
                }
            },
            "ngap": {
                "fields": [
                    {"id": 1, "value": amf_name},
                    {"id": 96, "value": {
                        "mcc": mcc,
                        "mnc": mnc,
                        "amf_region_id": amf_region_id,
                        "amf_set_id": amf_set_id,
                        "amf_pointer": amf_pointer
                    }},
                    {"id": 86, "value": int(amf_capacity)},
                    {"id": 80, "value": [{
                        "mcc": mcc,
                        "mnc": mnc,
                        "sst": sst
                    }]}
                ]
            },
            "crafting_instructions": "Emulate AMF connect to real gNodeB",
            "expected_impact": "Successfully obtain UE registration"
        }
    }
    return testcase


def main():
    import argparse
    p = argparse.ArgumentParser(description="Extract NGAP NGSetupResponse fields from test.txt using LLM (Ollama or OpenAI GPT)")
    p.add_argument("--file", default="test.txt", help="Path to test.txt file (default: test.txt)")
    p.add_argument("--provider", choices=["ollama", "openai", "gpt"], default="ollama", help="LLM provider: 'ollama' or 'openai'/'gpt' (default: ollama)")
    p.add_argument("--model", default=None, help="Model name (default: llama3.1:8b for Ollama, gpt-4o-mini for OpenAI)")
    args = p.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return

    print(f"[+] Reading file: {args.file}")
    packet_dump = read_test_file(args.file)
    
    if not packet_dump:
        print(f"[!] Failed to read {args.file}")
        return
    
    print(f"[+] Read {len(packet_dump)} characters from {args.file}")
    
    provider = args.provider.lower()
    if provider == "gpt":
        provider = "openai"
    
    if args.model:
        model_name = args.model
    else:
        model_name = OLLAMA_MODEL if provider == "ollama" else OPENAI_MODEL
    
    provider_display = "OpenAI GPT" if provider == "openai" else "Ollama"
    print(f"[+] Using {provider_display} provider")
    print(f"[+] Using model: {model_name}")
    print(f"[+] Sending packet dump to LLM for field extraction...")
    
    extracted_fields = extract_fields_with_llm(packet_dump, provider=provider, model=args.model)
    
    if not extracted_fields:
        print("[!] ERROR: Failed to extract fields from LLM")
        return
    
    required_fields = [
        "eth_dst", "eth_src", "ip_src", "ip_dst",
        "src_port", "dst_port", "verification_tag", "initial_tsn",
        "ppid", "sid", "ssn",
        "mcc", "mnc", "sst",
        "amf_name", "amf_region_id", "amf_set_id", "amf_pointer", "amf_capacity"
    ]
    
    missing = [f for f in required_fields if f not in extracted_fields or extracted_fields[f] is None]
    
    if missing:
        print(f"[!] ERROR: Missing required fields: {missing}")
        print("[!] LLM did not extract all required fields.")
        return
    
    output_variables_format(extracted_fields)
    
    print("\n[+] All required fields extracted successfully!")
    print("\n[+] Building testcase from extracted values...")
    
    testcase = make_testcase_dict(extracted_fields)
    
    out_dir = "testcase_output"
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"ngap_NGSetupResponse_llm_{ts}.json")
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(testcase, f, indent=2)
    
    print(f"[+] Testcase written: {out_file}")
    print("\n[+] Generated testcase structure:")
    pprint(testcase)


if __name__ == "__main__":
    main()
