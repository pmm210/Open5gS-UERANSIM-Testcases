import json
import os
import sys
import time
from pprint import pprint

from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers

try:
    from scapy.contrib.sctp import SCTP, SCTPChunkData, SCTPChunkSACK
    try:
        bind_layers(IP, SCTP, proto=132)
    except Exception:
        pass
except Exception:
    SCTP = None
    SCTPChunkData = None
    SCTPChunkSACK = None

try:
    from pycrate_asn1dir import NGAP
    from pycrate_asn1rt.err import ASN1Err
    NGAP_AVAILABLE = True
except ImportError:
    NGAP_AVAILABLE = False
    print("[!] Warning: pycrate_asn1dir not available. Cannot parse NGAP messages.")


def decode_plmn(plmn_bytes: bytes):
    """Decode PLMN bytes to MCC/MNC strings.
    
    PLMN encoding (3GPP TS 24.301):
    Byte 1: MNC_digit2 (bits 4-7) || MCC_digit1 (bits 0-3)
    Byte 2: MNC_digit1 (bits 4-7) || MCC_digit3 (bits 0-3)
    Byte 3: MNC_digit3 (bits 4-7) || MCC_digit2 (bits 0-3)
    
    For 2-digit MNC: If byte 2 upper nibble = 0xF, then:
      - MNC_digit1 is in byte 1 upper nibble
      - MNC_digit2 is in byte 3 upper nibble
      - Byte 2 upper nibble = 0xF is just an indicator
    """
    if len(plmn_bytes) < 3:
        return None, None
    
    b1, b2, b3 = plmn_bytes[0], plmn_bytes[1], plmn_bytes[2]
    
    mcc1 = (b1 & 0x0F)
    mcc2 = (b1 & 0xF0) >> 4
    mcc3 = (b2 & 0x0F)
    
    if (b2 & 0xF0) >> 4 == 0xF:
        mnc1 = (b3 & 0x0F)
        mnc2 = (b3 & 0xF0) >> 4
        mnc = f"{mnc1}{mnc2}"
    elif (b3 & 0xF0) >> 4 == 0xF:
        mnc1 = (b2 & 0xF0) >> 4
        mnc1 = (b1 & 0xF0) >> 4
        mnc2 = (b2 & 0xF0) >> 4
        mnc1 = (b2 & 0xF0) >> 4
        mnc2 = (b1 & 0xF0) >> 4
        mnc = f"{mnc1}{mnc2}"
    else:
        mnc1 = (b2 & 0xF0) >> 4
        mnc2 = (b1 & 0xF0) >> 4
        mnc3 = (b3 & 0xF0) >> 4
        mnc = f"{mnc1}{mnc2}{mnc3}"
    
    mcc = f"{mcc1}{mcc2}{mcc3}"
    
    return mcc, mnc


def decode_ngap_message(ngap_bytes: bytes):
    """Decode NGAP message from bytes and extract values."""
    if not NGAP_AVAILABLE:
        return None
    
    try:
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.from_aper(ngap_bytes)
        pdu_val = PDU.get_val()
        
        if isinstance(pdu_val, tuple) and len(pdu_val) >= 2:
            if pdu_val[0] == "initiatingMessage":
                procedure_code = pdu_val[1].get("procedureCode", 0) if isinstance(pdu_val[1], dict) else 0
                if procedure_code == 21:
                    value = pdu_val[1].get("value", {})
                    if isinstance(value, tuple) and len(value) >= 2:
                        if value[0] == "NGSetupRequest":
                            return extract_ngsetup_request_values(value[1])
        
        if isinstance(pdu_val, tuple) and len(pdu_val) >= 2:
            if pdu_val[0] == "successfulOutcome":
                procedure_code = pdu_val[1].get("procedureCode", 0) if isinstance(pdu_val[1], dict) else 0
                if procedure_code == 21:
                    value = pdu_val[1].get("value", {})
                    if isinstance(value, tuple) and len(value) >= 2:
                        if value[0] == "NGSetupResponse":
                            return extract_ngsetup_response_values(value[1])
        
        return None
    except Exception as e:
        import traceback
        print(f"[!] NGAP decoding error: {type(e).__name__}: {e}")
        print(f"[!] Traceback: {traceback.format_exc()}")
        if len(ngap_bytes) > 0:
            print(f"[!] First 32 bytes (hex): {ngap_bytes[:32].hex() if len(ngap_bytes) >= 32 else ngap_bytes.hex()}")
        return None


def extract_ngsetup_request_values(ngsetup_request):
    """Extract MCC/MNC/SST from NGSetupRequest."""
    extracted = {}
    
    try:
        ies = ngsetup_request.get("protocolIEs", [])
        
        for ie in ies:
            ie_id = ie.get("id", 0)
            ie_value = ie.get("value", {})
            
            if ie_id == 27:
                if isinstance(ie_value, tuple) and len(ie_value) >= 2:
                    node_id = ie_value[1]
                    if isinstance(node_id, tuple) and len(node_id) >= 2:
                        if node_id[0] == "globalGNB-ID":
                            gnb_id = node_id[1]
                            if isinstance(gnb_id, dict):
                                plmn = gnb_id.get("pLMNIdentity", b"")
                                if plmn:
                                    mcc, mnc = decode_plmn(plmn)
                                    if mcc and mnc:
                                        extracted["mcc"] = mcc
                                        extracted["mnc"] = mnc
            
            if ie_id == 102:
                ta_list = []
                if isinstance(ie_value, list):
                    ta_list = ie_value
                elif isinstance(ie_value, tuple):
                    if len(ie_value) >= 2 and isinstance(ie_value[1], list):
                        ta_list = ie_value[1]
                    else:
                        ta_list = [ie_value]
                
                for ta_item in ta_list:
                    if isinstance(ta_item, dict):
                        broadcast_list = ta_item.get("broadcastPLMNList", [])
                        for plmn_item in broadcast_list:
                            if isinstance(plmn_item, dict):
                                plmn = plmn_item.get("pLMNIdentity", b"")
                                if plmn and "mcc" not in extracted:
                                    mcc, mnc = decode_plmn(plmn)
                                    if mcc and mnc:
                                        extracted["mcc"] = mcc
                                        extracted["mnc"] = mnc
                                
                                slice_list = plmn_item.get("tAISliceSupportList", [])
                                for slice_item in slice_list:
                                    if isinstance(slice_item, dict):
                                        nssai = slice_item.get("s-NSSAI", {})
                                        if isinstance(nssai, dict):
                                            sst = nssai.get("sST", b"")
                                            if sst and len(sst) > 0:
                                                if isinstance(sst, bytes):
                                                    extracted["sst"] = f"{sst[0]:02X}"
                                                else:
                                                    extracted["sst"] = f"{sst:02X}"
                                                break
                                break
                        break
        
        
    except Exception as e:
        import traceback
        print(f"[!] Error extracting NGSetupRequest: {e}")
        print(f"[!] Traceback: {traceback.format_exc()}")
        pass
    
    return extracted if extracted else None


def extract_ngsetup_response_values(ngsetup_response):
    """Extract AMF identity values from NGSetupResponse."""
    extracted = {}
    
    try:
        ies = ngsetup_response.get("protocolIEs", [])
        
        for ie in ies:
            ie_id = ie.get("id", 0)
            ie_value = ie.get("value", {})
            
            if ie_id == 1:
                if isinstance(ie_value, tuple) and len(ie_value) >= 2:
                    if ie_value[0] == "AMFName":
                        extracted["amf_name"] = str(ie_value[1])
                    else:
                        extracted["amf_name"] = str(ie_value[1])
                elif isinstance(ie_value, str):
                    extracted["amf_name"] = ie_value
                elif isinstance(ie_value, bytes):
                    extracted["amf_name"] = ie_value.decode('utf-8', errors='ignore')
            
            if ie_id == 96:
                guami_list = []
                
                if isinstance(ie_value, tuple):
                    if len(ie_value) >= 2 and isinstance(ie_value[1], list):
                        guami_list = ie_value[1]
                    elif isinstance(ie_value[0], list):
                        guami_list = ie_value[0]
                    else:
                        guami_list = [ie_value]
                elif isinstance(ie_value, list):
                    guami_list = ie_value
                
                for idx, guami_item in enumerate(guami_list):
                    
                    guami = None
                    if isinstance(guami_item, dict):
                        guami = guami_item.get("gUAMI", guami_item)
                    elif isinstance(guami_item, tuple) and len(guami_item) >= 2:
                        if isinstance(guami_item[1], dict):
                            guami = guami_item[1].get("gUAMI", guami_item[1])
                        else:
                            guami = guami_item[1]
                    
                    if guami is None:
                        continue
                        
                    
                    if isinstance(guami, dict):
                        plmn = guami.get("pLMNIdentity", b"")
                        if plmn:
                            mcc, mnc = decode_plmn(plmn)
                            if mcc and mnc:
                                extracted["mcc"] = mcc
                                extracted["mnc"] = mnc
                        
                        region_bits = guami.get("aMFRegionID", None)
                        if region_bits is not None:
                            if isinstance(region_bits, tuple):
                                extracted["amf_region_id"] = f"{region_bits[0]:02X}"
                            else:
                                extracted["amf_region_id"] = f"{region_bits:02X}"
                        
                        set_bits = guami.get("aMFSetID", None)
                        if set_bits is not None:
                            if isinstance(set_bits, tuple):
                                extracted["amf_set_id"] = f"{set_bits[0]:04X}"
                            else:
                                extracted["amf_set_id"] = f"{set_bits:04X}"
                        
                        pointer_bits = guami.get("aMFPointer", None)
                        if pointer_bits is not None:
                            if isinstance(pointer_bits, tuple):
                                extracted["amf_pointer"] = f"{pointer_bits[0]:02X}"
                            else:
                                extracted["amf_pointer"] = f"{pointer_bits:02X}"
                    break
            
            if ie_id == 86:
                if isinstance(ie_value, tuple) and len(ie_value) >= 2:
                    if ie_value[0] == "RelativeAMFCapacity":
                        extracted["amf_capacity"] = int(ie_value[1])
                    else:
                        extracted["amf_capacity"] = int(ie_value[1])
                elif isinstance(ie_value, int):
                    extracted["amf_capacity"] = ie_value
            
            if ie_id == 80:
                plmn_list = []
                
                if isinstance(ie_value, tuple):
                    if len(ie_value) >= 2 and isinstance(ie_value[1], list):
                        plmn_list = ie_value[1]
                    elif isinstance(ie_value[0], list):
                        plmn_list = ie_value[0]
                    else:
                        plmn_list = [ie_value]
                elif isinstance(ie_value, list):
                    plmn_list = ie_value
                
                for idx, plmn_item in enumerate(plmn_list):
                    
                    item_dict = None
                    if isinstance(plmn_item, dict):
                        item_dict = plmn_item
                    elif isinstance(plmn_item, tuple) and len(plmn_item) >= 2:
                        if isinstance(plmn_item[1], dict):
                            item_dict = plmn_item[1]
                    
                    if item_dict is None:
                        continue
                    
                    plmn = item_dict.get("pLMNIdentity", b"")
                    if plmn and "mcc" not in extracted:
                        mcc, mnc = decode_plmn(plmn)
                        if mcc and mnc:
                            extracted["mcc"] = mcc
                            extracted["mnc"] = mnc
                    
                    slice_list = item_dict.get("sliceSupportList", [])
                    for slice_item in slice_list:
                        nssai = None
                        if isinstance(slice_item, dict):
                            nssai = slice_item.get("s-NSSAI", slice_item)
                        elif isinstance(slice_item, tuple) and len(slice_item) >= 2:
                            nssai = slice_item[1] if isinstance(slice_item[1], dict) else slice_item
                        
                        if nssai and isinstance(nssai, dict):
                            sst = nssai.get("sST", b"")
                            if sst and len(sst) > 0:
                                if isinstance(sst, bytes):
                                    extracted["sst"] = f"{sst[0]:02X}"
                                else:
                                    extracted["sst"] = f"{sst:02X}"
                                break
                    break
        
        
    except Exception as e:
        import traceback
        print(f"[!] Error extracting NGSetupResponse: {e}")
        print(f"[!] Traceback: {traceback.format_exc()}")
        pass
    
    return extracted if extracted else None


def analyze_stream(packets):
    """
    Analyze SCTP stream following scenario9 pattern.
    Returns: transport info, extracted NGAP values
    Strategy:
    - Extract MCC/MNC/SST from NGSetupRequest (gNB's request - must match what gNB wants)
    - Generate fake AMF identity (region/set/pointer/capacity) - attacker chooses these
    - Use fake AMF name: "fake-amf-attacker"
    """
    latest_sack = None
    down_src = None
    down_dst = None
    last_dl = None
    latest_tsn = None
    initial_tsn = None
    amf_initial_tsn = None
    gnb_initial_tsn = None
    verification_tag = None
    ngap_values = {}
    ngap_packet_count = 0
    ngsetup_request_values = {}
    ngsetup_request_src = None
    ngsetup_request_dst = None
    ngsetup_request_src_port = None
    ngsetup_request_dst_port = None

    packet_num = 0
    for pkt in packets:
        packet_num += 1
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        
        sctp_root = None
        try:
            if SCTP is not None and pkt.haslayer(SCTP):
                sctp_root = pkt[SCTP]
        except Exception:
            sctp_root = None
        if sctp_root is None:
            try:
                sctp_root = pkt["SCTP"]
            except Exception:
                sctp_root = None
        if not sctp_root:
            continue
        
        chunks = list(getattr(sctp_root, "chunks", []) or [])
        if not chunks:
            ch_iter = getattr(sctp_root, "payload", None)
            while ch_iter is not None and hasattr(ch_iter, "name") and str(ch_iter.name).startswith("SCTPChunk"):
                chunks.append(ch_iter)
                ch_iter = getattr(ch_iter, "payload", None)
        if not chunks:
            chunks = [sctp_root]
        
        for idx, ch in enumerate(chunks):
            chn = ch.__class__.__name__
            
            is_sack = hasattr(ch, "cumul_tsn_ack") or hasattr(ch, "cum_tsn_ack") or chn.endswith("SACK")
            is_data = hasattr(ch, "tsn") or chn.endswith("Data") or (SCTPChunkData and isinstance(ch, SCTPChunkData))
            is_init = hasattr(ch, "initiate_tag") or chn.endswith("INIT") or (hasattr(ch, "type") and getattr(ch, "type", None) == 1)
            is_init_ack = hasattr(ch, "initiate_tag") and hasattr(ch, "state_cookie") or chn.endswith("INIT-ACK") or (hasattr(ch, "type") and getattr(ch, "type", None) == 2)
            
            if is_init or is_init_ack:
                init_tsn = getattr(ch, "init_tsn", getattr(ch, "initial_tsn", None))
                src_port_init = getattr(sctp_root, "sport", None)
                dst_port_init = getattr(sctp_root, "dport", None)
                
                if init_tsn is not None:
                    
                    if is_init:
                        gnb_initial_tsn = init_tsn
                        init_tag = getattr(ch, "initiate_tag", getattr(ch, "tag", None))
                        if init_tag is not None:
                            verification_tag = init_tag
                    elif is_init_ack:
                        amf_initial_tsn = init_tsn
                        if verification_tag is None:
                            vt = getattr(sctp_root, "tag", None)
                            if vt is not None:
                                verification_tag = vt
                    
                    if initial_tsn is None:
                        initial_tsn = init_tsn
                    elif is_init_ack:
                        initial_tsn = init_tsn
                continue
            
            if is_sack:
                latest_sack = {
                    "ip_src": ip.src,
                    "ip_dst": ip.dst,
                    "cumulative": getattr(ch, "cum_tsn_ack", getattr(ch, "cumul_tsn_ack", None)),
                    "a_rwnd": getattr(ch, "a_rwnd", None),
                    "gap_blocks": len(getattr(ch, "gap_ack_blocks", []) or []),
                }
                down_src = ip.dst
                down_dst = ip.src
                continue
            
            if is_data:
                ppid_val = getattr(ch, "ppid", getattr(ch, "proto_id", None))
                
                ngap_payload = None
                if ppid_val == 60:
                    ngap_packet_count += 1
                    
                    if hasattr(ch, "data"):
                        try:
                            data_attr = ch.data
                            if data_attr is not None:
                                ngap_payload = bytes(data_attr)
                        except Exception:
                            pass
                    
                    if not ngap_payload and hasattr(ch, "load"):
                        try:
                            load_bytes = bytes(ch.load)
                            if load_bytes:
                                ngap_payload = load_bytes
                        except Exception:
                            pass
                    
                    if not ngap_payload and hasattr(ch, "payload"):
                        try:
                            payload_obj = ch.payload
                            if payload_obj:
                                if hasattr(payload_obj, "load"):
                                    ngap_payload = bytes(payload_obj.load)
                                else:
                                    ngap_payload = bytes(payload_obj)
                        except Exception:
                            pass
                    
                    if ngap_payload and NGAP_AVAILABLE:
                        decoded = decode_ngap_message(ngap_payload)
                        if decoded:
                            is_uplink = None
                            if down_src and down_dst:
                                is_uplink = (ip.src == down_dst and ip.dst == down_src)
                            
                            if "mcc" in decoded and "amf_name" not in decoded:
                                print(f"[+] Extracted from NGSetupRequest: MCC={decoded.get('mcc')}, MNC={decoded.get('mnc')}, SST={decoded.get('sst', 'N/A')}")
                                ngsetup_request_values.update({k: v for k, v in decoded.items() if k in ["mcc", "mnc", "sst"]})
                                ngsetup_request_src = ip.src
                                ngsetup_request_dst = ip.dst
                                ngsetup_request_src_port = getattr(sctp_root, "sport", None)
                                ngsetup_request_dst_port = getattr(sctp_root, "dport", None)
                            elif "amf_name" in decoded:
                                pass
                
                
                current_tsn = getattr(ch, "tsn", None)
                src_port = getattr(sctp_root, "sport", None)
                dst_port = getattr(sctp_root, "dport", None)
                
                is_attacker_to_target = False
                
                if ngsetup_request_src_port and ngsetup_request_dst_port:
                    if src_port == ngsetup_request_dst_port and dst_port == ngsetup_request_src_port:
                        is_attacker_to_target = True
                elif ngsetup_request_src and ngsetup_request_dst:
                    if ip.src == ngsetup_request_dst and ip.dst == ngsetup_request_src:
                        is_attacker_to_target = True
                elif down_src and down_dst:
                    if ip.src == down_src and ip.dst == down_dst:
                        is_attacker_to_target = True
                
                if is_attacker_to_target and current_tsn is not None:
                    if latest_tsn is None or current_tsn > latest_tsn:
                        latest_tsn = current_tsn
                        last_dl = {
                            "eth_dst": pkt[Ether].dst if pkt.haslayer(Ether) else None,
                            "eth_src": pkt[Ether].src if pkt.haslayer(Ether) else None,
                            "ip_src": ip.src,
                            "ip_dst": ip.dst,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "verification_tag": getattr(sctp_root, "tag", None),
                            "ppid": ppid_val,
                            "sid": getattr(ch, "sid", None),
                            "tsn_abs": current_tsn,
                            "ssn": getattr(ch, "ssn", None),
                        }
                elif is_attacker_to_target and last_dl is None:
                    last_dl = {
                        "eth_dst": pkt[Ether].dst if pkt.haslayer(Ether) else None,
                        "eth_src": pkt[Ether].src if pkt.haslayer(Ether) else None,
                        "ip_src": ip.src,
                        "ip_dst": ip.dst,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "verification_tag": getattr(sctp_root, "tag", None),
                        "ppid": ppid_val,
                        "sid": getattr(ch, "sid", None),
                        "tsn_abs": current_tsn,
                        "ssn": getattr(ch, "ssn", None),
                    }

    ngap_values = {}
    
    ngap_values.update(ngsetup_request_values)
    
    ngap_values["amf_name"] = "fake-amf-attacker"
    ngap_values["amf_region_id"] = "01"
    ngap_values["amf_set_id"] = "0001"
    ngap_values["amf_pointer"] = "00"
    ngap_values["amf_capacity"] = 255
    
    
    if not last_dl and ngsetup_request_src_port and ngsetup_request_dst_port:
        use_tsn = amf_initial_tsn if amf_initial_tsn is not None else initial_tsn
        if use_tsn is not None:
            last_dl = {
                "eth_dst": None,
                "eth_src": None,
                "ip_src": ngsetup_request_dst,
                "ip_dst": ngsetup_request_src,
                "src_port": ngsetup_request_dst_port,
                "dst_port": ngsetup_request_src_port,
                "verification_tag": verification_tag,
                "ppid": 60,
                "sid": 0,
                "tsn_abs": use_tsn,
                "ssn": 0,
            }
            latest_tsn = use_tsn
    
    if last_dl:
        if amf_initial_tsn is not None:
            last_dl["initial_tsn"] = amf_initial_tsn
        elif initial_tsn is not None:
            last_dl["initial_tsn"] = initial_tsn
    
    return last_dl, ngap_values, ngap_packet_count


def make_testcase_dict(last_dl: dict, amf_name, mcc, mnc, amf_region, amf_set, amf_pointer, sst, amf_capacity):
    """Build testcase from extracted values."""

    chunks = [
        {
            "type": "DATA",
            "ppid": int(last_dl.get("ppid")) if last_dl.get("ppid") is not None else 60,
            "sid": int(last_dl.get("sid")) if last_dl.get("sid") is not None else 0,
            "ssn": int(last_dl.get("ssn")) if last_dl.get("ssn") is not None else 0,
            "tsn_abs": int(last_dl.get("tsn_abs")) if last_dl.get("tsn_abs") is not None else 0,
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
                    "dst_mac": last_dl.get("eth_dst") or "00:00:00:00:00:00",
                    "src_mac": last_dl.get("eth_src") or "00:00:00:00:00:00",
                    "ethertype": "0x0800"
                },
                "ip": {
                    "src_ip": last_dl.get("ip_src"),
                    "dst_ip": last_dl.get("ip_dst"),
                    "ttl": 64,
                    "dscp_ecn": "0x00"
                },
                "sctp": {
                    "src_port": int(last_dl.get("src_port")) if last_dl.get("src_port") else None,
                    "dst_port": int(last_dl.get("dst_port")) if last_dl.get("dst_port") else None,
                    "verification_tag": hex(int(last_dl.get("verification_tag"))) if last_dl.get("verification_tag") else None,
                    "initial_tsn": int(last_dl.get("initial_tsn")) if last_dl.get("initial_tsn") is not None else None,
                    "chunks": chunks
                }
            },
            "ngap": {
                "fields": [
                    {"id": 1, "value": amf_name},
                    {"id": 96, "value": {
                        "mcc": mcc,
                        "mnc": mnc,
                        "amf_region_id": amf_region,
                        "amf_set_id": amf_set,
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
    p = argparse.ArgumentParser(description="Extract NGAP NGSetupResponse testcase from PCAP - NO MANUAL INPUT")
    p.add_argument("--pcap", required=True)
    args = p.parse_args()

    if not os.path.exists(args.pcap):
        print("[!] pcap not found:", args.pcap)
        return

    print(f"[+] Analyzing PCAP: {args.pcap}")
    print("[+] Extracting ALL values from PCAP...")
    
    if not NGAP_AVAILABLE:
        print("[!] ERROR: pycrate_asn1dir not available. Cannot decode NGAP messages.")
        print("[!] Install with: pip install pycrate")
        return
    
    packets = rdpcap(args.pcap)
    print(f"[+] Loaded {len(packets)} packets from PCAP")
    
    last_dl, ngap_values, ngap_count = analyze_stream(packets)
    
    print(f"[+] Found {ngap_count} NGAP packets (PPID 60) in PCAP")
    
    if not last_dl:
        print("[!] ERROR: No downlink SCTP DATA found in pcap.")
        return
    
    if not ngap_values:
        print("[!] ERROR: No NGAP messages successfully decoded from PCAP.")
        print("[!] PCAP must contain valid NGSetupRequest and/or NGSetupResponse messages.")
        return

    if "mcc" not in ngap_values:
        print("[!] ERROR: MCC not found in PCAP NGSetupRequest")
        return
    mcc = ngap_values["mcc"]
    print(f"[+] EXTRACTED MCC from NGSetupRequest: {mcc} (gNB's requested PLMN)")
    
    if "mnc" not in ngap_values:
        print("[!] ERROR: MNC not found in PCAP NGSetupRequest")
        return
    mnc = ngap_values["mnc"]
    print(f"[+] EXTRACTED MNC from NGSetupRequest: {mnc} (gNB's requested PLMN)")
    
    if "sst" not in ngap_values:
        print("[!] ERROR: SST not found in PCAP NGSetupRequest")
        return
    sst = ngap_values["sst"]
    print(f"[+] EXTRACTED SST from NGSetupRequest: {sst} (gNB's requested slice)")
    
    if "amf_name" not in ngap_values:
        print("[!] ERROR: AMF name not found")
        return
    amf_name = ngap_values["amf_name"]
    print(f"[+] USING AMF Name: {amf_name} (FAKE - attacker's identity)")
    
    if "amf_region_id" not in ngap_values:
        print("[!] ERROR: AMF region ID not generated")
        return
    amf_region = ngap_values["amf_region_id"]
    print(f"[+] USING AMF Region: {amf_region} (FAKE - attacker's identity)")
    
    if "amf_set_id" not in ngap_values:
        print("[!] ERROR: AMF set ID not generated")
        return
    amf_set = ngap_values["amf_set_id"]
    print(f"[+] USING AMF Set: {amf_set} (FAKE - attacker's identity)")
    
    if "amf_pointer" not in ngap_values:
        print("[!] ERROR: AMF pointer not generated")
        return
    amf_pointer = ngap_values["amf_pointer"]
    print(f"[+] USING AMF Pointer: {amf_pointer} (FAKE - attacker's identity)")
    
    if "amf_capacity" not in ngap_values:
        print("[!] ERROR: AMF capacity not generated")
        return
    amf_capacity = ngap_values["amf_capacity"]
    print(f"[+] USING AMF Capacity: {amf_capacity} (FAKE - attacker's identity)")

    print("\n[+] Building testcase from extracted values...")
    testcase = make_testcase_dict(
        last_dl,
        amf_name=amf_name,
        mcc=mcc, mnc=mnc,
        amf_region=amf_region,
        amf_set=amf_set,
        amf_pointer=amf_pointer,
        sst=sst,
        amf_capacity=amf_capacity
    )

    out_dir = "testcase_output"
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"ngap_NGSetupResponse_{ts}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(testcase, f, indent=2)
    print("[+] Testcase written:", out_file)
    pprint(testcase)


if __name__ == "__main__":
    main()
