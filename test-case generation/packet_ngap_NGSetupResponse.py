#!/usr/bin/env python3
"""
packet_ngap_NGSetupResponse.py

Builds an APER-encoded NGAP NGSetupResponse using pycrate_asn1dir.
Fully compatible with pycrate_asn1dir (3GPP_NR_NGAP_38413) structure.

Default JSON testcase path:
testcase_output/ngap_NGSetupResponse_20251023_234452.json
"""

from binascii import hexlify
import sys, os, json
from scapy.all import Ether, IP, wrpcap, hexdump
from scapy.layers.sctp import SCTP, SCTPChunkData

# --------------------------------------------------------------------
# Import pycrate_asn1dir
# --------------------------------------------------------------------
try:
    from pycrate_asn1dir import NGAP
    print("[+] Using pycrate_asn1dir (NGAP)")
except Exception as e:
    print("[!] ERROR: Cannot import pycrate_asn1dir:", e)
    sys.exit(1)

from pycrate_asn1rt.err import ASN1ObjErr


# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------
def encode_plmn_identity(mcc: str, mnc: str) -> bytes:
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


def load_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["test_case"]


# --------------------------------------------------------------------
# Build NGAP message
# --------------------------------------------------------------------
def build_ngap_ngsetup_response(amf_name, served_guami, amf_capacity, plmn_list):
    """Use pycrate_asn1dir to construct NGSetupResponse with direct native values."""
    PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU

    # Build GUAMI
    mcc = served_guami.get("mcc", "999")
    mnc = served_guami.get("mnc", "70")
    plmn_bytes = encode_plmn_identity(mcc, mnc)
    region = int(served_guami.get("amf_region_id", "01"), 16)
    setid  = int(served_guami.get("amf_set_id", "0001"), 16)
    pointer= int(served_guami.get("amf_pointer", "00"), 16)

    guami_val = {
        # ✅ OCTET STRING as raw bytes
        "pLMNIdentity": plmn_bytes,
        # ✅ BIT STRINGs as (value, bitlen)
        "aMFRegionID": (region, 8),
        "aMFSetID":    (setid, 10),
        "aMFPointer":  (pointer, 6),
    }
    served_guami_list = [{"gUAMI": guami_val}]

    # Build PLMNSupportList
    plmn_items = []
    for item in plmn_list:
        mcc_plmn = item.get("mcc", "999")
        mnc_plmn = item.get("mnc", "70")
        plmn_bytes_item = encode_plmn_identity(mcc_plmn, mnc_plmn)

        # ✅ OCTET STRING as raw bytes
        entry = {"pLMNIdentity": plmn_bytes_item}

        # sST is OCTET STRING (SIZE(1)) → 1-byte
        if "sst" in item:
            sst_val = int(item.get("sst", "01"), 16)
            entry["sliceSupportList"] = [
                {"s-NSSAI": {"sST": bytes([sst_val])}}
            ]
        plmn_items.append(entry)

    # Build IEs
    ies = [
        {"id": 1,  "criticality": "reject", "value": ("AMFName", str(amf_name))},
        {"id": 96, "criticality": "reject", "value": ("ServedGUAMIList", served_guami_list)},
        {"id": 86, "criticality": "reject", "value": ("RelativeAMFCapacity", int(amf_capacity))},
        {"id": 80, "criticality": "reject", "value": ("PLMNSupportList", plmn_items)},
    ]

    pdu_val = (
        "successfulOutcome",
        {
            "procedureCode": 21,  # id-NGSetup
            "criticality": "reject",
            "value": ("NGSetupResponse", {"protocolIEs": ies}),
        },
    )

    try:
        PDU.set_val(pdu_val)
        aper_bytes = PDU.to_aper()
        print("[+] NGSetupResponse ASN.1 encoding successful")
        return aper_bytes
    except ASN1ObjErr as e:
        print("[!] ASN1 encoding error:", e)
        raise
    except Exception as e:
        print("[!] Unexpected error:", e)
        raise


# --------------------------------------------------------------------
# Build SCTP layers
# --------------------------------------------------------------------
def build_sctp_layers(data_dict, payload_bytes):
    sctp = data_dict["transport"]["sctp"]
    sport = sctp.get("src_port")
    dport = sctp.get("dst_port")
    tag   = int(sctp.get("verification_tag", "0x0"), 16)

    data_chunk = next((c for c in sctp.get("chunks", []) if c.get("type") == "DATA"), None)
    tsn = data_chunk.get("tsn_abs") if data_chunk else 0
    sid = data_chunk.get("sid")     if data_chunk else 0
    ssn = data_chunk.get("ssn")     if data_chunk else 0
    ppid= data_chunk.get("ppid")    if data_chunk else 60  # NGAP

    # Single complete NGAP message:
    beginning = 1
    ending    = 1
    unordered = 0
    delay_sack= 0

    data_layer = SCTPChunkData(
        tsn=tsn,
        stream_id=sid,
        stream_seq=ssn,
        proto_id=ppid,
        beginning=beginning,
        ending=ending,
        unordered=unordered,
        delay_sack=delay_sack,
        data=payload_bytes,
    )

    return SCTP(sport=sport, dport=dport, tag=tag) / data_layer



# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main():
    JSON_FILE = "testcase_output/ngap_NGSetupResponse_20251106_162154.json"
    if not os.path.exists(JSON_FILE):
        print("[!] JSON file not found:", JSON_FILE)
        sys.exit(1)

    data = load_json(JSON_FILE)
    ngap = data["ngap"]
    fields = {f["id"]: f["value"] for f in ngap["fields"]}

    amf_name          = fields[1]
    served_guami      = fields[96]
    amf_capacity      = fields[86]
    plmn_support_list = fields[80]

    print("[+] Building NGSetupResponse with:")
    print(f"    AMFName={amf_name}")
    print(f"    ServedGUAMI={served_guami}")
    print(f"    RelativeAMFCapacity={amf_capacity}")
    print(f"    PLMNSupportList={plmn_support_list}")

    ngap_bytes = build_ngap_ngsetup_response(amf_name, served_guami, amf_capacity, plmn_support_list)
    print("[+] Encoded NGAP bytes length:", len(ngap_bytes))
    print(hexlify(ngap_bytes).decode())

    # Wrap into Ethernet/IP/SCTP
    eth = data["transport"]["l2_ethernet"]
    ip  = data["transport"]["ip"]

    ether_layer = Ether(dst=eth["dst_mac"], src=eth["src_mac"], type=int(eth["ethertype"], 16))
    ip_layer    = IP(src=ip["src_ip"], dst=ip["dst_ip"])
    sctp_layer  = build_sctp_layers(data, ngap_bytes)

    pkt = ether_layer / ip_layer / sctp_layer
    print("\n[+] Packet summary:")
    pkt.show()

    wrpcap("ngsetup_response.pcap", pkt)
    print("[✓] Saved as ngsetup_response.pcap")


if __name__ == "__main__":
    main()
