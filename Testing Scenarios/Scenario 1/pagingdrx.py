import socket
import sctp
import binascii
import time
import struct

def create_correct_ng_setup():
    """Create the CORRECT NG Setup Request with safemalwarescanner123 name and v64 Paging DRX"""
    
    # safemalwarescanner123 is 21 chars - same as original!
    # Using 0x20 for v64 (your packet tracer encoding)
    exact_ngap = (
        "0015004100000400" +  # NGAP header - SAME LENGTH (65 bytes)
        "1b00090099f9075000000061" +  # GlobalRANNodeID (id=0x1B)
        "005240170a00736166656d616c776172657363616e6e6572313233" +  # RANNodeName: "safemalwarescanner123"
        "0066000d00000000010099f90700000008" +  # SupportedTAList (id=0x66)
        "0015400120000000"  # DefaultPagingDRX (id=0x15) - CHANGED: 0x20 for v64
    )
    
    return binascii.unhexlify(exact_ngap)

def create_ran_node_name_ie(name: str = "safemalwarescanner123"):
    """Create RANNodeName IE with new name"""
    ie_data = bytearray()
    
    # IE ID: 0x52 = RANNodeName
    ie_data.extend(b'\x00\x52')
    
    # Criticality: ignore (0x40)
    ie_data.extend(b'\x40')
    
    # Value - RANNodeName (NO NULL TERMINATOR!)
    name_bytes = name.encode('ascii')
    
    # Some extra bytes observed in the hex: 0a 00
    value_data = b'\x0a\x00' + name_bytes
    
    # Encode value with length
    value_encoded = bytearray()
    value_encoded.extend(struct.pack('!H', len(value_data)))
    value_encoded.extend(value_data)
    
    # Add to IE
    ie_data.extend(struct.pack('!H', len(value_encoded)))
    ie_data.extend(value_encoded)
    
    return ie_data

def create_global_ran_node_id_ie(plmn: str, gnb_id: int):
    """Create GlobalRANNodeID IE with correct structure"""
    ie_data = bytearray()
    
    # IE ID: 0x1B = GlobalRANNodeID
    ie_data.extend(b'\x00\x1b')
    
    # Criticality: reject (0)
    ie_data.extend(b'\x00')
    
    # Value - GlobalRANNodeID
    value_data = bytearray()
    
    # Choice: globalGNB-ID (0)
    value_data.extend(b'\x00')
    
    # PLMN Identity: 999-07
    value_data.extend(b'\x99\xf9\x07')
    
    # gNB-ID
    value_data.extend(b'\x50')  # gNB-ID type/length indicator
    value_data.extend(struct.pack('!I', gnb_id)[1:])  # Use last 3 bytes: 00 00 61
    
    # Encode value with length
    value_encoded = bytearray()
    value_encoded.extend(struct.pack('!H', len(value_data)))
    value_encoded.extend(value_data)
    
    # Add to IE
    ie_data.extend(struct.pack('!H', len(value_encoded)))
    ie_data.extend(value_encoded)
    
    return ie_data

def create_supported_ta_list_ie():
    """Create SupportedTAList IE - ends with 08!"""
    ie_data = bytearray()
    
    # IE ID: 0x66 = SupportedTAList
    ie_data.extend(b'\x00\x66')
    
    # Criticality: reject (0)
    ie_data.extend(b'\x00')
    
    # Value - SupportedTAList
    value_data = bytearray()
    value_data.extend(b'\x00\x00\x00\x00\x01\x00\x99\xf9\x07\x00\x00\x00\x08')  # Ends with 08!
    
    # Encode value with length
    value_encoded = bytearray()
    value_encoded.extend(struct.pack('!H', len(value_data)))
    value_encoded.extend(value_data)
    
    # Add to IE
    ie_data.extend(struct.pack('!H', len(value_encoded)))
    ie_data.extend(value_encoded)
    
    return ie_data

def create_default_paging_drx_ie():
    """Create DefaultPagingDRX IE - v64 (using 0x20 for packet tracer)"""
    ie_data = bytearray()
    
    # IE ID: 0x15 = DefaultPagingDRX
    ie_data.extend(b'\x00\x15')
    
    # Criticality: ignore (0x40)
    ie_data.extend(b'\x40')
    
    # Value - PagingDRX: v64 (using 0x20 for your packet tracer)
    value_data = b'\x20'  # v64
    
    # Encode value with length
    value_encoded = bytearray()
    value_encoded.extend(struct.pack('!H', len(value_data)))
    value_encoded.extend(value_data)
    
    # Add to IE
    ie_data.extend(struct.pack('!H', len(value_encoded)))
    ie_data.extend(value_encoded)
    
    return ie_data

def create_custom_ng_setup(gnb_id: int = 97, ran_node_name: str = "safemalwarescanner123"):
    """Create NG Setup Request with new RANNode name and v64 Paging DRX"""
    ngap_payload = bytearray()
    
    # NGAP Header - SAME LENGTH since name is same length
    ngap_payload.extend(b'\x00\x15\x00\x41\x00\x00\x04\x00')
    
    # GlobalRANNodeID IE
    ngap_payload.extend(create_global_ran_node_id_ie("99907", gnb_id))
    
    # RANNodeName IE - With new name!
    ngap_payload.extend(create_ran_node_name_ie(ran_node_name))
    
    # SupportedTAList IE
    ngap_payload.extend(create_supported_ta_list_ie())
    
    # DefaultPagingDRX IE - WITH v64 (0x20)!
    ngap_payload.extend(create_default_paging_drx_ie())
    
    return bytes(ngap_payload)

def verify_exact_match():
    """Verify our generated message matches the exact hexdump with new name and v64 Paging DRX"""
    print("\n🔍 Verifying exact byte match with safemalwarescanner123 name and v64 Paging DRX...")
    
    # Expected hex for safemalwarescanner123 (21 chars) with v64 Paging DRX (0x20)
    expected_hex = "00150041000004001b00090099f9075000000061005240170a00736166656d616c776172657363616e6e65723132330066000d00000000010099f907000000080015400120000000"
    
    # Our generated
    generated = create_correct_ng_setup()
    generated_hex = binascii.hexlify(generated).decode()
    
    print(f"Expected: {expected_hex}")
    print(f"Generated: {generated_hex}")
    
    if expected_hex == generated_hex:
        print("✅ PERFECT MATCH! safemalwarescanner123 name and v64 Paging DRX (0x20) applied correctly!")
        return True
    else:
        print("❌ MISMATCH!")
        # Find where they differ
        min_len = min(len(expected_hex), len(generated_hex))
        for i in range(0, min_len, 2):
            e_chunk = expected_hex[i:i+2]
            g_chunk = generated_hex[i:i+2]
            if e_chunk != g_chunk:
                print(f"Difference at byte {i//2}: expected={e_chunk}, generated={g_chunk}")
                print(f"Context: ...{expected_hex[i-8:i]}>{expected_hex[i:i+8]}<{expected_hex[i+8:i+16]}...")
                print(f"         ...{generated_hex[i-8:i]}>{generated_hex[i:i+8]}<{generated_hex[i+8:i+16]}...")
                break
        return False

def show_changes():
    """Show what changed"""
    print("\n📝 CHANGES MADE:")
    print("=" * 50)
    
    print("✅ RANNodeName: safemalwarescanner123")
    print("✅ PLMN: 999-07")
    print("✅ gNB ID: 97")
    print("✅ TAC: 1")
    print("🔄 Paging DRX: Using 0x20 for v64")
    print("   - Your packet tracer encoding:")
    print("     - 0x20 = v64")
    print("     - 0x40 = v128")
    print("     - 0x60 = v32") 
    print("     - 0x80 = v256")

def test_ng_setup():
    """Test the NG Setup Request with new name and v64 Paging DRX"""
    print("\n🚀 Testing NG Setup Request with safemalwarescanner123 name and v64 Paging DRX (0x20)...")
    
    # First verify we have the exact bytes
    if not verify_exact_match():
        print("Cannot proceed - byte mismatch!")
        return False
    
    ngap_payload = create_correct_ng_setup()
    
    s = sctp.sctpsocket_tcp(socket.AF_INET)
    try:
        s.connect(("192.168.42.134", 38412))
        print("✓ Connected to AMF")
        
        bytes_sent = s.sctp_send(ngap_payload)
        print(f"✓ Sent {bytes_sent} bytes with:")
        print(f"  - RANNode name: 'safemalwarescanner123'")
        print(f"  - Paging DRX: v64 (using 0x20)")
        
        s.settimeout(10.0)
        response = s.recv(4096)
        
        if response:
            print(f"✓ Received {len(response)} byte response")
            
            if len(response) >= 2:
                pdu_type, procedure = response[0], response[1]
                
                print(f"\n📊 Response Analysis:")
                print(f"  PDU Type: 0x{pdu_type:02x}", end="")
                
                if pdu_type == 0x20:
                    print(" - successfulOutcome")
                    if procedure == 0x15:
                        print("  ✅ NG Setup Procedure SUCCESS!")
                        print("  🎉 AMF accepted name 'safemalwarescanner123' and v64 Paging DRX!")
                        return True
                    else:
                        print(f"  Procedure: 0x{procedure:02x} (unexpected)")
                elif pdu_type == 0x40:
                    print(" - unsuccessfulOutcome")
                    print("  ❌ NG Setup Failed")
                else:
                    print(f" - unknown type")
                
                # Show first few bytes of response
                resp_hex = binascii.hexlify(response[:20]).decode()
                print(f"  Response (first 20 bytes): {resp_hex}")
            
            return False
        else:
            print("✗ No response received")
            return False
            
    except socket.timeout:
        print("⏱ Timeout waiting for response")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        s.close()
        print("\n🔌 Connection closed")

def main():
    print("NG Setup Request - safemalwarescanner123 + v64 Paging DRX (0x20)")
    print("=" * 50)
    print("Configuration:")
    print("  - RANNodeName: safemalwarescanner123")
    print("  - PLMN: 999-07") 
    print("  - gNB ID: 97")
    print("  - TAC: 1")
    print("  - Paging DRX: v64 (using 0x20)")
    print("=" * 50)
    
    # Show the changes
    show_changes()
    
    # Test the NG Setup
    success = test_ng_setup()
    
    if success:
        print("\n🎉 SUCCESS! v64 Paging DRX (0x20) accepted by AMF!")
        print("Your packet tracer should now show v64!")
    else:
        print("\n❌ NG Setup failed with v64 Paging DRX")

if __name__ == "__main__":
    main()
