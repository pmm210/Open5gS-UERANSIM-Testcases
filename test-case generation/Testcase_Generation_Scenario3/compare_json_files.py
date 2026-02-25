import json
import sys

def normalize(val):
    """
    Helper to treat '100', 100, and '0x64' as the same value.
    """
    val = str(val).strip().lower()
    
    # Try converting to int (handling hex and decimal)
    try:
        if val.startswith("0x"):
            return int(val, 16)
        return int(val)
    except:
        return val

def compare_step(llm_step, manual_step, step_name):
    print(f"\n--- Checking {step_name} ---")
    score = 0
    total = 0
    
    # Define critical paths to check for this step
    # Format: (Description, Key_Path_List)
    if "Association" in step_name:
        checks = [
            ("Source IP", ["transport_layer", "src_ip"]),
            ("Dest IP", ["transport_layer", "dst_ip"]),
            ("Message Type", ["pfcp_header", "type"]),
            ("Node ID", ["payload_ies", "node_id", "value"])
        ]
    else: # Modification / Attack
        checks = [
            ("Source IP", ["transport_layer", "src_ip"]),
            ("Dest IP", ["transport_layer", "dst_ip"]),
            ("Message Type", ["pfcp_header", "type"]),
            ("Target SEID", ["pfcp_header", "seid"]),
            ("Target TEID", ["payload_ies", "pdr", "pdi", "fteid", "teid"]),
            ("Target UE IP", ["payload_ies", "pdr", "pdi", "ue_ip"]),
            ("Action", ["payload_ies", "far", "apply_action"])
        ]

    for desc, keys in checks:
        total += 1
        
        # Traverse LLM JSON
        llm_val = llm_step
        try:
            for k in keys: llm_val = llm_val[k]
        except KeyError: llm_val = "MISSING"

        # Traverse Manual JSON
        man_val = manual_step
        try:
            for k in keys: man_val = man_val[k]
        except KeyError: man_val = "MISSING"

        # Compare
        if normalize(llm_val) == normalize(man_val):
            status = "PASS"
            score += 1
        else:
            status = "FAIL"

        print(f"{desc:<15} | LLM: {str(llm_val):<15} | Manual: {str(man_val):<15} | {status}")

    return score, total

def main():
    if len(sys.argv) < 3:
        print("Usage: python compare_json_files.py <llm_output.json> <manual_truth.json>")
        sys.exit(1)

    file_llm = sys.argv[1]
    file_manual = sys.argv[2]

    try:
        with open(file_llm, 'r') as f: llm_data = json.load(f)
        with open(file_manual, 'r') as f: manual_data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading files: {e}")
        sys.exit(1)

    print(f"Comparing '{file_llm}' against '{file_manual}'...\n")

    total_score = 0
    total_checks = 0

    # Compare Step 1
    s1, t1 = compare_step(llm_data['execution_flow'][0], manual_data['execution_flow'][0], "Step 1: Association")
    total_score += s1
    total_checks += t1

    # Compare Step 2
    s2, t2 = compare_step(llm_data['execution_flow'][1], manual_data['execution_flow'][1], "Step 2: Attack")
    total_score += s2
    total_checks += t2

    accuracy = (total_score / total_checks) * 100
    print("-" * 70)
    print(f"FINAL ACCURACY: {accuracy:.2f}%")
    print("-" * 70)

    if accuracy == 100:
        print("[SUCCESS] The LLM perfectly replicated the manual attack scenario.")
    else:
        print("[WARNING] Differences detected.")

if __name__ == "__main__":
    main()