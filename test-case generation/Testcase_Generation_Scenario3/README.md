Prerequisite: Prepare Your Environment
Open a Terminal and start the Ollama server (keep this window open):
ollama serve

Open a Second Terminal and ensure you have the model:
ollama pull tinyllama

Step 1: Run the LLM Generator
This uses your updated scenario3_llm_gen.py (the one with smart_filter_packets) to read your Wireshark dump and ask the AI to build the attack.
Run this command:
python scenario3_llm_gen.py --file legitimate_setup.txt

Expected Output:
[-] Input reduced to ... characters.
[*] Querying Ollama (tinyllama)...
[+] Reconnaissance Successful! Stolen Data: {...}
[+] Malicious Test Case generated: scenario3_attack_std_20251118_xxxx.json
Copy the filename of the JSON file that was just generated.

Step 2: Verify the Results
Now, compare the AI-generated file against your manual ground truth to get the score.
Run this command (replace [GENERATED_FILENAME] with the actual file from Step 3):
python compare_json_files.py [GENERATED_FILENAME] manual_ground_truth.json
Example:
python compare_json_files.py scenario3_attack_std_20251118_1230.json manual_ground_truth.json
