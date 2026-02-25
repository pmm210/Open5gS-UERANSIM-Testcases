------------------------------------ SIT Mini-project ------------------------------------------ 
To test the testcase generation:

run these series of command:
docker compose up -d
docker exec itp-ollama-1 ollama pull llama3.1:8b (only once)

python testcase_generation_scenario2_llm.py --file scenario2_captured.txt (for llama model)
OR
python testcase_generation_scenario2_llm.py --file scenario2_captured.txt --provider openai (for ChatGPT model)


# Setting Up UERANSIM and Open5GS
1. Follow the guide in this link and "Setting up Open5GS and UERANSIM" document
https://open5gs.org/open5gs/docs/tutorial/01-your-first-lte/
https://nickvsnetworking.com/my-first-5g-core-open5gs-and-ueransim/

2. VMWare Setup
This project requires either 2 or 4 VMWare to work.
Ensure the ip address is configured accordingly

# 1st VMWare setup which requires only 2 (Open5GS and UERANSIM)
Config can be found under "Config for 2 VMWare Setup" folder
    1. UERANSIM gNodeB can point towards the amf ip address
    2. Open5GS amf, smf, upf config can point towards itself (Open5GS VMWare)
    3. UERANSIM ue yaml file points towards itself

# 2nd Setup uses 3 VMWare (Open5GS without UPF, Open5GS with UPF only, UERANSIM)
Config can be found under "Config for 4 VMWare Setup" folder
    1. Disable open5gs-upfd service in "Open5GS without UPF" VMWare
    2. Disable the rest of the open5gs service and leave the UPF service up in "Open5GS with UPF only" VMWare
    3. UERANSIM gNodeB yaml file points towards (1) VMWare
    4. UERANSIM ue yaml file points towards itself
