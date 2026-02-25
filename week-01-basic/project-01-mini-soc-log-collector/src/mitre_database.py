"""
AXIORA - Mini SOC MITRE ATT&CK Knowledge Base
This file stores the static mappings for known attacker behaviors.
"""

MITRE_ATTACK_DB = {
    "SSH_BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts."
    },
    "SSH_SUCCESS_AFTER_FAILURE": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
    },
    "SSH_REMOTE_ACCESS": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as SSH."
    }
}

# --- TEST BLOCK ---
if __name__ == "__main__":
    print("--- AXIORA MITRE KNOWLEDGE BASE ---")
    for key, data in MITRE_ATTACK_DB.items():
        print(f"[*] {key} -> {data['technique_id']}: {data['technique_name']} ({data['tactic']})")
