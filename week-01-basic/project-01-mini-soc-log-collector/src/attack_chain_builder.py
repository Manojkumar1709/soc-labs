import hashlib
from datetime import datetime

class AttackChainBuilder:
    def build_incident(self, source_ip, target_user, chain_events, chain_name):
        """
        Takes a sequence of raw events and builds a structured Tier-2 Correlated Incident.
        """
        stages = []
        for index, event in enumerate(chain_events):
            # Map events to MITRE Techniques dynamically
            technique = "Unknown"
            if event["event_type"] == "SSH_FAILED_LOGIN":
                technique = "T1110 (Brute Force)"
            elif event["event_type"] == "SSH_SUCCESS_LOGIN":
                technique = "T1078 (Valid Accounts)"
            elif event["event_type"] == "SUDO_COMMAND":
                technique = "T1548 (Privilege Escalation)"

            stages.append({
                "stage": index + 1,
                "event_type": event["event_type"],
                "technique": technique,
                "timestamp": event["timestamp"]
            })

        # --- STEP 5: Risk Escalation Logic ---
        # More stages = higher severity
        stage_count = len(stages)
        severity = "LOW"
        if stage_count >= 3:
            severity = "CRITICAL"
        elif stage_count == 2:
            severity = "HIGH"
        elif stage_count == 1:
            severity = "MEDIUM"

        # --- STEP 6: Deduplication Key ---
        # Creates a unique hash based on IP, User, and the first event's time 
        # to ensure we don't create duplicate incidents for the same chain.
        dedup_string = f"{source_ip}_{target_user}_{stages[0]['timestamp']}"
        incident_id = f"INC-CHAIN-{hashlib.md5(dedup_string.encode()).hexdigest()[:8].upper()}"

        incident = {
            "incident_id": incident_id,
            "generated_at": datetime.now().isoformat(),
            "summary": f"Multi-stage {chain_name} detected.",
            "entities": {
                "source_ip": source_ip,
                "target_user": target_user
            },
            "confidence": "HIGH" if stage_count >= 2 else "MEDIUM",
            "severity": severity,
            "attack_chain": stages
        }
        
        return incident
